/**
 * JWKS retrieval and key cache.
 *
 * Three behaviours here are load-bearing rather than tidy, all learned from the hand-rolled Go
 * verifier that shipped before this package:
 *
 *   - The algorithm is chosen from THIS list, never from the token's own header. A token that
 *     asks for `none` or for an HMAC is refused before any key is looked up.
 *   - An unknown `kid` is indistinguishable from a rotated key, so a miss triggers at most one
 *     refetch per cooldown window. Without it every junk-kid token costs one outbound request
 *     and a busy verifier trips the issuer's rate limit — failing its GOOD tokens too.
 *   - Concurrent misses share ONE in-flight fetch per key set, with the cache re-checked after
 *     it resolves. Serialising is what makes the cooldown hold under concurrency.
 */

import { isRecord } from './jwt.js';
import type { FetchLike } from './types.js';

export const SUPPORTED_ALGORITHMS = ['RS256', 'ES256'] as const;
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

/** How long a `kid` miss suppresses further refetches of the same key set. */
export const KEY_MISS_COOLDOWN_MS = 30_000;
/** How long a successfully fetched key set is reused without refetching. */
export const KEY_SET_TTL_MS = 10 * 60_000;

/**
 * A key set is kilobytes. Anything larger is not a JWKS, and the request is driven by input the
 * verifier does not control, so it is capped rather than streamed to completion.
 */
export const MAX_REMOTE_BODY_BYTES = 512 * 1024;

interface KeySetEntry {
  keys: Map<string, CryptoKey>;
  /** Keys served without a `kid`, tried in order when the token carries none. */
  anonymousKeys: CryptoKey[];
  fetchedAt: number;
  lastMissAt: number;
  /** Resolves to the fetch's failure (or null) so waiters see THAT fetch's outcome. */
  inFlight: Promise<JwksUnavailableError | null> | null;
}

const cache = new Map<string, KeySetEntry>();

/** Test seam — drops every cached key set. */
export function resetJwksCache(): void {
  cache.clear();
}

export class JwksUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwksUnavailableError';
  }
}

function importParams(alg: SupportedAlgorithm): {
  algorithm: RsaHashedImportParams | EcKeyImportParams;
  verify: AlgorithmIdentifier | EcdsaParams;
} {
  if (alg === 'ES256') {
    return {
      algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
      verify: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
    };
  }
  return {
    algorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    verify: { name: 'RSASSA-PKCS1-v1_5' },
  };
}

export function isSupportedAlgorithm(alg: unknown): alg is SupportedAlgorithm {
  return typeof alg === 'string' && (SUPPORTED_ALGORITHMS as readonly string[]).includes(alg);
}

async function importJwk(jwk: Record<string, unknown>, alg: SupportedAlgorithm): Promise<CryptoKey | null> {
  try {
    const { algorithm } = importParams(alg);
    return await crypto.subtle.importKey('jwk', jwk as JsonWebKey, algorithm, false, ['verify']);
  } catch {
    return null;
  }
}

async function fetchKeySet(
  entry: KeySetEntry,
  jwksUri: string,
  alg: SupportedAlgorithm,
  fetchImpl: FetchLike,
  timeoutMs: number
): Promise<void> {
  const response = await fetchImpl(jwksUri, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { accept: 'application/json' },
    // A redirect would let any open redirect on the issuer's origin move this fetch off it.
    redirect: 'error',
  });
  if (!response.ok) {
    throw new JwksUnavailableError(`JWKS fetch failed with HTTP ${response.status}`);
  }

  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REMOTE_BODY_BYTES) {
    throw new JwksUnavailableError('JWKS response is too large');
  }

  const raw = await response.text();
  if (raw.length > MAX_REMOTE_BODY_BYTES) {
    throw new JwksUnavailableError('JWKS response is too large');
  }

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    throw new JwksUnavailableError('JWKS response is not JSON');
  }
  if (!isRecord(body) || !Array.isArray(body.keys)) {
    throw new JwksUnavailableError('JWKS response has no `keys` array');
  }

  const keys = new Map<string, CryptoKey>();
  const anonymousKeys: CryptoKey[] = [];
  for (const candidate of body.keys) {
    if (!isRecord(candidate)) continue;
    // A key set may legitimately mix algorithms; only the ones usable for THIS verification
    // are imported, and an unusable entry is skipped rather than failing the whole set.
    if (typeof candidate.alg === 'string' && candidate.alg !== alg) continue;
    const key = await importJwk(candidate, alg);
    if (!key) continue;
    if (typeof candidate.kid === 'string' && candidate.kid.length > 0) {
      keys.set(candidate.kid, key);
    } else {
      anonymousKeys.push(key);
    }
  }

  entry.keys = keys;
  entry.anonymousKeys = anonymousKeys;
  entry.fetchedAt = Date.now();
}

function lookup(entry: KeySetEntry, kid: string | undefined): CryptoKey[] {
  if (kid) {
    const key = entry.keys.get(kid);
    return key ? [key] : [];
  }
  // No `kid` in the header: every key in the set is a candidate.
  return [...entry.anonymousKeys, ...entry.keys.values()];
}

/**
 * Candidate verification keys for `kid`, fetching the key set at most once per cooldown.
 * Returns an empty array when the key is genuinely unknown; throws `JwksUnavailableError`
 * when the key set could not be read at all ("I could not check" is not "the token is bad").
 */
export async function getVerificationKeys(params: {
  jwksUri: string;
  kid?: string;
  alg: SupportedAlgorithm;
  fetch: FetchLike;
  timeoutMs: number;
}): Promise<CryptoKey[]> {
  const cacheKey = `${params.jwksUri}|${params.alg}`;
  let entry = cache.get(cacheKey);
  if (!entry) {
    entry = {
      keys: new Map(),
      anonymousKeys: [],
      fetchedAt: 0,
      lastMissAt: 0,
      inFlight: null,
    };
    cache.set(cacheKey, entry);
  }

  const fresh = entry.fetchedAt > 0 && Date.now() - entry.fetchedAt < KEY_SET_TTL_MS;
  const hit = lookup(entry, params.kid);
  if (fresh && hit.length > 0) return hit;

  if (fresh && Date.now() - entry.lastMissAt < KEY_MISS_COOLDOWN_MS) {
    return []; // Cooldown: a miss we already paid a request for.
  }

  const current = entry;
  if (!current.inFlight) {
    const running = fetchKeySet(current, params.jwksUri, params.alg, params.fetch, params.timeoutMs);
    // The shared promise RESOLVES to the outcome rather than recording it on the entry: a
    // waiter reading shared state after its await could be handed the state of the NEXT
    // fetch. Carried, not stored — a waiter that only saw an empty key set would report
    // `unknown_key` ("this token names a key that does not exist") for what is actually
    // "I could not reach the issuer": a false forgery signal during an outage.
    current.inFlight = running.then(
      () => null,
      (error: unknown) =>
        error instanceof JwksUnavailableError
          ? error
          : new JwksUnavailableError(error instanceof Error ? error.message : 'JWKS fetch failed')
    );
    const settled = current.inFlight;
    settled.finally(() => {
      if (current.inFlight === settled) current.inFlight = null;
    });
    const failure = await settled;
    if (failure) throw failure;
  } else {
    const failure = await current.inFlight;
    if (failure) throw failure;
  }

  const after = lookup(current, params.kid);
  if (after.length === 0) current.lastMissAt = Date.now();
  return after;
}

/** Verify a JWS signature against one candidate key. */
export async function verifySignature(
  key: CryptoKey,
  alg: SupportedAlgorithm,
  signingInput: string,
  signature: Uint8Array
): Promise<boolean> {
  const { verify } = importParams(alg);
  try {
    return await crypto.subtle.verify(
      verify,
      key,
      signature as unknown as BufferSource,
      new TextEncoder().encode(signingInput) as unknown as BufferSource
    );
  } catch {
    return false;
  }
}
