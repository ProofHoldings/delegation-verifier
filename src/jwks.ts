/**
 * JWKS retrieval and key cache — the I/O half. The rules a fetched key set is held to (merge,
 * tombstones, purpose, window) live in `keyset.ts`; this file decides WHEN to fetch and what to
 * answer when a fetch fails.
 *
 * Behaviours that are load-bearing rather than tidy, the first three learned from the hand-rolled
 * Go verifier that shipped before this package:
 *
 *   - The algorithm is chosen from THIS list, never from the token's own header. A token that
 *     asks for `none` or for an HMAC is refused before any key is looked up.
 *   - An unknown `kid` is indistinguishable from a rotated (or emergency) key, so a miss triggers
 *     at most one refetch per cooldown window. Without it every junk-kid token costs one outbound
 *     request and a busy verifier trips the issuer's rate limit — failing its GOOD tokens too.
 *   - Concurrent misses share ONE in-flight fetch per key set, with the cache re-checked after
 *     it resolves. Serialising is what makes the cooldown hold under concurrency.
 *   - A failed refetch does not discard a cached key set. Under `maxJwksAgeMs` its CONFIRMED keys
 *     keep answering (a kid they do not cover is `jwks_unavailable`: it may be new); over it the answer
 *     is `jwks_stale` — except for an applied tombstone, which is `key_revoked` at any age. A set
 *     that was never fetched has no cache to fall back on, so its failure stays `jwks_unavailable`
 *     and is retried on every call.
 *   - Age is measured on a monotonic clock in-process. Only what is persisted uses wall clock.
 */

import { isRecord } from './jwt.js';
import {
  checkKeyPolicy,
  deserializeKeySetState,
  emptyKeySetState,
  isRegistryLive,
  mergeFetchedDocument,
  selectKeys,
  serializeKeySetState,
  withConfirmedKeysOnly,
  withoutTombstones,
  withPersistedTombstones,
} from './keyset.js';
import type { KeyFamily, KeyPolicyViolation, KeyRecord, KeySetClockReading, KeySetEvent, KeySetState } from './keyset.js';
import type { FetchLike, JwksEvent, KeySetStore } from './types.js';

export const SUPPORTED_ALGORITHMS = ['RS256', 'ES256'] as const;
export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

/** How long a `kid` miss — or a failed refetch of a cached set — suppresses further fetches. */
export const KEY_MISS_COOLDOWN_MS = 30_000;
/** How long a successfully fetched key set is reused without refetching. */
export const KEY_SET_TTL_MS = 10 * 60_000;
/** Default `maxJwksAgeMs`. */
export const DEFAULT_MAX_JWKS_AGE_MS = 24 * 60 * 60_000;
/** Largest accepted `maxJwksAgeMs` — below the issuer's ~30-day lead on its next key. */
export const MAX_JWKS_AGE_CAP_MS = 25 * 24 * 60 * 60_000;
/** Bound on a JWKS fetch and on each `keySetStore` call when the caller passes no `timeoutMs`. */
const DEFAULT_IO_TIMEOUT_MS = 5_000;

/**
 * A key set is kilobytes. Anything larger is not a JWKS, and the request is driven by input the
 * verifier does not control, so it is capped rather than streamed to completion.
 */
export const MAX_REMOTE_BODY_BYTES = 512 * 1024;

export interface JwksClock {
  monotonicMs(): number;
  wallMs(): number;
}

const systemClock: JwksClock = {
  monotonicMs: () => performance.now(),
  wallMs: () => Date.now(),
};

let clock: JwksClock = systemClock;

/** Test seam — replaces both clocks; `null` restores the system clocks. Not exported publicly. */
export function setJwksClockForTests(replacement: JwksClock | null): void {
  clock = replacement ?? systemClock;
}

function readClock(): KeySetClockReading {
  return { monotonicMs: clock.monotonicMs(), wallMs: clock.wallMs() };
}

/** The per-call knobs that shape key-set handling. */
export interface KeySetOptions {
  maxJwksAgeMs: number;
  keySetStore?: KeySetStore;
  onJwksEvent?: (event: JwksEvent) => void;
}

type StoreOptions = Partial<KeySetOptions> & { timeoutMs?: number };

type FetchOutcome = { ok: true } | { ok: false; message: string };

interface KeySetEntry {
  state: KeySetState;
  /** Imported keys by key material + algorithm; `null` records a JWK that failed to import. */
  imported: Map<string, CryptoKey | null>;
  lastMissAt: number | null;
  lastFailedAt: number | null;
  inFlight: Promise<FetchOutcome> | null;
  storeLoaded: Promise<void> | null;
  /** The store could not be read: saving now would overwrite what it holds (tombstones included). */
  storeLoadFailed: boolean;
}

const cache = new Map<string, KeySetEntry>();

/** Test seam — drops every cached key set, tombstones included. */
export function resetJwksCache(): void {
  cache.clear();
}

export class JwksUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwksUnavailableError';
  }
}

function entryFor(jwksUri: string): KeySetEntry {
  let entry = cache.get(jwksUri);
  if (!entry) {
    entry = {
      state: emptyKeySetState(),
      imported: new Map(),
      lastMissAt: null,
      lastFailedAt: null,
      inFlight: null,
      storeLoaded: null,
      storeLoadFailed: false,
    };
    cache.set(jwksUri, entry);
  }
  return entry;
}

function emit(options: Pick<KeySetOptions, 'onJwksEvent'>, jwksUri: string, event: KeySetEvent | Omit<JwksEvent, 'jwksUri'>): void {
  if (!options.onJwksEvent) return;
  try {
    options.onJwksEvent({ ...event, jwksUri });
  } catch {
    // A throwing listener must not turn into a verification failure.
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** A store is the caller's code: a call that never settles must not hang every verification. */
async function boundedStoreCall<T>(call: () => T | Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs} ms`)), timeoutMs);
  });
  try {
    return await Promise.race([Promise.resolve().then(call), timedOut]);
  } finally {
    clearTimeout(timer);
  }
}

async function loadFromStore(entry: KeySetEntry, jwksUri: string, options: StoreOptions): Promise<void> {
  const store = options.keySetStore;
  if (!store || entry.storeLoaded) {
    if (entry.storeLoaded) await entry.storeLoaded;
    return;
  }
  entry.storeLoaded = (async () => {
    try {
      const raw = await boundedStoreCall(() => store.load(jwksUri), options.timeoutMs ?? DEFAULT_IO_TIMEOUT_MS);
      if (typeof raw !== 'string') return;
      const loaded = deserializeKeySetState(raw, readClock());
      if (!loaded) {
        emit(options, jwksUri, { type: 'store_error', message: 'keySetStore.load returned a state this version cannot read' });
        return;
      }
      // A set fetched in this process before the store was first offered is newer than disk —
      // except for its tombstones, which no later fetch can restore.
      entry.state = entry.state.fetchedAt === null ? loaded : withPersistedTombstones(entry.state, loaded);
    } catch (error) {
      entry.storeLoadFailed = true;
      emit(options, jwksUri, { type: 'store_error', message: `keySetStore.load failed: ${errorMessage(error)}` });
    }
  })();
  await entry.storeLoaded;
}

async function saveToStore(entry: KeySetEntry, jwksUri: string, options: StoreOptions): Promise<void> {
  const store = options.keySetStore;
  if (!store) return;
  if (entry.storeLoadFailed) {
    emit(options, jwksUri, { type: 'store_error', message: 'keySetStore.save skipped: the persisted state could not be loaded, and saving would overwrite it' });
    return;
  }
  const serialized = serializeKeySetState(entry.state);
  try {
    await boundedStoreCall(() => store.save(jwksUri, serialized), options.timeoutMs ?? DEFAULT_IO_TIMEOUT_MS);
  } catch (error) {
    emit(options, jwksUri, { type: 'store_error', message: `keySetStore.save failed: ${errorMessage(error)}` });
  }
}

async function fetchDocument(jwksUri: string, fetchImpl: FetchLike, timeoutMs: number): Promise<Record<string, unknown>> {
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
  return body;
}

/**
 * Fetch and merge once per key set at a time. The shared promise RESOLVES to the outcome rather
 * than recording it on the entry: a waiter reading shared state after its await could be handed
 * the state of the NEXT fetch — and a waiter that only saw an empty key set would report
 * `unknown_key` ("this token names a key that does not exist") for what is actually "I could not
 * reach the issuer": a false forgery signal during an outage.
 */
function runFetch(
  entry: KeySetEntry,
  jwksUri: string,
  params: { fetch: FetchLike; timeoutMs: number } & Partial<KeySetOptions>
): Promise<FetchOutcome> {
  if (entry.inFlight) return entry.inFlight;
  const running = (async (): Promise<FetchOutcome> => {
    let failure: string;
    try {
      const body = await fetchDocument(jwksUri, params.fetch, params.timeoutMs);
      const merged = mergeFetchedDocument(entry.state, body, readClock());
      for (const event of merged.events) emit(params, jwksUri, event);
      if (merged.accepted) {
        entry.state = merged.state;
        entry.lastFailedAt = null;
        await saveToStore(entry, jwksUri, params);
        return { ok: true };
      }
      failure = merged.events[0]?.message ?? 'JWKS refused';
    } catch (error) {
      failure = error instanceof JwksUnavailableError ? error.message : errorMessage(error) || 'JWKS fetch failed';
    }
    // The failure cooldown applies only to a set with a cache to fall back on; a set that was
    // never fetched is retried on every call, exactly as before.
    if (entry.state.fetchedAt !== null) entry.lastFailedAt = clock.monotonicMs();
    return { ok: false, message: failure };
  })();
  entry.inFlight = running;
  void running.finally(() => {
    if (entry.inFlight === running) entry.inFlight = null;
  });
  return running;
}

function cacheAgeMs(state: KeySetState, now: number): number {
  if (state.fetchedAt === null || state.fetchedAtUntrusted) return Number.POSITIVE_INFINITY;
  return now - state.fetchedAt.monotonicMs;
}

function isFresh(state: KeySetState, now: number): boolean {
  return cacheAgeMs(state, now) < KEY_SET_TTL_MS;
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

async function importRecord(entry: KeySetEntry, record: KeyRecord, alg: SupportedAlgorithm): Promise<CryptoKey | null> {
  // A key set may legitimately mix algorithms; a key declared for another one is not a candidate.
  if (typeof record.jwk.alg === 'string' && record.jwk.alg !== alg) return null;
  // A key the JWKS marks for anything but signatures is not a candidate (RFC 7517 §4.2, §4.3). Only
  // the material is handed to `importKey`, so these members would otherwise go unread — and the
  // check precedes the import cache, which is keyed by material and shared across kids.
  const { use, key_ops: keyOps } = record.jwk;
  if (use !== undefined && use !== 'sig') return null;
  if (keyOps !== undefined && !(Array.isArray(keyOps) && keyOps.includes('verify'))) return null;
  const cacheKey = `${record.fingerprint}|${alg}`;
  if (entry.imported.has(cacheKey)) return entry.imported.get(cacheKey) ?? null;
  let key: CryptoKey | null = null;
  try {
    const { kty, crv, x, y, n, e } = record.jwk;
    const material = Object.fromEntries(
      Object.entries({ kty, crv, x, y, n, e }).filter(([, value]) => value !== undefined)
    ) as JsonWebKey;
    key = await crypto.subtle.importKey('jwk', material, importParams(alg).algorithm, false, ['verify']);
  } catch {
    key = null;
  }
  entry.imported.set(cacheKey, key);
  return key;
}

export interface KeyCandidate {
  key: CryptoKey;
  record: KeyRecord;
}

export type KeyResolution =
  | { kind: 'keys'; candidates: KeyCandidate[]; registryLive: boolean }
  | { kind: 'revoked'; kid: string }
  | { kind: 'wrong_purpose'; kid: string }
  | { kind: 'unknown' }
  | { kind: 'stale'; cacheAgeSeconds: number | null }
  | { kind: 'unavailable'; message: string };

async function resolveFromState(
  entry: KeySetEntry,
  state: KeySetState,
  kid: string | undefined,
  family: KeyFamily,
  alg: SupportedAlgorithm
): Promise<KeyResolution> {
  const selection = selectKeys(state, kid, family);
  if (selection.kind !== 'candidates') return selection;
  const candidates: KeyCandidate[] = [];
  for (const record of selection.records) {
    const key = await importRecord(entry, record, alg);
    if (key) candidates.push({ key, record });
  }
  if (candidates.length === 0) return { kind: 'unknown' };
  return { kind: 'keys', candidates, registryLive: isRegistryLive(state) };
}

function candidateCount(state: KeySetState, family: KeyFamily): number {
  const selection = selectKeys(state, undefined, family);
  return selection.kind === 'candidates' ? selection.records.length : 0;
}

/**
 * The keys that may verify a token of `family` carrying `kid` — or why none may. Fetches the key
 * set when it is older than the TTL, or once per cooldown when `kid` is unknown.
 */
export async function resolveVerificationKeys(
  params: {
    jwksUri: string;
    kid?: string;
    alg: SupportedAlgorithm;
    family: KeyFamily;
    fetch: FetchLike;
    timeoutMs: number;
  } & KeySetOptions
): Promise<KeyResolution> {
  const entry = entryFor(params.jwksUri);
  await loadFromStore(entry, params.jwksUri, params);

  const now = clock.monotonicMs();
  if (isFresh(entry.state, now)) {
    const cached = await resolveFromState(entry, entry.state, params.kid, params.family, params.alg);
    if (cached.kind !== 'unknown') return cached;
    if (entry.lastMissAt !== null && now - entry.lastMissAt < KEY_MISS_COOLDOWN_MS) {
      // Cooldown: no refetch. The kid may have been published since the last one, so this is
      // "could not check", not "this key does not exist".
      return { kind: 'unavailable', message: 'unknown key; the key set is refetched again after the cooldown' };
    }
  }

  const recentlyFailed =
    entry.state.fetchedAt !== null && entry.lastFailedAt !== null && now - entry.lastFailedAt < KEY_MISS_COOLDOWN_MS;
  const outcome: FetchOutcome = recentlyFailed
    ? { ok: false, message: 'JWKS refetch failed recently; it is retried after the cooldown' }
    : await runFetch(entry, params.jwksUri, params);

  if (!outcome.ok) {
    if (entry.state.fetchedAt === null) return { kind: 'unavailable', message: outcome.message };
    // An applied tombstone is final whatever the cache's age: no refetch could lift it.
    const known = selectKeys(entry.state, params.kid, params.family);
    if (known.kind === 'revoked') return known;
    const age = cacheAgeMs(entry.state, clock.monotonicMs());
    if (age > params.maxJwksAgeMs) {
      return { kind: 'stale', cacheAgeSeconds: Number.isFinite(age) ? Math.floor(age / 1000) : null };
    }
    // Only confirmed keys answer from a cache we failed to refresh (`withConfirmedKeysOnly`).
    const fallback = withConfirmedKeysOnly(entry.state);
    // A no-kid token tries every candidate: if the fallback lost one, a signature that matches none
    // of the rest may still be that key's — "could not check", not a forgery.
    if (params.kid === undefined && candidateCount(fallback, params.family) < candidateCount(entry.state, params.family)) {
      return { kind: 'unavailable', message: outcome.message };
    }
    const cached = await resolveFromState(entry, fallback, params.kid, params.family, params.alg);
    // An unknown kid we could not refetch may be a key the issuer just added: "could not check".
    return cached.kind === 'unknown' ? { kind: 'unavailable', message: outcome.message } : cached;
  }

  const resolved = await resolveFromState(entry, entry.state, params.kid, params.family, params.alg);
  if (resolved.kind === 'unknown') entry.lastMissAt = clock.monotonicMs();
  return resolved;
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

/**
 * Signature first, then the window and lifetime of the key that verified it — so a forged token
 * is reported as `bad_signature`, not as a policy violation of a key it never came from.
 */
export async function verifyWithCandidates(
  resolution: Extract<KeyResolution, { kind: 'keys' }>,
  alg: SupportedAlgorithm,
  signingInput: string,
  signature: Uint8Array,
  token: { iat: unknown; exp: unknown }
): Promise<'ok' | 'bad_signature' | KeyPolicyViolation> {
  for (const candidate of resolution.candidates) {
    if (await verifySignature(candidate.key, alg, signingInput, signature)) {
      return checkKeyPolicy(candidate.record, token, resolution.registryLive) ?? 'ok';
    }
  }
  return 'bad_signature';
}

/**
 * Refetch a key set now, ignoring the TTL and cooldowns — the method a `jwks_stale` answer names.
 * Resolves with the outcome rather than throwing.
 */
export async function refreshJwks(params: {
  jwksUri: string;
  fetch?: FetchLike;
  timeoutMs?: number;
  keySetStore?: KeySetStore;
  onJwksEvent?: (event: JwksEvent) => void;
}): Promise<{ ok: true } | { ok: false; message: string }> {
  const entry = entryFor(params.jwksUri);
  await loadFromStore(entry, params.jwksUri, params);
  return runFetch(entry, params.jwksUri, {
    ...params,
    fetch: params.fetch ?? ((input, init) => fetch(input, init)),
    timeoutMs: params.timeoutMs ?? DEFAULT_IO_TIMEOUT_MS,
  });
}

/**
 * Forget every applied and pending tombstone — the documented manual reset. With `jwksUri`, only
 * that key set (and, given a `keySetStore`, its persisted copy); without, every set in memory.
 */
export async function clearTombstones(params: { jwksUri?: string; keySetStore?: KeySetStore } = {}): Promise<void> {
  const uris = params.jwksUri !== undefined ? [params.jwksUri] : [...cache.keys()];
  for (const jwksUri of uris) {
    const entry = entryFor(jwksUri);
    await loadFromStore(entry, jwksUri, params);
    entry.state = withoutTombstones(entry.state);
    await saveToStore(entry, jwksUri, params);
  }
}

export interface JwksDiagnostics {
  jwksUri: string;
  /** Age of the cached set in seconds; null when never fetched or the persisted age is unknown. */
  cacheAgeSeconds: number | null;
  registryLive: boolean;
  /** Confirmed registry kids no longer served before their retention ended — kept with last-known state. */
  vanishedKids: string[];
  pendingTombstones: Array<{ kid: string; revokedAt: number; pendingForSeconds: number }>;
  appliedTombstones: Array<{ kid: string; revokedAt: number }>;
}

/** What the verifier currently holds for one key set, or null if it has never been used. */
export function getJwksDiagnostics(jwksUri: string): JwksDiagnostics | null {
  const entry = cache.get(jwksUri);
  if (!entry) return null;
  const now = clock.monotonicMs();
  const age = cacheAgeMs(entry.state, now);
  return {
    jwksUri,
    cacheAgeSeconds: Number.isFinite(age) ? Math.floor(age / 1000) : null,
    registryLive: isRegistryLive(entry.state),
    vanishedKids: [...entry.state.keys.values()]
      .filter((record) => record.vanished && record.kid)
      .map((record) => record.kid as string),
    pendingTombstones: [...entry.state.pending.values()].map((pending) => ({
      kid: pending.kid,
      revokedAt: pending.revokedAt,
      pendingForSeconds: Math.floor((now - pending.firstSeen.monotonicMs) / 1000),
    })),
    appliedTombstones: [...entry.state.applied.values()].map((applied) => ({ ...applied })),
  };
}
