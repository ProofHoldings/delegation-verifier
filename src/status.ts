/**
 * Revocation status of a delegation, over two channels that answer different questions.
 *
 *   1. **Token Status List** (IETF draft-ietf-oauth-status-list). The token carries its own
 *      slot — `status.status_list.{idx, uri}` — and the signed list at that uri says whether
 *      the slot is valid (0), revoked (1) or suspended (2). This is the standard, cacheable,
 *      herd-private channel, and — since `h-status-list-cascade-fold` — it is AUTHORITATIVE
 *      for the delegation, including the domain control proof cascade underneath it: a
 *      revoked or suspended control folds into this same bit, so `checkDelegationStatus`
 *      trusts a `valid`/`revoked`/`suspended` list read and does not also ask the endpoint
 *      (`h-delegation-verifier-status-fallthrough-gate`).
 *   2. **The issuer's status endpoint.** Stays the only channel for three things the bit
 *      cannot express: `unknown_delegation` ("no record of this handle" is distinguishable
 *      from "we have a record and it is dead" only by a live call), a token carrying no
 *      status-list claim at all, and cascade-derived EXPIRY — the control's own `expires_at`
 *      is never packed into the bit (only revoked/suspended are), so a delegation whose
 *      effective lifetime is capped by an expired control, while its own list bit and its own
 *      `exp` claim both still read fine, is only visible through this endpoint.
 *
 *      `h-fix-control-proof-reissue-shorter` closes the write side of that expiry gap going
 *      forward — a delegation can no longer be minted longer than its control, and reissuing a
 *      control shorter than an outstanding delegation now caps the reissue instead of leaving
 *      the delegation to outlive it — but two bounded residuals remain, both deliberately
 *      accepted there rather than fixed here: a control shortened before that task shipped
 *      (measured zero on staging, unmeasured in production), and that task's own fail-open
 *      when its registry-budget guard cannot run. A verifier package cannot special-case any
 *      one issuer's guarantees, so this residual is disclosed, not silently assumed away — see
 *      the package README's Failure reasons section.
 *
 * Both channels are authenticated: the status list is a signed JWT checked against the same
 * key set as the delegation, and the uri inside the token is refused unless it belongs to the
 * trusted issuer — it arrives INSIDE the artifact being verified, so treating it as an address
 * to fetch would hand an attacker both the status authority and an SSRF primitive.
 */

import { base64UrlToBytes, isRecord, parseJwt } from './jwt.js';
import { getVerificationKeys, isSupportedAlgorithm, MAX_REMOTE_BODY_BYTES, verifySignature } from './jwks.js';
import type { FetchLike, TrustedIssuer } from './types.js';

export type StatusOutcome =
  | { state: 'valid' }
  | { state: 'revoked'; message: string }
  | { state: 'suspended'; message: string }
  /** The issuer's clock says this delegation is over — distinct from withdrawn. */
  | { state: 'expired'; message: string }
  /** The issuer has no record of the delegation at all. */
  | { state: 'unknown'; message: string }
  | { state: 'untrusted_uri'; message: string }
  | { state: 'unavailable'; message: string };

const STATUS_VALID = 0;
const STATUS_REVOKED = 1;
const STATUS_SUSPENDED = 2;

export function allowedStatusOrigins(issuer: TrustedIssuer): string[] {
  const origins = new Set<string>();
  for (const candidate of [issuer.jwksUri, issuer.statusEndpoint, ...(issuer.statusListOrigins ?? [])]) {
    if (!candidate) continue;
    try {
      origins.add(new URL(candidate).origin);
    } catch {
      // A malformed policy entry contributes no origin; the caller's own validation reports it.
    }
  }
  return [...origins];
}

/** Inflate a zlib-wrapped DEFLATE payload without pulling in a compression dependency. */
async function inflate(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate'));
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

/**
 * Read one 2-bit slot out of a decoded status list. Lowest index in the least significant
 * bits, `bits` statuses per byte — the draft's byte order.
 */
export function readStatusSlot(bytes: Uint8Array, index: number, bits: number): number | null {
  if (!Number.isInteger(index) || index < 0) return null;
  if (bits !== 1 && bits !== 2 && bits !== 4 && bits !== 8) return null;
  const perByte = 8 / bits;
  const byteIndex = Math.floor(index / perByte);
  if (byteIndex >= bytes.length) return null;
  const shift = (index % perByte) * bits;
  const mask = (1 << bits) - 1;
  return (bytes[byteIndex] >> shift) & mask;
}

interface StatusListClaim {
  idx: number;
  uri: string;
}

export function readStatusListClaim(claims: Record<string, unknown>): StatusListClaim | null {
  const status = claims.status;
  if (!isRecord(status)) return null;
  const statusList = status.status_list;
  if (!isRecord(statusList)) return null;
  const { idx, uri } = statusList;
  if (typeof idx !== 'number' || !Number.isInteger(idx) || idx < 0) return null;
  if (typeof uri !== 'string' || uri.length === 0) return null;
  return { idx, uri };
}

async function checkStatusList(params: {
  claim: StatusListClaim;
  issuer: TrustedIssuer;
  fetch: FetchLike;
  timeoutMs: number;
  now: Date;
  clockToleranceSeconds: number;
}): Promise<StatusOutcome> {
  const { claim, issuer } = params;

  let uri: URL;
  try {
    uri = new URL(claim.uri);
  } catch {
    return { state: 'untrusted_uri', message: 'status list uri is not a valid URL' };
  }
  if (!allowedStatusOrigins(issuer).includes(uri.origin)) {
    return {
      state: 'untrusted_uri',
      message: `status list uri origin ${uri.origin} is not an origin of trusted issuer "${issuer.issuer}"`,
    };
  }

  let response: Response;
  try {
    response = await params.fetch(uri.toString(), {
      signal: AbortSignal.timeout(params.timeoutMs),
      headers: { accept: 'application/statuslist+jwt, application/jwt, text/plain' },
      // The origin guard above is only worth as much as the hop it guards: with the default
      // `follow`, ANY open redirect on the issuer's origin would carry this fetch off it —
      // the token controls the path — handing back both the status authority and an SSRF
      // primitive against the verifying gateway's network.
      redirect: 'error',
    });
  } catch (error) {
    return {
      state: 'unavailable',
      message: `status list fetch failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (!response.ok) {
    return { state: 'unavailable', message: `status list fetch failed with HTTP ${response.status}` };
  }

  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REMOTE_BODY_BYTES) {
    return { state: 'unavailable', message: 'status list response is too large' };
  }

  const listToken = (await response.text()).trim();
  if (listToken.length > MAX_REMOTE_BODY_BYTES) {
    return { state: 'unavailable', message: 'status list response is too large' };
  }
  const parsed = parseJwt(listToken);
  if (!parsed) return { state: 'unavailable', message: 'status list is not a JWT' };

  const alg = parsed.header.alg;
  if (!isSupportedAlgorithm(alg)) {
    return { state: 'unavailable', message: `status list uses unsupported algorithm ${String(alg)}` };
  }

  // The draft mandates this `typ`, and it is the one header that separates a status list from
  // every other JWT the issuer signs with the SAME key — without it, any such token with a
  // matching `sub` could stand in as a status authority.
  if (parsed.header.typ !== 'statuslist+jwt') {
    return {
      state: 'unavailable',
      message: `status list must carry typ "statuslist+jwt", got ${JSON.stringify(parsed.header.typ)}`,
    };
  }

  let keys: CryptoKey[];
  try {
    keys = await getVerificationKeys({
      jwksUri: issuer.jwksUri,
      kid: typeof parsed.header.kid === 'string' ? parsed.header.kid : undefined,
      alg,
      fetch: params.fetch,
      timeoutMs: params.timeoutMs,
    });
  } catch (error) {
    return {
      state: 'unavailable',
      message: `status list signing key unavailable: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (keys.length === 0) {
    return { state: 'unavailable', message: 'status list is signed by an unknown key' };
  }

  let signatureOk = false;
  for (const key of keys) {
    if (await verifySignature(key, alg, parsed.signingInput, parsed.signature)) {
      signatureOk = true;
      break;
    }
  }
  if (!signatureOk) {
    return { state: 'unavailable', message: 'status list signature is invalid' };
  }

  // The list must say it is the list we asked for, or a valid list from the same issuer could
  // be replayed in place of another one.
  if (parsed.payload.sub !== claim.uri) {
    return { state: 'unavailable', message: 'status list `sub` does not match the uri it was fetched from' };
  }

  // A freshness channel with no expiry is not one: an `exp`-less list would be honoured
  // forever, so its absence is treated as "cannot answer" rather than fail-open.
  const nowSeconds = Math.floor(params.now.getTime() / 1000);
  const exp = parsed.payload.exp;
  if (typeof exp !== 'number') {
    return { state: 'unavailable', message: 'status list carries no exp' };
  }
  if (nowSeconds > exp + params.clockToleranceSeconds) {
    return { state: 'unavailable', message: 'status list has expired' };
  }

  const statusList = parsed.payload.status_list;
  if (!isRecord(statusList) || typeof statusList.lst !== 'string') {
    return { state: 'unavailable', message: 'status list payload has no `lst`' };
  }
  const bits = typeof statusList.bits === 'number' ? statusList.bits : 2;

  let decoded: Uint8Array;
  try {
    decoded = await inflate(base64UrlToBytes(statusList.lst));
  } catch (error) {
    return {
      state: 'unavailable',
      message: `status list payload could not be decompressed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const slot = readStatusSlot(decoded, claim.idx, bits);
  if (slot === null) {
    // A slot beyond the list is not "valid" — the issuer has no answer for this token.
    return { state: 'unavailable', message: `status list has no slot ${claim.idx}` };
  }
  if (slot === STATUS_REVOKED) return { state: 'revoked', message: 'the issuer status list marks this delegation revoked' };
  if (slot === STATUS_SUSPENDED) {
    return { state: 'suspended', message: 'the issuer status list marks this delegation suspended' };
  }
  if (slot !== STATUS_VALID) {
    return { state: 'unavailable', message: `status list slot carries unknown status ${slot}` };
  }
  return { state: 'valid' };
}

/**
 * Ask the issuer's status endpoint about this exact token. Contract:
 * `POST` `{"proof_token": "<jwt>"}` → JSON with at least `{"valid": boolean}` and optionally
 * `{"reason": "revoked" | "suspended" | "expired" | ...}`.
 */
async function checkStatusEndpoint(params: {
  token: string;
  issuer: TrustedIssuer;
  fetch: FetchLike;
  timeoutMs: number;
}): Promise<StatusOutcome> {
  const endpoint = params.issuer.statusEndpoint;
  if (!endpoint) {
    return {
      state: 'unavailable',
      message: `trusted issuer "${params.issuer.issuer}" declares no statusEndpoint, so the control-proof cascade cannot be checked`,
    };
  }

  let response: Response;
  try {
    response = await params.fetch(endpoint, {
      method: 'POST',
      signal: AbortSignal.timeout(params.timeoutMs),
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ proof_token: params.token }),
      redirect: 'error',
    });
  } catch (error) {
    return {
      state: 'unavailable',
      message: `status endpoint request failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  if (!response.ok) {
    return { state: 'unavailable', message: `status endpoint answered HTTP ${response.status}` };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { state: 'unavailable', message: 'status endpoint answered with a non-JSON body' };
  }
  if (!isRecord(body) || typeof body.valid !== 'boolean') {
    return { state: 'unavailable', message: 'status endpoint answer carries no `valid` boolean' };
  }
  if (body.valid) return { state: 'valid' };

  // `valid: false` is not automatically "withdrawn". An issuer answers it for things that mean
  // "I could not check" too — proof.holdings itself answers `status_unavailable` on a registry
  // read failure. Reporting those as `revoked` would make a database blip at the issuer look
  // like a permanent withdrawal to every gateway that asked, so only reasons that actually
  // name a withdrawal are treated as one; anything unrecognised fails closed as unavailable.
  const reason = typeof body.reason === 'string' ? body.reason : '';
  switch (reason) {
    case 'revoked':
      return { state: 'revoked', message: 'the issuer reports this delegation revoked' };
    case 'suspended':
      return { state: 'suspended', message: 'the issuer reports this delegation suspended' };
    case 'expired':
      return { state: 'expired', message: 'the issuer reports this delegation expired' };
    case 'unknown_delegation':
      return { state: 'unknown', message: 'the issuer has no record of this delegation' };
    default:
      return {
        state: 'unavailable',
        message: `the issuer answered invalid without a recognised reason (${reason || 'none'})`,
      };
  }
}

/**
 * Combined status. A negative answer from EITHER channel is decisive; `unavailable` from
 * either one is reported so the caller can fail closed.
 */
export async function checkDelegationStatus(params: {
  token: string;
  claims: Record<string, unknown>;
  issuer: TrustedIssuer;
  fetch: FetchLike;
  timeoutMs: number;
  now: Date;
  clockToleranceSeconds: number;
}): Promise<StatusOutcome> {
  const claim = readStatusListClaim(params.claims);
  if (claim) {
    const listOutcome = await checkStatusList({
      claim,
      issuer: params.issuer,
      fetch: params.fetch,
      timeoutMs: params.timeoutMs,
      now: params.now,
      clockToleranceSeconds: params.clockToleranceSeconds,
    });
    // Authoritative for `valid`/`revoked`/`suspended` — the fold (h-status-list-cascade-fold)
    // makes those three the issuer's whole answer for this delegation's own bit.
    // `unavailable`/`untrusted_uri` mean "could not read the list", not an answer from it, and
    // still fall through to the endpoint below.
    if (listOutcome.state !== 'unavailable' && listOutcome.state !== 'untrusted_uri') {
      return listOutcome;
    }
  }

  return checkStatusEndpoint({
    token: params.token,
    issuer: params.issuer,
    fetch: params.fetch,
    timeoutMs: params.timeoutMs,
  });
}
