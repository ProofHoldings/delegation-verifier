/**
 * The key-set rules, free of I/O: how a fetched JWKS is merged into what the verifier already
 * knows, and which key — if any — may verify a token of a given family.
 *
 * Kept apart from `jwks.ts` (fetch, cache, cooldowns) because these are the rules every verifier
 * must agree on — the JS, Python, Go and PHP SDKs port them function for function, and the shared
 * fixtures in `sdks/shared/fixtures/jwks_rotation/` pin the outcome of each one.
 *
 * Four properties are load-bearing:
 *
 *   - One response is never trusted for long. Anything that would outlive the next fetch — a key
 *     being remembered, a window narrowing, a tombstone — takes effect only when a second fetch, at
 *     least five minutes after the first sighting, says the same. A key verifies from its first
 *     sighting (an emergency key must work at once), but until it is confirmed the next document
 *     replaces or drops it, exactly as before rotation existed. Otherwise one poisoned response
 *     could plant a key the verifier keeps for as long as that key's own members claim, or revoke
 *     or re-date an honest key fleet-wide.
 *   - A fetch is MERGED, never swapped in. A CONFIRMED registry key that disappears keeps its
 *     last-known state, never gets new key material, and its window may narrow (by the rule above)
 *     but never widen — a document that widens one is refused whole, whatever key material it
 *     serves under that kid.
 *   - An applied tombstone is sticky until every token the key signed is dead.
 *   - "Registry live" is a property of the merged set (some key carries `proof_purpose`). Until
 *     then the set is in tolerant mode and behaves exactly as it did before rotation existed. An
 *     unconfirmed key counts too: it is gone with the next document that omits it.
 */

import { isRecord } from './jwt.js';
import type { JwksEventType } from './types.js';

export const KEY_FAMILIES = ['proof', 'delegation', 'status-list'] as const;
export type KeyFamily = (typeof KEY_FAMILIES)[number];

/** Clock skew tolerated on each edge of a key's `[not_before, not_after]` window. */
export const KEY_WINDOW_SKEW_SECONDS = 300;
/** Minimum spacing between the two fetches that confirm a key, a narrowed window or a tombstone. */
export const CONFIRM_SPACING_MS = 5 * 60_000;
/** An applied tombstone is kept until `revoked_at` plus this. */
export const TOMBSTONE_RETENTION_SECONDS = 365 * 86_400;

/** Both clocks at one instant: monotonic for in-process intervals, wall for anything persisted. */
export interface KeySetClockReading {
  monotonicMs: number;
  wallMs: number;
}

export interface KeyRecord {
  kid?: string;
  /** The JWK as last accepted, with any narrowing of its window applied. */
  jwk: Record<string, unknown>;
  /** Identity of the key material: a protected kid keeps its first material, an unprotected one takes the latest. */
  fingerprint: string;
  /** `alg`, `use` and `key_ops` — the members that decide whether the key may verify at all. */
  usage: string;
  hasPurposeMember: boolean;
  purpose?: KeyFamily;
  legacy: boolean;
  notBefore?: number;
  notAfter?: number;
  maxTokenLifetime?: number;
  vanished: boolean;
  /** When this exact description of the key was first served. */
  firstSeen: KeySetClockReading;
  /** Served unchanged by two fetches at least `CONFIRM_SPACING_MS` apart. */
  confirmed: boolean;
  /** A narrower window served for a confirmed key, applied once a later fetch confirms it. */
  pendingWindow?: PendingWindow;
}

export interface PendingWindow {
  notBefore: number;
  notAfter: number;
  firstSeen: KeySetClockReading;
}

export interface PendingTombstone {
  kid: string;
  revokedAt: number;
  firstSeen: KeySetClockReading;
}

export interface AppliedTombstone {
  kid: string;
  revokedAt: number;
}

export interface KeySetState {
  keys: Map<string, KeyRecord>;
  /** Keys served without a `kid` — tolerant mode only ever needs them. */
  anonymous: KeyRecord[];
  pending: Map<string, PendingTombstone>;
  applied: Map<string, AppliedTombstone>;
  fetchedAt: KeySetClockReading | null;
  /** A persisted `fetched_at` lay in the future: its age is unknown, so it counts as stale. */
  fetchedAtUntrusted: boolean;
}

export type KeySetEventType = Exclude<JwksEventType, 'store_error'>;

export interface KeySetEvent {
  type: KeySetEventType;
  kid?: string;
  message: string;
}

export interface MergeResult {
  state: KeySetState;
  events: KeySetEvent[];
  /** False when the document was refused whole; `state` is then the unchanged input. */
  accepted: boolean;
}

export type KeySelection =
  | { kind: 'candidates'; records: KeyRecord[] }
  | { kind: 'revoked'; kid: string }
  | { kind: 'wrong_purpose'; kid: string }
  | { kind: 'unknown' };

export type KeyPolicyViolation = 'outside_key_window' | 'token_lifetime_exceeded';

export function emptyKeySetState(): KeySetState {
  return {
    keys: new Map(),
    anonymous: [],
    pending: new Map(),
    applied: new Map(),
    fetchedAt: null,
    fetchedAtUntrusted: false,
  };
}

function isWholeNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value);
}

function isKeyFamily(value: unknown): value is KeyFamily {
  return typeof value === 'string' && (KEY_FAMILIES as readonly string[]).includes(value);
}

const MATERIAL_MEMBERS = ['kty', 'crv', 'x', 'y', 'n', 'e'] as const;

function fingerprintOf(jwk: Record<string, unknown>): string {
  return JSON.stringify(MATERIAL_MEMBERS.map((member) => jwk[member] ?? null));
}

function usageOf(jwk: Record<string, unknown>): string {
  return JSON.stringify([jwk.alg ?? null, jwk.use ?? null, jwk.key_ops ?? null]);
}

export function parseKeyRecord(jwk: Record<string, unknown>, firstSeen: KeySetClockReading): KeyRecord {
  const record: KeyRecord = {
    jwk,
    fingerprint: fingerprintOf(jwk),
    usage: usageOf(jwk),
    hasPurposeMember: jwk.proof_purpose !== undefined,
    legacy: jwk.proof_legacy === true,
    vanished: false,
    firstSeen,
    confirmed: false,
  };
  if (typeof jwk.kid === 'string' && jwk.kid.length > 0) record.kid = jwk.kid;
  if (isKeyFamily(jwk.proof_purpose)) record.purpose = jwk.proof_purpose;
  if (isWholeNumber(jwk.not_before)) record.notBefore = jwk.not_before;
  if (isWholeNumber(jwk.not_after)) record.notAfter = jwk.not_after;
  if (isWholeNumber(jwk.max_token_lifetime)) record.maxTokenLifetime = jwk.max_token_lifetime;
  return record;
}

function hasWindow(record: KeyRecord): record is KeyRecord & { notBefore: number; notAfter: number; maxTokenLifetime: number } {
  return record.notBefore !== undefined && record.notAfter !== undefined && record.maxTokenLifetime !== undefined;
}

/**
 * A key the issuer's registry describes — it carries `proof_purpose` or `proof_legacy` — AND that
 * two fetches at least `CONFIRM_SPACING_MS` apart served unchanged. The ONE predicate behind every
 * rule that outlives a fetch: material lock, no widening, pending narrowing, retained when it
 * vanishes. Window members alone do not make a registry key: without a purpose such a key cannot
 * verify anything once the registry is live, so it keeps tolerant semantics.
 */
function isProtectedRecord(record: KeyRecord): boolean {
  return record.confirmed && (record.hasPurposeMember || record.legacy);
}

/**
 * Whether two records describe the same key: material, usage, purpose, legacy marker and window.
 * Usage counts because the record kept is the one first seen: a poisoned first sighting marked
 * `use: "enc"` must be replaced by the honest description, not confirmed by it.
 */
function describesSameKey(a: KeyRecord, b: KeyRecord): boolean {
  return (
    a.fingerprint === b.fingerprint &&
    a.usage === b.usage &&
    a.hasPurposeMember === b.hasPurposeMember &&
    a.purpose === b.purpose &&
    a.legacy === b.legacy &&
    a.notBefore === b.notBefore &&
    a.notAfter === b.notAfter &&
    a.maxTokenLifetime === b.maxTokenLifetime
  );
}

function spacingElapsed(since: KeySetClockReading, now: KeySetClockReading): boolean {
  return now.monotonicMs - since.monotonicMs >= CONFIRM_SPACING_MS;
}

export function isRegistryLive(state: KeySetState): boolean {
  for (const record of state.keys.values()) if (record.hasPurposeMember) return true;
  return state.anonymous.some((record) => record.hasPurposeMember);
}

function wallSeconds(reading: KeySetClockReading): number {
  return Math.floor(reading.wallMs / 1000);
}

/** Whether a kid may still be signing: legacy, window unknown, or not yet past `not_after`. */
function isLiveKey(record: KeyRecord, nowSeconds: number): boolean {
  if (record.legacy || !hasWindow(record)) return true;
  return nowSeconds <= record.notAfter + KEY_WINDOW_SKEW_SECONDS;
}

function parseTombstones(value: unknown): AppliedTombstone[] {
  if (!Array.isArray(value)) return [];
  const tombstones: AppliedTombstone[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    if (typeof entry.kid !== 'string' || entry.kid.length === 0) continue;
    if (!isWholeNumber(entry.revoked_at)) continue;
    tombstones.push({ kid: entry.kid, revokedAt: entry.revoked_at });
  }
  return tombstones;
}

function cloneState(state: KeySetState): KeySetState {
  return {
    keys: new Map([...state.keys].map(([kid, record]) => [kid, { ...record }])),
    anonymous: state.anonymous.map((record) => ({ ...record })),
    pending: new Map(state.pending),
    applied: new Map(state.applied),
    fetchedAt: state.fetchedAt,
    fetchedAtUntrusted: state.fetchedAtUntrusted,
  };
}

/**
 * Merge one fetched JWKS body (already known to be an object with a `keys` array) into `state`.
 * Pure: returns a new state and the events the caller should report.
 */
export function mergeFetchedDocument(
  state: KeySetState,
  body: Record<string, unknown>,
  now: KeySetClockReading
): MergeResult {
  const nowSeconds = wallSeconds(now);
  const candidates = Array.isArray(body.keys) ? body.keys.filter(isRecord) : [];
  const served = new Map<string, KeyRecord>();
  const anonymous: KeyRecord[] = [];
  for (const jwk of candidates) {
    const record = parseKeyRecord(jwk, now);
    if (record.kid) served.set(record.kid, record);
    else anonymous.push(record);
  }

  // Widening is checked before anything is touched: such a document is refused whole.
  for (const [kid, incoming] of served) {
    const known = state.keys.get(kid);
    if (!known || !isProtectedRecord(known) || !hasWindow(known) || !hasWindow(incoming)) continue;
    if (incoming.notBefore < known.notBefore || incoming.notAfter > known.notAfter) {
      return {
        state,
        accepted: false,
        events: [
          {
            type: 'window_widening_rejected',
            kid,
            message: `JWKS refused: it widens the window of confirmed key "${kid}"`,
          },
        ],
      };
    }
  }

  const next = cloneState(state);
  const events: KeySetEvent[] = [];
  const tombstones = parseTombstones(body.proof_tombstones);
  const tombstonedNow = new Set(tombstones.map((tombstone) => tombstone.kid));

  for (const [kid, incoming] of served) {
    const known = next.keys.get(kid);
    // Not protected yet: the latest document describes the key, exactly as before rotation
    // existed. Serving the same description again, far enough apart, confirms it.
    if (!known || !isProtectedRecord(known)) {
      if (known && describesSameKey(known, incoming)) {
        if (!known.confirmed && spacingElapsed(known.firstSeen, now)) known.confirmed = true;
      } else {
        next.keys.set(kid, incoming);
      }
      continue;
    }
    known.vanished = false;
    if (known.fingerprint !== incoming.fingerprint) {
      delete known.pendingWindow;
      events.push({
        type: 'key_material_changed',
        kid,
        message: `JWKS serves different key material for confirmed key "${kid}"; the first-seen key is kept`,
      });
      continue;
    }
    if (!hasWindow(known) || !hasWindow(incoming)) continue;
    if (incoming.notBefore === known.notBefore && incoming.notAfter === known.notAfter) {
      delete known.pendingWindow;
      continue;
    }
    const pending = known.pendingWindow;
    if (!pending || pending.notBefore !== incoming.notBefore || pending.notAfter !== incoming.notAfter) {
      known.pendingWindow = { notBefore: incoming.notBefore, notAfter: incoming.notAfter, firstSeen: now };
      events.push({
        type: 'window_narrowing_pending',
        kid,
        message: `JWKS narrows the window of confirmed key "${kid}"; applied only if a fetch at least 5 minutes later serves the same window`,
      });
      continue;
    }
    if (!spacingElapsed(pending.firstSeen, now)) continue;
    known.notBefore = pending.notBefore;
    known.notAfter = pending.notAfter;
    known.jwk = { ...known.jwk, not_before: pending.notBefore, not_after: pending.notAfter };
    delete known.pendingWindow;
    events.push({
      type: 'window_narrowing_applied',
      kid,
      message: `narrowed window of key "${kid}" confirmed by a second fetch and applied`,
    });
  }

  for (const [kid, known] of [...next.keys]) {
    if (served.has(kid)) continue;
    if (!isProtectedRecord(known)) {
      next.keys.delete(kid);
      continue;
    }
    if (hasWindow(known)) {
      if (nowSeconds > known.notAfter + known.maxTokenLifetime + KEY_WINDOW_SKEW_SECONDS) {
        next.keys.delete(kid);
        continue;
      }
    } else if (!known.legacy) {
      next.keys.delete(kid);
      continue;
    }
    // A narrowing is confirmed by consecutive documents serving it; one that omits the kid breaks the run.
    delete known.pendingWindow;
    if (!known.vanished && !tombstonedNow.has(kid)) {
      known.vanished = true;
      events.push({
        type: 'kid_vanished',
        kid,
        message: `key "${kid}" is no longer served before its retention ended; its last-known state is kept`,
      });
    }
  }

  next.anonymous = anonymous;

  for (const [kid] of next.pending) {
    if (!tombstonedNow.has(kid)) next.pending.delete(kid);
  }
  for (const tombstone of tombstones) {
    if (next.applied.has(tombstone.kid)) continue;
    const pending = next.pending.get(tombstone.kid);
    if (pending) {
      if (spacingElapsed(pending.firstSeen, now)) {
        next.pending.delete(tombstone.kid);
        next.applied.set(tombstone.kid, { kid: tombstone.kid, revokedAt: pending.revokedAt });
        events.push({
          type: 'tombstone_applied',
          kid: tombstone.kid,
          message: `tombstone for key "${tombstone.kid}" confirmed by a second fetch and applied`,
        });
      }
      continue;
    }
    next.pending.set(tombstone.kid, { kid: tombstone.kid, revokedAt: tombstone.revokedAt, firstSeen: now });
    events.push({
      type: 'tombstone_pending',
      kid: tombstone.kid,
      message: `tombstone for key "${tombstone.kid}" seen; applied only if a fetch at least 5 minutes later still carries it`,
    });
    // "Last seen live" is read from what the verifier knew BEFORE this document, which may itself
    // have dropped the key.
    const known = state.keys.get(tombstone.kid);
    if (known && isLiveKey(known, nowSeconds)) {
      events.push({
        type: 'tombstone_for_live_key',
        kid: tombstone.kid,
        message: `ANOMALY: tombstone names key "${tombstone.kid}", which was last seen live`,
      });
    }
  }

  for (const [kid, applied] of [...next.applied]) {
    if (nowSeconds > applied.revokedAt + TOMBSTONE_RETENTION_SECONDS) next.applied.delete(kid);
  }

  next.fetchedAt = now;
  next.fetchedAtUntrusted = false;
  return { state: next, events, accepted: true };
}

/**
 * Which keys may verify a token of `family` carrying `kid`. Checks the applied tombstone and the
 * key's purpose; the signature and the window are the caller's next steps, in that order.
 */
export function selectKeys(state: KeySetState, kid: string | undefined, family: KeyFamily): KeySelection {
  const registryLive = isRegistryLive(state);
  if (kid !== undefined) {
    if (state.applied.has(kid)) return { kind: 'revoked', kid };
    const record = state.keys.get(kid);
    if (!record) return { kind: 'unknown' };
    if (record.legacy || !registryLive) return { kind: 'candidates', records: [record] };
    if (record.purpose !== family) return { kind: 'wrong_purpose', kid };
    return { kind: 'candidates', records: [record] };
  }

  // No `kid`: once the registry is live only a key marked legacy may answer — trying every key
  // would let a token borrow any family's key and skip the purpose check.
  const all = [...state.anonymous, ...state.keys.values()].filter(
    (record) => !(record.kid && state.applied.has(record.kid))
  );
  const records = registryLive ? all.filter((record) => record.legacy) : all;
  return records.length > 0 ? { kind: 'candidates', records } : { kind: 'unknown' };
}

/** The window and lifetime rules for a key whose signature has verified. */
export function checkKeyPolicy(
  record: KeyRecord,
  token: { iat: unknown; exp: unknown },
  registryLive: boolean
): KeyPolicyViolation | null {
  if (!registryLive || record.legacy) return null;
  if (!hasWindow(record)) return 'outside_key_window';
  if (!isWholeNumber(token.iat)) return 'outside_key_window';
  if (token.iat < record.notBefore - KEY_WINDOW_SKEW_SECONDS) return 'outside_key_window';
  if (token.iat > record.notAfter + KEY_WINDOW_SKEW_SECONDS) return 'outside_key_window';
  if (typeof token.exp !== 'number' || token.exp > token.iat + record.maxTokenLifetime) {
    return 'token_lifetime_exceeded';
  }
  return null;
}

/**
 * Fold the tombstones of a persisted state into a set this process has already fetched. The
 * fetched keys are newer than disk, but a tombstone is not something a later fetch can restore:
 * dropping the persisted one would silently un-revoke a key until two more fetches agreed again.
 */
export function withPersistedTombstones(state: KeySetState, persisted: KeySetState): KeySetState {
  const next = cloneState(state);
  for (const [kid, applied] of persisted.applied) {
    if (!next.applied.has(kid)) next.applied.set(kid, applied);
  }
  for (const [kid, pending] of persisted.pending) {
    if (!next.applied.has(kid) && !next.pending.has(kid)) next.pending.set(kid, pending);
  }
  return next;
}

/**
 * The part of a cached set that may answer after a refetch FAILED: confirmed keys only. An
 * unconfirmed key is trusted until the next document, and a failing fetch must not stretch that to
 * `maxJwksAgeMs` — otherwise one poisoned response followed by an outage would keep its key, and
 * the registry mode it switched on, for a day.
 */
export function withConfirmedKeysOnly(state: KeySetState): KeySetState {
  const next = cloneState(state);
  for (const [kid, record] of [...next.keys]) {
    if (!record.confirmed) next.keys.delete(kid);
  }
  next.anonymous = [];
  return next;
}

/** Drop every applied and pending tombstone — the documented manual reset. */
export function withoutTombstones(state: KeySetState): KeySetState {
  const next = cloneState(state);
  next.applied.clear();
  next.pending.clear();
  return next;
}

const PERSISTED_VERSION = 1;

/**
 * Persisted form. Every timestamp is wall-clock milliseconds: a monotonic reading means nothing
 * to another process.
 */
export function serializeKeySetState(state: KeySetState): string {
  return JSON.stringify({
    v: PERSISTED_VERSION,
    fetched_at_wall_ms: state.fetchedAt && !state.fetchedAtUntrusted ? state.fetchedAt.wallMs : null,
    keys: [...state.keys.values()].map((record) => ({
      jwk: record.jwk,
      vanished: record.vanished,
      confirmed: record.confirmed,
      first_seen_wall_ms: record.firstSeen.wallMs,
      ...(record.pendingWindow
        ? {
            pending_window: {
              not_before: record.pendingWindow.notBefore,
              not_after: record.pendingWindow.notAfter,
              first_seen_wall_ms: record.pendingWindow.firstSeen.wallMs,
            },
          }
        : {}),
    })),
    anonymous: state.anonymous.map((record) => record.jwk),
    pending: [...state.pending.values()].map((pending) => ({
      kid: pending.kid,
      revoked_at: pending.revokedAt,
      first_seen_wall_ms: pending.firstSeen.wallMs,
    })),
    applied: [...state.applied.values()].map((applied) => ({ kid: applied.kid, revoked_at: applied.revokedAt })),
  });
}

function fromWall(wallMs: number, now: KeySetClockReading): KeySetClockReading {
  return { wallMs, monotonicMs: now.monotonicMs - (now.wallMs - wallMs) };
}

/**
 * Rebuild a persisted state, or null when the blob is not one. A `fetched_at` in the future marks
 * the set stale; a pending tombstone first seen in the future is dropped.
 */
export function deserializeKeySetState(raw: string, now: KeySetClockReading): KeySetState | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isRecord(parsed) || parsed.v !== PERSISTED_VERSION) return null;

  const state = emptyKeySetState();
  if (Array.isArray(parsed.keys)) {
    for (const entry of parsed.keys) {
      if (!isRecord(entry) || !isRecord(entry.jwk)) continue;
      // A first sighting persisted in the future cannot be timed: the key starts over as unconfirmed.
      const firstSeenWall = entry.first_seen_wall_ms;
      const firstSeen = isWholeNumber(firstSeenWall) && firstSeenWall <= now.wallMs ? fromWall(firstSeenWall, now) : null;
      const record = parseKeyRecord(entry.jwk, firstSeen ?? now);
      if (!record.kid) continue;
      record.vanished = entry.vanished === true;
      record.confirmed = firstSeen !== null && entry.confirmed === true;
      const pendingWindow = entry.pending_window;
      if (
        isRecord(pendingWindow) &&
        isWholeNumber(pendingWindow.not_before) &&
        isWholeNumber(pendingWindow.not_after) &&
        isWholeNumber(pendingWindow.first_seen_wall_ms) &&
        pendingWindow.first_seen_wall_ms <= now.wallMs
      ) {
        record.pendingWindow = {
          notBefore: pendingWindow.not_before,
          notAfter: pendingWindow.not_after,
          firstSeen: fromWall(pendingWindow.first_seen_wall_ms, now),
        };
      }
      state.keys.set(record.kid, record);
    }
  }
  if (Array.isArray(parsed.anonymous)) {
    state.anonymous = parsed.anonymous.filter(isRecord).map((jwk) => parseKeyRecord(jwk, now));
  }
  for (const applied of parseTombstones(parsed.applied)) state.applied.set(applied.kid, applied);
  if (Array.isArray(parsed.pending)) {
    for (const entry of parsed.pending) {
      if (!isRecord(entry) || typeof entry.kid !== 'string' || !isWholeNumber(entry.revoked_at)) continue;
      if (!isWholeNumber(entry.first_seen_wall_ms) || entry.first_seen_wall_ms > now.wallMs) continue;
      state.pending.set(entry.kid, {
        kid: entry.kid,
        revokedAt: entry.revoked_at,
        firstSeen: fromWall(entry.first_seen_wall_ms, now),
      });
    }
  }

  const fetchedAtWall = parsed.fetched_at_wall_ms;
  if (isWholeNumber(fetchedAtWall)) {
    if (fetchedAtWall > now.wallMs) {
      state.fetchedAt = now;
      state.fetchedAtUntrusted = true;
    } else {
      state.fetchedAt = fromWall(fetchedAtWall, now);
    }
  }
  return state;
}
