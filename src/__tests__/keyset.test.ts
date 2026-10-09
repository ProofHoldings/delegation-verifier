import { describe, expect, it } from 'vitest';
import {
  checkKeyPolicy,
  CONFIRM_SPACING_MS,
  deserializeKeySetState,
  emptyKeySetState,
  isRegistryLive,
  KEY_WINDOW_SKEW_SECONDS,
  mergeFetchedDocument,
  selectKeys,
  serializeKeySetState,
  TOMBSTONE_RETENTION_SECONDS,
} from '../keyset.js';
import type { KeySetState, KeySetClockReading } from '../keyset.js';

const T0 = 1_798_761_600;
const DAY = 86_400;

function at(seconds: number): KeySetClockReading {
  return { monotonicMs: seconds * 1000, wallMs: seconds * 1000 };
}

function ecJwk(kid: string | undefined, x: string, members: Record<string, unknown> = {}): Record<string, unknown> {
  return { kty: 'EC', crv: 'P-256', x, y: `${x}-y`, alg: 'ES256', use: 'sig', ...(kid ? { kid } : {}), ...members };
}

function registryJwk(
  kid: string,
  x: string,
  purpose: string,
  window: { nb: number; na: number; mtl?: number }
): Record<string, unknown> {
  return ecJwk(kid, x, {
    proof_purpose: purpose,
    not_before: window.nb,
    not_after: window.na,
    max_token_lifetime: window.mtl ?? 365 * DAY,
  });
}

const D1 = registryJwk('D1', 'd1', 'delegation', { nb: T0 - 30 * DAY, na: T0 + 30 * DAY });
const P1 = registryJwk('P1', 'p1', 'proof', { nb: T0 - 30 * DAY, na: T0 + 30 * DAY });
const R1 = registryJwk('R1', 'r1', 'delegation', { nb: T0 - 60 * DAY, na: T0 - 30 * DAY });
const L1 = ecJwk('L1', 'l1', { proof_legacy: true });
const T1 = ecJwk('T1', 't1');

function merge(state: KeySetState, doc: Record<string, unknown>, seconds: number) {
  return mergeFetchedDocument(state, doc, at(seconds));
}

function accepted(state: KeySetState, doc: Record<string, unknown>, seconds: number): KeySetState {
  const result = merge(state, doc, seconds);
  expect(result.accepted).toBe(true);
  return result.state;
}

const SPACING = CONFIRM_SPACING_MS / 1000;

/** Two identical sightings one confirmation spacing apart — the state of a key served for a while. */
function confirmed(doc: Record<string, unknown>, seconds = T0): KeySetState {
  return accepted(accepted(emptyKeySetState(), doc, seconds), doc, seconds + SPACING);
}

describe('one response is never trusted for long', () => {
  const EVIL = registryJwk('EVIL', 'evil', 'delegation', { nb: 0, na: 4_000_000_000, mtl: 4_000_000_000 });

  it('forgets a key served by a single response as soon as the next one omits it', () => {
    let state = confirmed({ keys: [T1] });
    const poisoned = merge(state, { keys: [T1, EVIL] }, T0 + 700);
    state = poisoned.state;
    expect(isRegistryLive(state)).toBe(true);
    const honest = merge(state, { keys: [T1] }, T0 + 1400);
    state = honest.state;
    expect(honest.events).toEqual([]);
    expect(state.keys.has('EVIL')).toBe(false);
    expect(isRegistryLive(state)).toBe(false);
    expect(selectKeys(state, 'T1', 'delegation').kind).toBe('candidates');
    expect(selectKeys(state, 'EVIL', 'delegation').kind).toBe('unknown');
  });

  it('lets a key verify from its first sighting, so an emergency key works at once', () => {
    const state = accepted(confirmed({ keys: [D1] }), { keys: [D1, EVIL] }, T0 + 700);
    expect(selectKeys(state, 'EVIL', 'delegation').kind).toBe('candidates');
  });

  it('replaces the material and window of an unconfirmed kid with what the next document serves', () => {
    let state = accepted(emptyKeySetState(), { keys: [{ ...D1, x: 'attacker', not_after: T0 + 900 * DAY }] }, T0);
    const honest = merge(state, { keys: [D1] }, T0 + 100);
    state = honest.state;
    expect(honest.accepted).toBe(true);
    expect(honest.events).toEqual([]);
    expect(state.keys.get('D1')?.jwk.x).toBe('d1');
    expect(state.keys.get('D1')?.notAfter).toBe(D1.not_after);
  });

  it('confirms a kid only when a fetch at least five minutes after first sight serves it unchanged', () => {
    let state = accepted(emptyKeySetState(), { keys: [D1] }, T0);
    state = accepted(state, { keys: [D1] }, T0 + SPACING - 1);
    expect(state.keys.get('D1')?.confirmed).toBe(false);
    state = accepted(state, { keys: [{ ...D1, not_after: T0 + DAY }] }, T0 + SPACING);
    expect(state.keys.get('D1')?.confirmed).toBe(false);
    state = accepted(state, { keys: [{ ...D1, not_after: T0 + DAY }] }, T0 + 2 * SPACING);
    expect(state.keys.get('D1')?.confirmed).toBe(true);
    expect(state.keys.get('D1')?.notAfter).toBe(T0 + DAY);
  });

  it('replaces an unconfirmed kid whose first sighting declared another alg, use or key_ops', () => {
    for (const poisoned of [{ use: 'enc' }, { alg: 'RS256' }, { key_ops: ['encrypt'] }]) {
      let state = accepted(emptyKeySetState(), { keys: [{ ...D1, ...poisoned }] }, T0);
      state = accepted(state, { keys: [D1] }, T0 + SPACING);
      expect(state.keys.get('D1')?.jwk).toEqual(D1);
      expect(state.keys.get('D1')?.confirmed).toBe(false);
      state = accepted(state, { keys: [D1] }, T0 + 2 * SPACING);
      expect(state.keys.get('D1')?.confirmed).toBe(true);
    }
  });

  it('drops a pending narrowing when a document omits the kid or re-keys it', () => {
    const narrowed = accepted(confirmed({ keys: [D1, P1] }), { keys: [{ ...D1, not_after: T0 + DAY }, P1] }, T0 + 700);
    expect(narrowed.keys.get('D1')?.pendingWindow).toBeDefined();
    expect(accepted(narrowed, { keys: [P1] }, T0 + 1400).keys.get('D1')?.pendingWindow).toBeUndefined();
    expect(accepted(narrowed, { keys: [{ ...D1, x: 'other' }, P1] }, T0 + 1400).keys.get('D1')?.pendingWindow).toBeUndefined();
  });

  it('times confirmation on the monotonic clock, not the wall clock', () => {
    const doc = { keys: [D1] };
    const first = mergeFetchedDocument(emptyKeySetState(), doc, { monotonicMs: 5_000, wallMs: T0 * 1000 });
    const wallJumped = mergeFetchedDocument(first.state, doc, { monotonicMs: 65_000, wallMs: (T0 + 3600) * 1000 });
    expect(wallJumped.state.keys.get('D1')?.confirmed).toBe(false);
    const monoElapsed = mergeFetchedDocument(first.state, doc, { monotonicMs: 5_000 + CONFIRM_SPACING_MS, wallMs: T0 * 1000 });
    expect(monoElapsed.state.keys.get('D1')?.confirmed).toBe(true);
  });

  it('holds a narrowed window as pending: an honest document that follows is accepted and keeps the window', () => {
    let state = confirmed({ keys: [D1] });
    const narrowed = merge(state, { keys: [{ ...D1, not_after: T0 - DAY }] }, T0 + 700);
    state = narrowed.state;
    expect(narrowed.events.map((event) => event.type)).toEqual(['window_narrowing_pending']);
    expect(state.keys.get('D1')?.notAfter).toBe(D1.not_after);
    const honest = merge(state, { keys: [D1] }, T0 + 1400);
    expect(honest.accepted).toBe(true);
    expect(honest.state.keys.get('D1')?.notAfter).toBe(D1.not_after);
    expect(honest.state.keys.get('D1')?.pendingWindow).toBeUndefined();
  });

  it('applies a narrowed window once a fetch at least five minutes later serves the same narrowing', () => {
    let state = confirmed({ keys: [D1] });
    const narrowedDoc = { keys: [{ ...D1, not_after: T0 + DAY }] };
    state = accepted(state, narrowedDoc, T0 + 700);
    state = accepted(state, narrowedDoc, T0 + 700 + SPACING - 1);
    expect(state.keys.get('D1')?.notAfter).toBe(D1.not_after);
    const applied = merge(state, narrowedDoc, T0 + 700 + SPACING);
    expect(applied.events.map((event) => event.type)).toEqual(['window_narrowing_applied']);
    expect(applied.state.keys.get('D1')?.notAfter).toBe(T0 + DAY);
    expect(applied.state.keys.get('D1')?.jwk.not_after).toBe(T0 + DAY);
  });

  it('keeps confirmation and a pending narrowing across a reload whose monotonic clock restarted', () => {
    const process1 = (seconds: number): KeySetClockReading => ({ monotonicMs: (seconds - T0) * 1000 + 7, wallMs: seconds * 1000 });
    const process2 = (seconds: number): KeySetClockReading => ({ monotonicMs: (seconds - T0 - 800) * 1000 + 3, wallMs: seconds * 1000 });
    const narrowedDoc = { keys: [{ ...D1, not_after: T0 + DAY }] };
    let state = mergeFetchedDocument(emptyKeySetState(), { keys: [D1] }, process1(T0)).state;
    state = mergeFetchedDocument(state, { keys: [D1] }, process1(T0 + SPACING)).state;
    state = mergeFetchedDocument(state, narrowedDoc, process1(T0 + 700)).state;

    const reloaded = deserializeKeySetState(serializeKeySetState(state), process2(T0 + 800));
    expect(reloaded?.keys.get('D1')?.confirmed).toBe(true);
    const early = mergeFetchedDocument(reloaded!, narrowedDoc, process2(T0 + 700 + SPACING - 1));
    expect(early.state.keys.get('D1')?.notAfter).toBe(D1.not_after);
    const onTime = mergeFetchedDocument(reloaded!, narrowedDoc, process2(T0 + 700 + SPACING));
    expect(onTime.state.keys.get('D1')?.notAfter).toBe(T0 + DAY);
  });

  it('times an unconfirmed key and a pending tombstone from their wall-clock first sighting across a reload', () => {
    const process1 = (seconds: number): KeySetClockReading => ({ monotonicMs: (seconds - T0) * 1000 + 7, wallMs: seconds * 1000 });
    const process2 = (seconds: number): KeySetClockReading => ({ monotonicMs: (seconds - T0 - 100) * 1000 + 3, wallMs: seconds * 1000 });
    const doc = { keys: [D1], proof_tombstones: [{ kid: 'R1', revoked_at: T0 }] };
    const state = mergeFetchedDocument(emptyKeySetState(), doc, process1(T0)).state;

    const reloaded = deserializeKeySetState(serializeKeySetState(state), process2(T0 + 100));
    const early = mergeFetchedDocument(reloaded!, doc, process2(T0 + SPACING - 1)).state;
    expect(early.keys.get('D1')?.confirmed).toBe(false);
    expect(early.applied.has('R1')).toBe(false);
    const onTime = mergeFetchedDocument(reloaded!, doc, process2(T0 + SPACING)).state;
    expect(onTime.keys.get('D1')?.confirmed).toBe(true);
    expect(onTime.applied.has('R1')).toBe(true);
  });
});

describe('mergeFetchedDocument', () => {
  it('records the fetch time on both clocks', () => {
    const state = accepted(emptyKeySetState(), { keys: [D1] }, T0);
    expect(state.fetchedAt).toEqual(at(T0));
  });

  it('keeps tolerant-mode replace semantics: an absent member-less key is dropped', () => {
    let state = accepted(emptyKeySetState(), { keys: [T1] }, T0);
    state = accepted(state, { keys: [] }, T0 + 700);
    expect(state.keys.has('T1')).toBe(false);
  });

  it('keeps tolerant-mode replace semantics for key material: a re-keyed tolerant kid is adopted, as before', () => {
    let state = accepted(emptyKeySetState(), { keys: [T1] }, T0);
    const result = merge(state, { keys: [{ ...T1, x: 'rotated' }] }, T0 + 700);
    state = result.state;
    expect(state.keys.get('T1')?.jwk.x).toBe('rotated');
    expect(result.events).toEqual([]);
  });

  describe('a key carrying window members but neither proof_purpose nor proof_legacy is NOT a registry key', () => {
    const W1 = ecJwk('W1', 'w1', { not_before: T0 - DAY, not_after: T0 + DAY, max_token_lifetime: DAY });

    it('is re-keyed like a tolerant key', () => {
      let state = accepted(emptyKeySetState(), { keys: [D1, W1] }, T0);
      const result = merge(state, { keys: [D1, { ...W1, x: 'rotated' }] }, T0 + 700);
      state = result.state;
      expect(state.keys.get('W1')?.jwk.x).toBe('rotated');
      expect(result.events).toEqual([]);
    });

    it('is dropped when absent, like a tolerant key', () => {
      let state = accepted(emptyKeySetState(), { keys: [D1, W1] }, T0);
      const result = merge(state, { keys: [D1] }, T0 + 700);
      state = result.state;
      expect(state.keys.has('W1')).toBe(false);
      expect(result.events).toEqual([]);
    });

    it('does not make a widened window refuse the whole document', () => {
      const state = accepted(emptyKeySetState(), { keys: [D1, W1] }, T0);
      expect(merge(state, { keys: [D1, { ...W1, not_after: T0 + 2 * DAY }] }, T0 + 700).accepted).toBe(true);
    });
  });

  it('keeps a vanished registry kid with its last-known state and reports it once', () => {
    let state = confirmed({ keys: [D1, R1] });
    const result = merge(state, { keys: [D1] }, T0 + 700);
    expect(result.accepted).toBe(true);
    state = result.state;
    expect(state.keys.get('R1')?.vanished).toBe(true);
    expect(result.events.map((event) => event.type)).toEqual(['kid_vanished']);
    const again = merge(state, { keys: [D1] }, T0 + 1400);
    expect(again.events).toEqual([]);
  });

  it('prunes a vanished registry kid once tokens it signed can no longer be alive', () => {
    let state = confirmed({ keys: [D1, R1] });
    const retentionEnd = (R1.not_after as number) + (R1.max_token_lifetime as number) + KEY_WINDOW_SKEW_SECONDS;
    state = accepted(state, { keys: [D1] }, retentionEnd);
    expect(state.keys.has('R1')).toBe(true);
    state = accepted(state, { keys: [D1] }, retentionEnd + 1);
    expect(state.keys.has('R1')).toBe(false);
  });

  it('never replaces the key material of a confirmed kid, and says so', () => {
    let state = confirmed({ keys: [D1] });
    const rekeyed = { ...D1, x: 'attacker' };
    const result = merge(state, { keys: [rekeyed] }, T0 + 700);
    state = result.state;
    expect(state.keys.get('D1')?.jwk.x).toBe('d1');
    expect(result.events.map((event) => event.type)).toEqual(['key_material_changed']);
  });

  it('a reappearing kid is not new: it keeps its first-seen record', () => {
    let state = confirmed({ keys: [D1, R1] });
    state = accepted(state, { keys: [D1] }, T0 + 700);
    state = accepted(state, { keys: [D1, { ...R1, x: 'other' }] }, T0 + 1400);
    expect(state.keys.get('R1')?.jwk.x).toBe('r1');
    expect(state.keys.get('R1')?.vanished).toBe(false);
  });

  it('rejects the WHOLE document when a confirmed window is widened', () => {
    const state = confirmed({ keys: [D1] });
    const NEW = registryJwk('NEW', 'new', 'delegation', { nb: T0, na: T0 + DAY });
    for (const widened of [
      { ...D1, not_before: (D1.not_before as number) - 1 },
      { ...D1, not_after: (D1.not_after as number) + 1 },
    ]) {
      const result = merge(state, { keys: [widened, NEW] }, T0 + 700);
      expect(result.accepted).toBe(false);
      expect(result.state.keys.has('NEW')).toBe(false);
      expect(result.state.fetchedAt).toEqual(at(T0 + SPACING));
      expect(result.events.map((event) => event.type)).toEqual(['window_widening_rejected']);
    }
  });

  it('rejects the WHOLE document when a confirmed window is widened under different key material', () => {
    const state = confirmed({ keys: [D1] });
    const widenedRekeyed = { ...D1, x: 'attacker', not_after: (D1.not_after as number) + 1 };
    const result = merge(state, { keys: [widenedRekeyed], proof_tombstones: [{ kid: 'D1', revoked_at: T0 }] }, T0 + 700);
    expect(result.accepted).toBe(false);
    expect(result.state.pending.size).toBe(0);
    expect(result.state.fetchedAt).toEqual(at(T0 + SPACING));
    expect(result.events.map((event) => event.type)).toEqual(['window_widening_rejected']);
  });

  it('adopts registry metadata for a kid first seen in tolerant mode', () => {
    let state = accepted(emptyKeySetState(), { keys: [ecJwk('D1', 'd1')] }, T0);
    state = accepted(state, { keys: [D1] }, T0 + 700);
    expect(state.keys.get('D1')?.purpose).toBe('delegation');
  });
});

describe('tombstones', () => {
  const tombstoneR1 = { kid: 'R1', revoked_at: T0 + 100 };

  function withPending(): KeySetState {
    const state = confirmed({ keys: [D1, R1] });
    return accepted(state, { keys: [D1], proof_tombstones: [tombstoneR1] }, T0 + 700);
  }

  it('is pending, not applied, at first sight', () => {
    const state = withPending();
    expect(state.pending.has('R1')).toBe(true);
    expect(state.applied.has('R1')).toBe(false);
    expect(selectKeys(state, 'R1', 'delegation').kind).toBe('candidates');
  });

  it('stays pending on a second fetch under five minutes', () => {
    const state = accepted(withPending(), { keys: [D1], proof_tombstones: [tombstoneR1] }, T0 + 700 + 299);
    expect(state.applied.has('R1')).toBe(false);
  });

  it('is applied on a second fetch five minutes or more after first sight', () => {
    const result = merge(withPending(), { keys: [D1], proof_tombstones: [tombstoneR1] }, T0 + 700 + CONFIRM_SPACING_MS / 1000);
    expect(result.state.applied.get('R1')).toEqual({ kid: 'R1', revokedAt: T0 + 100 });
    expect(result.events.map((event) => event.type)).toContain('tombstone_applied');
    expect(selectKeys(result.state, 'R1', 'delegation').kind).toBe('revoked');
  });

  it('times confirmation on the monotonic clock, not the wall clock', () => {
    const doc = { keys: [D1], proof_tombstones: [tombstoneR1] };
    const first = mergeFetchedDocument(emptyKeySetState(), doc, { monotonicMs: 5_000, wallMs: T0 * 1000 });
    const wallJumped = mergeFetchedDocument(first.state, doc, { monotonicMs: 65_000, wallMs: (T0 + 3600) * 1000 });
    expect(wallJumped.state.applied.has('R1')).toBe(false);
    const monoElapsed = mergeFetchedDocument(first.state, doc, { monotonicMs: 5_000 + CONFIRM_SPACING_MS, wallMs: T0 * 1000 });
    expect(monoElapsed.state.applied.has('R1')).toBe(true);
  });

  it('is discarded by a fetch that no longer carries it', () => {
    let state = accepted(withPending(), { keys: [D1] }, T0 + 800);
    state = accepted(state, { keys: [D1], proof_tombstones: [tombstoneR1] }, T0 + 1100);
    expect(state.applied.has('R1')).toBe(false);
    expect(state.pending.get('R1')?.firstSeen.monotonicMs).toBe((T0 + 1100) * 1000);
  });

  it('is sticky once applied, until revoked_at + 365d', () => {
    let state = merge(withPending(), { keys: [D1], proof_tombstones: [tombstoneR1] }, T0 + 1000).state;
    state = accepted(state, { keys: [D1, R1] }, T0 + 1700);
    expect(selectKeys(state, 'R1', 'delegation').kind).toBe('revoked');
    state = accepted(state, { keys: [D1] }, T0 + 100 + TOMBSTONE_RETENTION_SECONDS);
    expect(state.applied.has('R1')).toBe(true);
    state = accepted(state, { keys: [D1] }, T0 + 100 + TOMBSTONE_RETENTION_SECONDS + 1);
    expect(state.applied.has('R1')).toBe(false);
  });

  it('flags a tombstone for a live kid as an anomaly at first sight, and applies it by the same rule', () => {
    let state = confirmed({ keys: [D1] });
    const first = merge(state, { keys: [], proof_tombstones: [{ kid: 'D1', revoked_at: T0 }] }, T0 + 700);
    expect(first.events.map((event) => event.type)).toEqual(['tombstone_pending', 'tombstone_for_live_key']);
    state = first.state;
    expect(selectKeys(state, 'D1', 'delegation').kind).toBe('candidates');
    state = accepted(state, { keys: [], proof_tombstones: [{ kid: 'D1', revoked_at: T0 }] }, T0 + 1000);
    expect(selectKeys(state, 'D1', 'delegation').kind).toBe('revoked');
  });

  it('flags it from what was known before the document, even when the same document drops the key', () => {
    const state = accepted(emptyKeySetState(), { keys: [D1] }, T0);
    const result = merge(state, { keys: [], proof_tombstones: [{ kid: 'D1', revoked_at: T0 }] }, T0 + 700);
    expect(result.state.keys.has('D1')).toBe(false);
    expect(result.events.map((event) => event.type)).toEqual(['tombstone_pending', 'tombstone_for_live_key']);
  });

  it('does not flag a tombstone for a retired kid', () => {
    const state = accepted(emptyKeySetState(), { keys: [D1, R1] }, T0);
    const result = merge(state, { keys: [D1], proof_tombstones: [tombstoneR1] }, T0 + 700);
    expect(result.events.map((event) => event.type)).not.toContain('tombstone_for_live_key');
  });

  it('ignores malformed tombstone entries', () => {
    const state = accepted(emptyKeySetState(), { keys: [D1], proof_tombstones: [{ kid: 'X' }, 'junk', { kid: 'Y', revoked_at: 1.5 }] }, T0);
    expect(state.pending.size).toBe(0);
  });
});

describe('selectKeys', () => {
  const live = accepted(emptyKeySetState(), { keys: [D1, P1, L1, ecJwk('U1', 'u1'), ecJwk(undefined, 'anon')] }, T0);

  it('detects registry live from any proof_purpose member', () => {
    expect(isRegistryLive(live)).toBe(true);
    expect(isRegistryLive(accepted(emptyKeySetState(), { keys: [T1] }, T0))).toBe(false);
  });

  it('rejects a kid of the wrong family', () => {
    expect(selectKeys(live, 'P1', 'delegation').kind).toBe('wrong_purpose');
    expect(selectKeys(live, 'D1', 'delegation').kind).toBe('candidates');
  });

  it('lets a legacy key match any family', () => {
    for (const family of ['proof', 'delegation', 'status-list'] as const) {
      expect(selectKeys(live, 'L1', family).kind).toBe('candidates');
    }
  });

  it('rejects a key without proof_purpose once the registry is live', () => {
    expect(selectKeys(live, 'U1', 'delegation').kind).toBe('wrong_purpose');
  });

  it('maps a no-kid token to the legacy key only once the registry is live', () => {
    const selection = selectKeys(live, undefined, 'delegation');
    expect(selection.kind === 'candidates' && selection.records.map((record) => record.kid)).toEqual(['L1']);
  });

  it('finds no candidate for a no-kid token when no key is legacy', () => {
    const state = accepted(emptyKeySetState(), { keys: [D1] }, T0);
    expect(selectKeys(state, undefined, 'delegation').kind).toBe('unknown');
  });

  it('tries every key for a no-kid token in tolerant mode, exactly as before', () => {
    const tolerant = accepted(emptyKeySetState(), { keys: [T1, ecJwk(undefined, 'anon')] }, T0);
    const selection = selectKeys(tolerant, undefined, 'delegation');
    expect(selection.kind === 'candidates' && selection.records.map((record) => record.jwk.x)).toEqual(['anon', 't1']);
  });

  it('reports an unknown kid', () => {
    expect(selectKeys(live, 'NOPE', 'delegation').kind).toBe('unknown');
  });
});

describe('checkKeyPolicy', () => {
  const live = accepted(emptyKeySetState(), { keys: [D1, L1, registryJwk('BAD', 'bad', 'delegation', { nb: T0, na: T0 })] }, T0);
  const d1 = live.keys.get('D1')!;
  const nb = D1.not_before as number;
  const na = D1.not_after as number;

  it('accepts iat inside the window with five minutes of skew either side', () => {
    expect(checkKeyPolicy(d1, { iat: nb - 240, exp: nb + DAY }, true)).toBeNull();
    expect(checkKeyPolicy(d1, { iat: na + 240, exp: na + DAY }, true)).toBeNull();
    expect(checkKeyPolicy(d1, { iat: nb - KEY_WINDOW_SKEW_SECONDS, exp: nb + DAY }, true)).toBeNull();
  });

  it('rejects iat outside the window beyond the skew', () => {
    expect(checkKeyPolicy(d1, { iat: nb - 360, exp: nb + DAY }, true)).toBe('outside_key_window');
    expect(checkKeyPolicy(d1, { iat: na + 360, exp: na + DAY }, true)).toBe('outside_key_window');
  });

  it('rejects exp beyond iat + max_token_lifetime', () => {
    expect(checkKeyPolicy(d1, { iat: T0, exp: T0 + 365 * DAY }, true)).toBeNull();
    expect(checkKeyPolicy(d1, { iat: T0, exp: T0 + 365 * DAY + 1 }, true)).toBe('token_lifetime_exceeded');
  });

  it('skips window and lifetime for a legacy key', () => {
    expect(checkKeyPolicy(live.keys.get('L1')!, { iat: 1, exp: T0 * 2 }, true)).toBeNull();
  });

  it('skips window and lifetime in tolerant mode', () => {
    const tolerant = accepted(emptyKeySetState(), { keys: [T1] }, T0);
    expect(checkKeyPolicy(tolerant.keys.get('T1')!, { iat: 1, exp: T0 * 2 }, false)).toBeNull();
  });

  it('treats a missing or non-integer iat as outside the window', () => {
    expect(checkKeyPolicy(d1, { iat: undefined, exp: T0 }, true)).toBe('outside_key_window');
    expect(checkKeyPolicy(d1, { iat: T0 + 0.5, exp: T0 + DAY }, true)).toBe('outside_key_window');
  });

  it('treats a registry key with unusable window members as outside its window', () => {
    const broken = accepted(emptyKeySetState(), { keys: [{ ...D1, not_after: 'soon' }] }, T0).keys.get('D1')!;
    expect(checkKeyPolicy(broken, { iat: T0, exp: T0 + DAY }, true)).toBe('outside_key_window');
  });
});
