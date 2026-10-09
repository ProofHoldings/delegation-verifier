/**
 * Key-rotation behaviour of the I/O shell that the shared fixtures cannot express: option
 * validation, persistence edge cases, store failures, the manual tombstone reset, and the
 * status-list key held to its own family.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  clearTombstones,
  getJwksDiagnostics,
  MAX_JWKS_AGE_CAP_MS,
  refreshJwks,
  resetJwksCache,
  setJwksClockForTests,
} from '../jwks.js';
import { serializeKeySetState, emptyKeySetState, mergeFetchedDocument } from '../keyset.js';
import { verifyDelegation } from '../verify.js';
import type { KeySetStore, TrustedIssuer, VerifyOptions } from '../types.js';
import {
  delegationClaims,
  expectFailure,
  generateKey,
  ISSUER,
  JWKS_URI,
  mockFetch,
  signJwt,
  signStatusList,
  STATUS_ENDPOINT,
  STATUS_LIST_URI,
  type TestKey,
} from './helpers.js';

const DAY = 86_400;
const trustedIssuer: TrustedIssuer = { issuer: ISSUER, jwksUri: JWKS_URI, statusEndpoint: STATUS_ENDPOINT };
const RESOLVED_DELEGATE = { type: 'purl', value: 'pkg:npm/postmark-mcp' } as const;

let nowSeconds = 0;

function options(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return { trustedIssuers: [trustedIssuer], delegate: RESOLVED_DELEGATE, statusCheck: 'skip', ...overrides };
}

function registryJwk(key: TestKey, purpose: string): JsonWebKey & Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    ...key.publicJwk,
    proof_purpose: purpose,
    not_before: now - 30 * DAY,
    not_after: now + 30 * DAY,
    max_token_lifetime: purpose === 'status-list' ? DAY : 365 * DAY,
  };
}

function memoryStore(): KeySetStore & { saved: Map<string, string> } {
  const saved = new Map<string, string>();
  return {
    saved,
    load: (jwksUri) => saved.get(jwksUri) ?? null,
    save: (jwksUri, state) => {
      saved.set(jwksUri, state);
    },
  };
}

let key: TestKey;

beforeEach(async () => {
  resetJwksCache();
  nowSeconds = Math.floor(Date.now() / 1000);
  setJwksClockForTests({ monotonicMs: () => nowSeconds * 1000, wallMs: () => nowSeconds * 1000 });
  key = await generateKey();
});

afterEach(() => {
  setJwksClockForTests(null);
  resetJwksCache();
});

describe('maxJwksAgeMs is validated at the call boundary (SC-6)', () => {
  it('accepts exactly 25 days and refuses a millisecond more, without any network call', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [key.publicJwk] } } });

    expect((await verifyDelegation(token, options({ fetch: net.fetch, maxJwksAgeMs: MAX_JWKS_AGE_CAP_MS }))).valid).toBe(true);
    expect(MAX_JWKS_AGE_CAP_MS).toBe(25 * DAY * 1000);

    const before = net.calls.length;
    for (const bad of [MAX_JWKS_AGE_CAP_MS + 1, 0, -1, 1.5, Number.NaN, '3600000' as unknown as number]) {
      const result = await verifyDelegation(token, options({ fetch: net.fetch, maxJwksAgeMs: bad }));
      expectFailure(result);
      expect(result.reason).toBe('invalid_options');
    }
    expect(net.calls.length).toBe(before);
  });

  it('refuses a keySetStore without load/save and a non-function onJwksEvent', async () => {
    const token = await signJwt(delegationClaims(), key);
    for (const overrides of [
      { keySetStore: {} as KeySetStore },
      { keySetStore: { load: () => null } as unknown as KeySetStore },
      { onJwksEvent: 'log' as unknown as VerifyOptions['onJwksEvent'] },
    ]) {
      const result = await verifyDelegation(token, options(overrides));
      expectFailure(result);
      expect(result.reason).toBe('invalid_options');
    }
  });
});

describe('a set that was never fetched keeps today’s failure behaviour (D9)', () => {
  it('retries on every call and answers jwks_unavailable, never jwks_stale', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: { status: 503 } });
    for (let attempt = 1; attempt <= 3; attempt++) {
      const result = await verifyDelegation(token, options({ fetch: net.fetch }));
      expectFailure(result);
      expect(result.reason).toBe('jwks_unavailable');
      expect(net.calls.length).toBe(attempt);
    }
  });
});

describe('persistence (SC-4, SC-6)', () => {
  it('treats a persisted fetched_at in the future as stale: a failed refetch answers jwks_stale with unknown age', async () => {
    const store = memoryStore();
    const future = (nowSeconds + 3600) * 1000;
    const merged = mergeFetchedDocument(emptyKeySetState(), { keys: [key.publicJwk] }, { monotonicMs: future, wallMs: future });
    store.saved.set(JWKS_URI, serializeKeySetState(merged.state));

    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: { status: 503 } });
    const result = await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }));
    expectFailure(result);
    expect(result.reason).toBe('jwks_stale');
    expect(result.cacheAgeSeconds).toBeNull();
    expect(net.calls).toEqual([JWKS_URI]);
  });

  it('serves a persisted set younger than the TTL without a network call', async () => {
    const store = memoryStore();
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [key.publicJwk] } } });
    const token = await signJwt(delegationClaims(), key);
    expect((await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }))).valid).toBe(true);

    resetJwksCache();
    nowSeconds += 60;
    expect((await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }))).valid).toBe(true);
    expect(net.calls.length).toBe(1);
  });

  it('ignores a store that throws, and reports it as an event', async () => {
    const events: string[] = [];
    const broken: KeySetStore = {
      load: () => {
        throw new Error('disk on fire');
      },
      save: async () => {
        throw new Error('disk on fire');
      },
    };
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [key.publicJwk] } } });
    const token = await signJwt(delegationClaims(), key);
    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, keySetStore: broken, onJwksEvent: (event) => events.push(event.type) })
    );
    expect(result.valid).toBe(true);
    expect(events).toEqual(['store_error', 'store_error']);
  });

  it('ignores a persisted blob that is not a key set, and reports it as an event', async () => {
    const store = memoryStore();
    store.saved.set(JWKS_URI, 'not json');
    const events: string[] = [];
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [key.publicJwk] } } });
    const token = await signJwt(delegationClaims(), key);
    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, keySetStore: store, onJwksEvent: (event) => events.push(event.type) })
    );
    expect(result.valid).toBe(true);
    expect(events).toEqual(['store_error']);
  });
});

describe('clearTombstones (SC-4)', () => {
  async function revokedSet(store: KeySetStore) {
    const tombstoned = { keys: [], proof_tombstones: [{ kid: key.kid, revoked_at: nowSeconds }] };
    const routes = { [JWKS_URI]: { json: { keys: [registryJwk(key, 'delegation')] } } as { json: unknown } };
    const net = mockFetch(routes);
    const token = await signJwt(delegationClaims(), key, { alg: 'RS256' });
    expect((await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }))).valid).toBe(true);
    nowSeconds += 300;
    await refreshJwks({ jwksUri: JWKS_URI, fetch: net.fetch, keySetStore: store });
    routes[JWKS_URI] = { json: tombstoned };
    await refreshJwks({ jwksUri: JWKS_URI, fetch: net.fetch, keySetStore: store });
    nowSeconds += 300;
    await refreshJwks({ jwksUri: JWKS_URI, fetch: net.fetch, keySetStore: store });
    const result = await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }));
    expectFailure(result);
    expect(result.reason).toBe('key_revoked');
    return { token, net };
  }

  it('drops the applied tombstone in memory and in the store', async () => {
    const store = memoryStore();
    const { token, net } = await revokedSet(store);
    expect(getJwksDiagnostics(JWKS_URI)?.appliedTombstones.map((entry) => entry.kid)).toEqual([key.kid]);

    await clearTombstones({ jwksUri: JWKS_URI, keySetStore: store });
    expect(getJwksDiagnostics(JWKS_URI)?.appliedTombstones).toEqual([]);
    resetJwksCache();
    const after = await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }));
    expect(after.valid ? 'valid' : after.reason).toBe('valid');
  });

  it('keeps a persisted tombstone when the first call in a process came without the store', async () => {
    const store = memoryStore();
    const { token } = await revokedSet(store);
    resetJwksCache();
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [registryJwk(key, 'delegation')] } } });
    await refreshJwks({ jwksUri: JWKS_URI, fetch: net.fetch });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }));
    expectFailure(result);
    expect(result.reason).toBe('key_revoked');
    nowSeconds += 700;
    await refreshJwks({ jwksUri: JWKS_URI, fetch: net.fetch, keySetStore: store });
    expect(JSON.parse(store.saved.get(JWKS_URI) as string).applied.map((entry: { kid: string }) => entry.kid)).toEqual([key.kid]);
  });

  it('does not overwrite persisted tombstones after a load that timed out', async () => {
    const store = memoryStore();
    const { token } = await revokedSet(store);
    resetJwksCache();
    const slow: KeySetStore = {
      load: (jwksUri) => new Promise((resolve) => setTimeout(() => resolve(store.load(jwksUri)), 200)),
      save: store.save,
    };
    nowSeconds += 700;
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [registryJwk(key, 'delegation')] } } });
    await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: slow, timeoutMs: 50 }));
    expect(JSON.parse(store.saved.get(JWKS_URI) as string).applied.map((entry: { kid: string }) => entry.kid)).toEqual([key.kid]);
  });

  it('answers key_revoked, not jwks_stale, for an applied tombstone when the issuer is unreachable', async () => {
    const { token } = await revokedSet(memoryStore());
    nowSeconds += 2 * DAY;
    const result = await verifyDelegation(token, options({ fetch: mockFetch({ [JWKS_URI]: { status: 503 } }).fetch }));
    expectFailure(result);
    expect(result.reason).toBe('key_revoked');
  });

  it('nothing but clearTombstones lifts it: a later document without the tombstone keeps it', async () => {
    const store = memoryStore();
    const { token } = await revokedSet(store);
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [registryJwk(key, 'delegation')] } } });
    await refreshJwks({ jwksUri: JWKS_URI, fetch: net.fetch, keySetStore: store });
    const result = await verifyDelegation(token, options({ fetch: net.fetch, keySetStore: store }));
    expectFailure(result);
    expect(result.reason).toBe('key_revoked');
  });
});

describe('clocks (SC-6): age is monotonic in-process, wall-clock only on disk', () => {
  it('neither refetches nor goes stale when only the wall clock jumps', async () => {
    let mono = 1_000;
    let wall = nowSeconds * 1000;
    setJwksClockForTests({ monotonicMs: () => mono, wallMs: () => wall });
    const routes = { [JWKS_URI]: { json: { keys: [key.publicJwk] } } as { json?: unknown; status?: number } };
    const net = mockFetch(routes);
    const token = await signJwt(delegationClaims(), key);
    expect((await verifyDelegation(token, options({ fetch: net.fetch }))).valid).toBe(true);

    routes[JWKS_URI] = { status: 503 };
    wall += 2 * DAY * 1000;
    mono += 60_000;
    expect((await verifyDelegation(token, options({ fetch: net.fetch }))).valid).toBe(true);
    expect(net.calls).toHaveLength(1);
  });

  it('keeps the age right across a restart whose monotonic clock starts over', async () => {
    let mono = 9_000_000_000;
    let wall = nowSeconds * 1000;
    setJwksClockForTests({ monotonicMs: () => mono, wallMs: () => wall });
    const store = memoryStore();
    const token = await signJwt(delegationClaims(), key);
    const up = mockFetch({ [JWKS_URI]: { json: { keys: [key.publicJwk] } } });
    expect((await verifyDelegation(token, options({ fetch: up.fetch, keySetStore: store }))).valid).toBe(true);
    mono += 300_000;
    wall += 300_000;
    await refreshJwks({ jwksUri: JWKS_URI, fetch: up.fetch, keySetStore: store });

    resetJwksCache();
    mono = 5;
    wall += 2 * 3_600_000;
    const down = mockFetch({ [JWKS_URI]: { status: 503 } });
    expect((await verifyDelegation(token, options({ fetch: down.fetch, keySetStore: store }))).valid).toBe(true);

    mono += 23 * 3_600_000;
    wall += 23 * 3_600_000;
    const result = await verifyDelegation(token, options({ fetch: down.fetch, keySetStore: store }));
    expectFailure(result);
    expect(result.reason).toBe('jwks_stale');
    expect(result.cacheAgeSeconds).toBe(25 * 3_600);
  });
});

describe('key usage', () => {
  it('never verifies with a key the JWKS marks for anything but signatures', async () => {
    const token = await signJwt(delegationClaims(), key);
    for (const members of [{ use: 'enc' }, { key_ops: ['encrypt'] }]) {
      resetJwksCache();
      const net = mockFetch({ [JWKS_URI]: { json: { keys: [{ ...key.publicJwk, ...members }] } } });
      const result = await verifyDelegation(token, options({ fetch: net.fetch }));
      expectFailure(result);
      expect(result.reason).toBe('unknown_key');
    }
    resetJwksCache();
    const control = mockFetch({ [JWKS_URI]: { json: { keys: [{ ...key.publicJwk, use: 'sig', key_ops: ['verify'] }] } } });
    expect((await verifyDelegation(token, options({ fetch: control.fetch }))).valid).toBe(true);
  });

  it('refuses it even when the same material was already imported under a signing kid', async () => {
    const encKid = 'same-material-for-encryption';
    const net = mockFetch({
      [JWKS_URI]: { json: { keys: [key.publicJwk, { ...key.publicJwk, kid: encKid, use: 'enc' }] } },
    });
    expect((await verifyDelegation(await signJwt(delegationClaims(), key), options({ fetch: net.fetch }))).valid).toBe(true);
    const viaEncKid = await signJwt(delegationClaims(), { ...key, kid: encKid });
    expect((await verifyDelegation(viaEncKid, options({ fetch: net.fetch }))).valid).toBe(false);
  });
});

describe('a no-kid token after a failed refetch', () => {
  it('answers jwks_unavailable, not bad_signature, when the key that may have signed it is unconfirmed', async () => {
    const anonymous = await generateKey('anonymous');
    const { kid: _omitted, ...anonymousJwk } = anonymous.publicJwk as JsonWebKey & { kid?: string };
    const routes = { [JWKS_URI]: { json: { keys: [anonymousJwk, key.publicJwk] } } as { json?: unknown; status?: number } };
    const net = mockFetch(routes);
    const token = await signJwt(delegationClaims(), anonymous, { kid: undefined });
    expect((await verifyDelegation(token, options({ fetch: net.fetch }))).valid).toBe(true);
    nowSeconds += 300;
    await refreshJwks({ jwksUri: JWKS_URI, fetch: net.fetch });

    routes[JWKS_URI] = { status: 503 };
    nowSeconds += 3_600;
    const result = await verifyDelegation(token, options({ fetch: net.fetch }));
    expectFailure(result);
    expect(result.reason).toBe('jwks_unavailable');
  });
});

describe('a hung keySetStore', () => {
  it('is bounded by timeoutMs on load and on save, and reported as a store error', async () => {
    const events: string[] = [];
    const hung: KeySetStore = { load: () => new Promise(() => {}), save: () => new Promise(() => {}) };
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [key.publicJwk] } } });
    const token = await signJwt(delegationClaims(), key);
    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, keySetStore: hung, timeoutMs: 50, onJwksEvent: (event) => events.push(event.type) })
    );
    expect(result.valid).toBe(true);
    expect(events).toEqual(['store_error', 'store_error']);
  });
});

describe('an unknown kid inside the miss cooldown', () => {
  it('answers jwks_unavailable — it may be a key published since the last refetch — not unknown_key', async () => {
    const fresh = await generateKey('published-a-moment-ago');
    const routes = { [JWKS_URI]: { json: { keys: [key.publicJwk] } } as { json: unknown } };
    const net = mockFetch(routes);
    const first = await verifyDelegation(await signJwt(delegationClaims(), fresh), options({ fetch: net.fetch }));
    expectFailure(first);
    expect(first.reason).toBe('unknown_key');

    routes[JWKS_URI] = { json: { keys: [key.publicJwk, fresh.publicJwk] } };
    nowSeconds += 6;
    const second = await verifyDelegation(await signJwt(delegationClaims(), fresh), options({ fetch: net.fetch }));
    expectFailure(second);
    expect(second.reason).toBe('jwks_unavailable');
    expect(net.calls).toHaveLength(1);
  });
});

describe('events', () => {
  it('a throwing listener does not change the verdict', async () => {
    const other = await generateKey('other-key');
    const net = mockFetch({ [JWKS_URI]: { json: { keys: [registryJwk(key, 'delegation')], proof_tombstones: [{ kid: other.kid, revoked_at: nowSeconds }] } } });
    const token = await signJwt(delegationClaims(), key);
    const result = await verifyDelegation(
      token,
      options({
        fetch: net.fetch,
        onJwksEvent: () => {
          throw new Error('listener bug');
        },
      })
    );
    expect(result.valid).toBe(true);
  });
});

describe('status-list key policy (D13)', () => {
  it('refuses a status list signed by a delegation-family key and falls through to the endpoint', async () => {
    const statusKey = await generateKey('dlg-key-signing-list');
    const net = mockFetch({
      [JWKS_URI]: { json: { keys: [registryJwk(key, 'delegation'), registryJwk(statusKey, 'delegation')] } },
      [STATUS_LIST_URI]: await signStatusList(statusKey, { 0: 0 }),
      [STATUS_ENDPOINT]: { status: 503 },
    });
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 0, uri: STATUS_LIST_URI } } }), key);
    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'required' }));
    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('accepts a status list signed by a status-list key (positive control)', async () => {
    const statusKey = await generateKey('sts-key');
    const net = mockFetch({
      [JWKS_URI]: { json: { keys: [registryJwk(key, 'delegation'), registryJwk(statusKey, 'status-list')] } },
      [STATUS_LIST_URI]: await signStatusList(statusKey, { 0: 0 }),
    });
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 0, uri: STATUS_LIST_URI } } }), key);
    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'required' }));
    expect(result.valid).toBe(true);
    expect(net.calls).not.toContain(STATUS_ENDPOINT);
  });
});
