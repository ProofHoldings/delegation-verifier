import { existsSync, readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it } from 'vitest';
import { verifyDelegation } from '../verify.js';
import { resetJwksCache } from '../jwks.js';
import type { TrustedIssuer, VerifyOptions } from '../types.js';
import {
  delegationClaims,
  expectFailure,
  generateKey,
  ISSUER,
  jwksBody,
  JWKS_URI,
  mockFetch,
  signJwt,
  signStatusList,
  STATUS_ENDPOINT,
  STATUS_LIST_URI,
  unsignedJwt,
  type TestKey,
} from './helpers.js';

const trustedIssuer: TrustedIssuer = {
  issuer: ISSUER,
  jwksUri: JWKS_URI,
  statusEndpoint: STATUS_ENDPOINT,
};

const RESOLVED_DELEGATE = { type: 'purl', value: 'pkg:npm/postmark-mcp' } as const;

let key: TestKey;

beforeEach(async () => {
  resetJwksCache();
  key = await generateKey();
});

function options(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return {
    trustedIssuers: [trustedIssuer],
    delegate: RESOLVED_DELEGATE,
    ...overrides,
  };
}

describe('trust policy (SC-2)', () => {
  it('refuses with no_trust_policy when trustedIssuers is empty, without any network call', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({});

    const result = await verifyDelegation(token, options({ trustedIssuers: [], fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('no_trust_policy');
    expect(net.calls).toEqual([]);
  });

  it('refuses an issuer outside the policy, without any network call', async () => {
    const token = await signJwt(delegationClaims({ iss: 'evil.example' }), key);
    const net = mockFetch({});

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('untrusted_issuer');
    expect(net.calls).toEqual([]);
  });

  it('ignores a trust entry whose jwksUri is not https', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({});

    const result = await verifyDelegation(
      token,
      options({ trustedIssuers: [{ issuer: ISSUER, jwksUri: 'http://issuer.test/jwks' }], fetch: net.fetch })
    );

    expectFailure(result);
    expect(result.reason).toBe('no_trust_policy');
    expect(net.calls).toEqual([]);
  });
});

describe('signature (SC-3)', () => {
  it('accepts a genuine token when status checks are skipped', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expect(result).toMatchObject({ valid: true, statusChecked: false });
    if (result.valid) {
      expect(result.delegation.principal).toBe('postmarkapp.com');
      expect(result.delegation.delegate).toBe('pkg:npm/postmark-mcp');
      expect(result.delegation.controlProof).toBe('ph_ctl_00000000000000000000000000000002');
    }
  });

  it('rejects alg: none before fetching any key', async () => {
    const token = unsignedJwt(delegationClaims());
    const net = mockFetch({});

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('unsupported_algorithm');
    expect(net.calls).toEqual([]);
  });

  it('rejects an HS256 token — the algorithm comes from the verifier, not the token', async () => {
    const token = unsignedJwt(delegationClaims(), 'HS256');
    const net = mockFetch({});

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('unsupported_algorithm');
    expect(net.calls).toEqual([]);
  });

  it('rejects a token signed by a different key of the same shape', async () => {
    const attacker = await generateKey('test-key-1'); // same kid, different key material
    const token = await signJwt(delegationClaims(), attacker);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('bad_signature');
  });

  it('reports unknown_key for a kid absent from the issuer JWKS', async () => {
    const other = await generateKey('rotated-away');
    const token = await signJwt(delegationClaims(), other);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('unknown_key');
  });

  it('distinguishes an unreachable JWKS from a bad token', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({
      [JWKS_URI]: () => {
        throw new Error('connection refused');
      },
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('jwks_unavailable');
  });

  it('rejects a tampered payload', async () => {
    const token = await signJwt(delegationClaims(), key);
    const [header, , signature] = token.split('.');
    const forgedPayload = btoa(JSON.stringify(delegationClaims({ principal: 'attacker.example' })))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      `${header}.${forgedPayload}.${signature}`,
      options({ fetch: net.fetch, statusCheck: 'skip', expectedPrincipal: 'attacker.example' })
    );

    expectFailure(result);
    expect(result.reason).toBe('bad_signature');
  });
});

describe('claims (SC-4)', () => {
  it('rejects a non-delegation token', async () => {
    const token = await signJwt(delegationClaims({ token_type: undefined }), key);
    const result = await verifyDelegation(token, options({ fetch: mockFetch({}).fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('not_a_delegation');
  });

  it('rejects a schema-1.x token, scope and all, as unsupported_version before any fetch', async () => {
    const token = await signJwt(delegationClaims({ delegation_schema_version: '1.0', scope: ['send-email'] }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('unsupported_version');
    expect(net.calls).toEqual([]);
  });

  it('rejects a later schema major as unsupported_version', async () => {
    const token = await signJwt(delegationClaims({ delegation_schema_version: '3.0' }), key);
    const result = await verifyDelegation(token, options({ fetch: mockFetch({}).fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('unsupported_version');
  });

  it('accepts a later minor of the same major', async () => {
    const token = await signJwt(delegationClaims({ delegation_schema_version: '2.4' }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expect(result.valid).toBe(true);
  });

  it('rejects an expired delegation without any network call', async () => {
    const past = Math.floor(Date.now() / 1000) - 10;
    const token = await signJwt(delegationClaims({ iat: past - 3600, exp: past }), key);
    const net = mockFetch({});

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('expired');
    expect(net.calls).toEqual([]);
  });

  // Pins the README's statement that a reason reports the FIRST failure: expiry is decided
  // BEFORE the principal and delegate pins are compared, so `expired` alone cannot distinguish
  // an expired delegation genuinely issued for your artifact from an expired token copied into
  // a stranger's card. Without this test the README sentence is only a promise — reordering the
  // checks would silently make it false. Found while walking the loop end to end
  // (docs/delegation-e2e-walkthrough.md § 5).
  it('reports expired even when the principal and delegate pins would also have failed', async () => {
    const past = Math.floor(Date.now() / 1000) - 10;
    const mismatchedPins = {
      delegate: { type: 'purl', value: 'pkg:npm/totally-unrelated-package' },
      expectedPrincipal: 'attacker-controlled-domain.example',
    } as const;

    // Positive control FIRST: the same pins against a LIVE token must actually fail, otherwise
    // "would also have failed" is vacuous and this test would keep passing if the fixture's
    // default principal/delegate ever drifted to match them.
    const live = await signJwt(delegationClaims(), key);
    const liveResult = await verifyDelegation(
      live,
      options({ fetch: mockFetch({}).fetch, statusCheck: 'skip', ...mismatchedPins })
    );
    expectFailure(liveResult);
    expect(liveResult.reason).toBe('principal_mismatch');

    const token = await signJwt(delegationClaims({ iat: past - 3600, exp: past }), key);
    const net = mockFetch({});

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip', ...mismatchedPins }));

    expectFailure(result);
    expect(result.reason).toBe('expired');
    expect(net.calls).toEqual([]);
  });

  it('rejects a token whose iat is in the future', async () => {
    const future = Math.floor(Date.now() / 1000) + 600;
    const token = await signJwt(delegationClaims({ iat: future, exp: future + 3600 }), key);

    const result = await verifyDelegation(token, options({ fetch: mockFetch({}).fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('not_yet_valid');
  });

  it('rejects malformed claims', async () => {
    const token = await signJwt(delegationClaims({ control_proof: '' }), key);

    const result = await verifyDelegation(token, options({ fetch: mockFetch({}).fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('malformed_claims');
  });

  it('reports principal_mismatch against expectedPrincipal', async () => {
    const token = await signJwt(delegationClaims(), key);

    const result = await verifyDelegation(
      token,
      options({ fetch: mockFetch({}).fetch, statusCheck: 'skip', expectedPrincipal: 'other.example' })
    );

    expectFailure(result);
    expect(result.reason).toBe('principal_mismatch');
  });

  it('matches expectedPrincipal case-insensitively', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, statusCheck: 'skip', expectedPrincipal: 'PostmarkApp.com ' })
    );

    expect(result.valid).toBe(true);
  });

  it('does not require a scope claim, and does not return one', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expect(result.valid).toBe(true);
    if (result.valid) expect(result.delegation).not.toHaveProperty('scope');
  });

  // Removed in 0.2.0 with the claim itself. Refused rather than ignored: an untyped caller still
  // passing it would otherwise believe a requirement was checked.
  it('refuses the removed requiredScopes option as invalid_options', async () => {
    const token = await signJwt(delegationClaims(), key);

    const result = await verifyDelegation(
      token,
      options({ fetch: mockFetch({}).fetch, statusCheck: 'skip', requiredScopes: ['send-email'] } as never)
    );

    expectFailure(result);
    expect(result.reason).toBe('invalid_options');
    expect(result.message).toMatch(/requiredScopes/);
  });
});

describe('delegate binding — requirement (a) (SC-5)', () => {
  it('refuses the call outright when delegate is missing', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({});

    const result = await verifyDelegation(token, {
      trustedIssuers: [trustedIssuer],
      fetch: net.fetch,
    } as unknown as VerifyOptions);

    expectFailure(result);
    expect(result.reason).toBe('invalid_options');
    expect(result.message).toMatch(/delegate is required/);
    expect(net.calls).toEqual([]);
  });

  it("defeats the copy attack: a genuine token republished under another package's identity", async () => {
    // Postmark's real, correctly signed delegation…
    const stolen = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    // …read by a client who resolved the artifact it is actually installing.
    const result = await verifyDelegation(
      stolen,
      options({ fetch: net.fetch, statusCheck: 'skip', delegate: { type: 'purl', value: 'pkg:npm/postmark-mcp-pro' } })
    );

    expectFailure(result);
    expect(result.reason).toBe('delegate_mismatch');
    expect(net.calls).toEqual([]);
  });

  it("canonicalizes the TOKEN's delegate too: a mixed-case Composer token verifies against the lowercase identity", async () => {
    // Minted before Composer names were lowercased (PR #712): the signed claim keeps its spelling.
    const token = await signJwt(delegationClaims({ delegate: 'pkg:composer/Foo/Bar' }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, statusCheck: 'skip', delegate: { type: 'purl', value: 'pkg:composer/foo/bar' } })
    );

    expect(result.valid).toBe(true);
    if (result.valid) expect(result.delegation.delegate).toBe('pkg:composer/Foo/Bar');
  });

  it("folds a PyPI token's separators the same way as the resolved identity", async () => {
    const token = await signJwt(delegationClaims({ delegate: 'pkg:pypi/zope_interface' }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, statusCheck: 'skip', delegate: { type: 'purl', value: 'pkg:pypi/zope.interface' } })
    );

    expect(result.valid).toBe(true);
  });

  it('keeps Go module case: a token for github.com/Foo/bar does not verify against github.com/foo/bar', async () => {
    const token = await signJwt(delegationClaims({ delegate: 'pkg:golang/github.com/Foo/bar' }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, statusCheck: 'skip', delegate: { type: 'purl', value: 'pkg:golang/github.com/foo/bar' } })
    );

    expectFailure(result);
    expect(result.reason).toBe('delegate_mismatch');
    expect(net.calls).toEqual([]);
  });

  it("answers delegate_mismatch — never throws — for a token delegate that does not canonicalize", async () => {
    const token = await signJwt(delegationClaims({ delegate: 'pkg:npm/postmark-mcp@1.0.0' }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('delegate_mismatch');
  });

  it('canonicalizes the caller-supplied delegate before comparing', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, statusCheck: 'skip', delegate: { type: 'purl', value: ' pkg:NPM/Postmark-MCP ' } })
    );

    expect(result.valid).toBe(true);
  });

  it('reports invalid_options when the resolved delegate cannot be canonicalized', async () => {
    const token = await signJwt(delegationClaims(), key);

    const result = await verifyDelegation(
      token,
      options({ fetch: mockFetch({}).fetch, delegate: { type: 'purl', value: 'pkg:npm/postmark-mcp@1.2.3' } })
    );

    expectFailure(result);
    expect(result.reason).toBe('invalid_options');
    expect(result.message).toMatch(/version is not allowed/);
  });
});

describe('status (SC-7)', () => {
  it('accepts a live delegation once the status list confirms it — no endpoint round trip', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 7, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 7: 0 }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expect(result).toMatchObject({ valid: true, statusChecked: true });
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).not.toContain(STATUS_ENDPOINT);
  });

  it('still short-circuits on a revoked list bit without calling the endpoint', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 9, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 9: 1 }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('revoked');
    expect(net.calls).not.toContain(STATUS_ENDPOINT);
  });

  it('reports revoked when the status list bit is set', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 7, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 7: 1 }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('revoked');
  });

  it('reports suspended for a paused delegation', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 3, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 3: 2 }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('suspended');
  });

  it('refuses a status-list uri outside the issuer origins WITHOUT fetching it, then asks the real endpoint', async () => {
    // The bogus claim-supplied uri is never trusted as an address to fetch (SSRF defence,
    // unchanged) — but an untrusted list read now falls through to the CALLER-CONFIGURED
    // statusEndpoint (h-delegation-verifier-status-fallthrough-gate SC-1/SC-2), which is not
    // derived from the token and so carries none of the same risk.
    const evilUri = 'https://attacker.example/status-list';
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: evilUri } } }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_ENDPOINT]: { json: { valid: true } } });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expect(result.valid).toBe(true);
    expect(net.calls).not.toContain(evilUri);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('no longer double-checks a valid bit against the endpoint — accepted trade-off (h-delegation-verifier-status-fallthrough-gate SC-6, bounded by h-fix-control-proof-reissue-shorter)', async () => {
    // Slot says valid, but the endpoint is wired to answer revoked-by-cascade anyway — before
    // h-status-list-cascade-fold this was the ONE thing only the endpoint could catch; the fold
    // now packs revoked/suspended straight into the bit, so this exact disagreement means the
    // issuer's own list is out of sync with itself, not something the verifier can second-guess
    // without paying for an endpoint round trip on every happy path. The residual this leaves
    // (an issuer whose list briefly disagrees with its own endpoint) is documented, not hidden:
    // see the status.ts file header and the package README.
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 2, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 2: 0 }),
      [STATUS_ENDPOINT]: { json: { valid: false, reason: 'revoked' } },
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expect(result.valid).toBe(true);
    expect(net.calls).not.toContain(STATUS_ENDPOINT);
  });

  it('fails closed when the issuer declares no status endpoint', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, trustedIssuers: [{ issuer: ISSUER, jwksUri: JWKS_URI }] })
    );

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
  });

  it('fails closed when the status endpoint is unreachable', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_ENDPOINT]: () => {
        throw new Error('timeout');
      },
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
  });

  it('reaches unknown_delegation through the endpoint — no list bit can answer it', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 5, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: () => {
        throw new Error('list unreachable');
      },
      [STATUS_ENDPOINT]: { json: { valid: false, reason: 'unknown_delegation' } },
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('unknown_delegation');
    expect(result.outcome).toBe('invalid');
  });

  it('rejects a status list signed by an unknown key', async () => {
    const attacker = await generateKey('attacker-key');
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(attacker, { 1: 0 }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('rejects a status list replayed from another uri', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 1: 0 }, { sub: 'https://issuer.test/other-list' }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('treats a slot beyond the end of the list as unanswered, not valid', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 4096, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 1: 0 }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('rejects an expired status list', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 1: 0 }, { exp: Math.floor(Date.now() / 1000) - 60 }),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('allows an extra status-list origin the trust policy declares', async () => {
    const cdnUri = 'https://cdn.issuer-mirror.test/status-list';
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: cdnUri } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [cdnUri]: await signStatusList(key, { 1: 0 }, { sub: cdnUri }),
      [STATUS_ENDPOINT]: { json: { valid: true } },
    });

    const result = await verifyDelegation(
      token,
      options({
        fetch: net.fetch,
        trustedIssuers: [{ ...trustedIssuer, statusListOrigins: ['https://cdn.issuer-mirror.test'] }],
      })
    );

    expect(result.valid).toBe(true);
  });
});

describe('key cache behaviour', () => {
  it('does not refetch the key set for a second token from the same issuer', async () => {
    const first = await signJwt(delegationClaims(), key);
    const second = await signJwt(delegationClaims({ sub: 'ph_dlg_second' }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    await verifyDelegation(first, options({ fetch: net.fetch, statusCheck: 'skip' }));
    await verifyDelegation(second, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expect(net.calls.filter((url) => url === JWKS_URI)).toHaveLength(1);
  });

  it('refetches at most once per cooldown for an unknown kid', async () => {
    const unknown = await generateKey('never-published');
    const token = await signJwt(delegationClaims(), unknown);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));
    await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));
    await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expect(net.calls.filter((url) => url === JWKS_URI)).toHaveLength(1);
  });

  it('serialises concurrent fetches of the same key set', async () => {
    const tokens = await Promise.all(
      Array.from({ length: 8 }, (_, index) => signJwt(delegationClaims({ sub: `ph_dlg_${index}` }), key))
    );
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const results = await Promise.all(
      tokens.map((token) => verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' })))
    );

    expect(results.every((result) => result.valid)).toBe(true);
    expect(net.calls.filter((url) => url === JWKS_URI)).toHaveLength(1);
  });
});

describe('malformed input', () => {
  it('rejects a non-JWT string', async () => {
    const result = await verifyDelegation('not-a-token', options({ fetch: mockFetch({}).fetch }));

    expectFailure(result);
    expect(result.reason).toBe('malformed_token');
  });
});

/**
 * `sdks/shared/fixtures/status_list_origin.json`, shared with the four SDKs. A refused uri is never
 * requested; the read then falls through to the configured `statusEndpoint`, whose answer is the
 * verdict — so "refused" shows on the wire, not in `reason`, which stays what it is today.
 *
 * The fixtures exist only in the monorepo, never in this package's public mirror, so there this suite
 * skips (see `vitest.config.ts`). Keyed on the directory rather than on the file, so that inside the
 * monorepo a renamed fixture still fails loudly.
 */
const SHARED_FIXTURES = new URL('../../../../sdks/shared/fixtures/', import.meta.url);
const HAS_SHARED_FIXTURES = existsSync(SHARED_FIXTURES);

describe.skipIf(!HAS_SHARED_FIXTURES)('the shared status-list origin fixture', () => {
  // vitest still runs a skipped suite's body to collect it, so the read waits on the same gate.
  const fixture = (
    HAS_SHARED_FIXTURES
      ? JSON.parse(readFileSync(new URL('status_list_origin.json', SHARED_FIXTURES), 'utf8'))
      : { configured_origin: 'https://fixture.invalid', status_list_origins: [], cases: [] }
  ) as {
    configured_origin: string;
    status_list_origins: string[];
    cases: Array<{ name: string; uri: string; delegation_verifier: 'accepted' | 'rejected' }>;
  };
  const configured = fixture.configured_origin;
  const jwksUri = `${configured}/.well-known/jwks.json`;
  const statusEndpoint = `${configured}/api/v1/proofs/validate`;

  it.each(fixture.cases)('$name: the status list is $delegation_verifier', async (testCase) => {
    const token = await signJwt(
      delegationClaims({ status: { status_list: { idx: 1, uri: testCase.uri } } }),
      key
    );
    const net = mockFetch({ [jwksUri]: jwksBody(key), [statusEndpoint]: { json: { valid: true } } });

    const result = await verifyDelegation(
      token,
      options({
        fetch: net.fetch,
        trustedIssuers: [
          { issuer: ISSUER, jwksUri, statusEndpoint, statusListOrigins: fixture.status_list_origins },
        ],
      })
    );
    const listPath = new URL(testCase.uri).pathname;
    const listRequests = net.calls.filter((url) => new URL(url).pathname === listPath);

    expect(result.valid).toBe(true);
    expect(net.calls).toContain(jwksUri);
    expect(net.calls).toContain(statusEndpoint);
    if (testCase.delegation_verifier === 'accepted') {
      // Unrouted, so the list read fails and falls through too: what is pinned is that it was made.
      expect(listRequests).toHaveLength(1);
      expect(new URL(listRequests[0]).origin).toBe(new URL(testCase.uri).origin);
    } else {
      expect(listRequests).toEqual([]);
    }
  });
});

/**
 * B.11f: a delegation token may carry `renewal_url`, where the current version of its token is served.
 * The verifier passes it on only when it is https and on the trusted issuer's own origin (the rule the
 * status-list uri follows); otherwise the delegation still verifies and the caller is told why it got
 * no pointer. The package never fetches it.
 */
describe('renewal_url (B.11f)', () => {
  const PULL = 'https://issuer.test/api/v1/proofs/delegation-token/ph_dlg_00000000000000000000000000000001';

  async function verified(claims: Record<string, unknown>, issuer: TrustedIssuer = trustedIssuer) {
    const token = await signJwt(delegationClaims(claims), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });
    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip', trustedIssuers: [issuer] }));
    if (!result.valid) throw new Error(`expected a valid delegation, got ${result.reason}`);
    return { delegation: result.delegation, calls: net.calls };
  }

  it('passes on an https URL on the issuer origin, and never fetches it', async () => {
    const { delegation, calls } = await verified({ renewal_url: PULL });
    expect(delegation.renewalUrl).toBe(PULL);
    expect(delegation.renewalUrlRejected).toBeUndefined();
    expect(calls).not.toContain(PULL);
  });

  it('answers null with no reason when the token carries none', async () => {
    const { delegation } = await verified({});
    expect(delegation.renewalUrl).toBeNull();
    expect(delegation.renewalUrlRejected).toBeUndefined();
  });

  it('refuses a URL off the issuer origin, still verifying the delegation (the rest: the shared fixture below)', async () => {
    const { delegation } = await verified({ renewal_url: 'https://elsewhere.test/api/v1/proofs/delegation-token/ph_dlg_00000000000000000000000000000001' });
    expect(delegation.renewalUrl).toBeNull();
    expect(delegation.renewalUrlRejected).toBe('off_origin');
  });

  it('carries the pointer on an EXPIRED copy too — the case the claim exists for', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(delegationClaims({ renewal_url: PULL, iat: now - 7200, exp: now - 3600 }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });
    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));
    expectFailure(result);
    expect(result.reason).toBe('expired');
    expect(result.renewalUrl).toBe(PULL);
    expect(result.renewalUrlRejected).toBeUndefined();
    expect(net.calls).not.toContain(PULL);
  });

  it('carries the pointer when the ISSUER reports the delegation expired, though the token’s own exp is ahead', async () => {
    const token = await signJwt(delegationClaims({ renewal_url: PULL }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_ENDPOINT]: { json: { valid: false, reason: 'expired' } } });
    const result = await verifyDelegation(token, options({ fetch: net.fetch }));
    expectFailure(result);
    expect([result.reason, result.renewalUrl, result.renewalUrlRejected]).toEqual(['expired', PULL, undefined]);
    expect(net.calls).toContain(STATUS_ENDPOINT);
    expect(net.calls).not.toContain(PULL);
  });

  it('applies the same rule to an expired copy: an off-origin pointer is withheld, with its reason', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(delegationClaims({ renewal_url: 'https://elsewhere.test/x', iat: now - 7200, exp: now - 3600 }), key);
    const result = await verifyDelegation(token, options({ fetch: mockFetch({ [JWKS_URI]: jwksBody(key) }).fetch, statusCheck: 'skip' }));
    expectFailure(result);
    expect([result.reason, result.renewalUrl, result.renewalUrlRejected]).toEqual(['expired', null, 'off_origin']);
  });

  it('carries no pointer on any other failure: a delegation from an untrusted issuer gets none', async () => {
    const token = await signJwt(delegationClaims({ renewal_url: PULL, iss: 'someone.else' }), key);
    const result = await verifyDelegation(token, options({ fetch: mockFetch({}).fetch }));
    expectFailure(result);
    expect(result.reason).toBe('untrusted_issuer');
    expect('renewalUrl' in result).toBe(false);
  });

  // Every reason's cases live in `sdks/shared/fixtures/renewal_url.json` (below, monorepo only).

});

describe.skipIf(!HAS_SHARED_FIXTURES)('the shared renewal_url fixture (B.11f)', () => {
  const fixture = (
    HAS_SHARED_FIXTURES
      ? JSON.parse(readFileSync(new URL('renewal_url.json', SHARED_FIXTURES), 'utf8'))
      : { jwks_origin: 'https://fixture.invalid', status_endpoint: 'https://fixture.invalid/v', status_list_origins: [], cases: [] }
  ) as {
    jwks_origin: string;
    status_endpoint: string;
    status_list_origins: string[];
    cases: Array<{ name: string; renewal_url?: unknown; renewalUrl: string | null; renewalUrlRejected: string | null }>;
  };
  const jwksUri = `${fixture.jwks_origin}/.well-known/jwks.json`;
  const issuer: TrustedIssuer = {
    issuer: ISSUER,
    jwksUri,
    statusEndpoint: fixture.status_endpoint,
    statusListOrigins: fixture.status_list_origins,
  };

  it('has every case the rule needs', () => {
    expect(new Set(fixture.cases.map((c) => c.renewalUrlRejected))).toEqual(new Set([null, 'not_https', 'off_origin', 'malformed']));
  });

  it.each(fixture.cases.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
    const claims = 'renewal_url' in c ? { renewal_url: c.renewal_url } : {};
    const token = await signJwt(delegationClaims(claims), key);
    const net = mockFetch({ [jwksUri]: jwksBody(key) });
    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip', trustedIssuers: [issuer] }));
    if (!result.valid) throw new Error(`expected a valid delegation, got ${result.reason}`);
    expect({ renewalUrl: result.delegation.renewalUrl, renewalUrlRejected: result.delegation.renewalUrlRejected ?? null }).toEqual({
      renewalUrl: c.renewalUrl,
      renewalUrlRejected: c.renewalUrlRejected,
    });
    expect(net.calls).toEqual([jwksUri]);
  });
});
