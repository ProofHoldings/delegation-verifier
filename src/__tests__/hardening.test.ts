/**
 * Regression cover for the code-review round-1 findings. Each case names the property it
 * defends rather than the fix that produced it.
 */

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
  type TestKey,
} from './helpers.js';

const trustedIssuer: TrustedIssuer = { issuer: ISSUER, jwksUri: JWKS_URI, statusEndpoint: STATUS_ENDPOINT };
const RESOLVED_DELEGATE = { type: 'purl', value: 'pkg:npm/postmark-mcp' } as const;

let key: TestKey;

beforeEach(async () => {
  resetJwksCache();
  key = await generateKey();
});

function options(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return { trustedIssuers: [trustedIssuer], delegate: RESOLVED_DELEGATE, ...overrides };
}

describe('principalChecked — the sibling attack the required delegate does NOT stop', () => {
  it('flags a verdict as principal-unchecked when no expectedPrincipal was supplied', async () => {
    // An issuer binds `delegate` to nothing: evil.example can mint this for someone else's
    // package, signature and all. The caller must be able to see that half was not asked.
    const token = await signJwt(delegationClaims({ principal: 'evil.example' }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.principalChecked).toBe(false);
      expect(result.delegation.principal).toBe('evil.example');
    }
  });

  it('reports principalChecked once the caller pins the domain', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyDelegation(
      token,
      options({ fetch: net.fetch, statusCheck: 'skip', expectedPrincipal: 'postmarkapp.com' })
    );

    expect(result.valid).toBe(true);
    if (result.valid) expect(result.principalChecked).toBe(true);
  });
});

describe('option validation returns a verdict rather than throwing', () => {
  it('reports invalid_options for a non-string expectedPrincipal instead of throwing', async () => {
    // The library is aimed at untyped consumers; the option that closes the sibling attack
    // must not be the one that escapes the discriminated-result contract.
    const token = await signJwt(delegationClaims(), key);

    const result = await verifyDelegation(
      token,
      options({ fetch: mockFetch({}).fetch, expectedPrincipal: 42 as unknown as string })
    );

    expectFailure(result);
    expect(result.reason).toBe('invalid_options');
  });

  it('reports invalid_options for a blank expectedPrincipal', async () => {
    const token = await signJwt(delegationClaims(), key);

    const result = await verifyDelegation(token, options({ fetch: mockFetch({}).fetch, expectedPrincipal: '   ' }));

    expectFailure(result);
    expect(result.reason).toBe('invalid_options');
  });
});

describe('issuer answers that are not withdrawals', () => {
  async function withEndpointAnswer(answer: Record<string, unknown>) {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_ENDPOINT]: { json: answer } });
    return verifyDelegation(token, options({ fetch: net.fetch }));
  }

  it('does NOT report revoked when the issuer says it could not check', async () => {
    // proof.holdings answers this on a registry read failure. Calling it "revoked" would make
    // a database blip at the issuer look like a permanent withdrawal to every gateway.
    const result = await withEndpointAnswer({ valid: false, reason: 'status_unavailable' });

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
  });

  it('treats an unrecognised reason as unavailable, not revoked', async () => {
    const result = await withEndpointAnswer({ valid: false, reason: 'teapot' });

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
  });

  it('reports unknown_delegation distinctly from revoked', async () => {
    const result = await withEndpointAnswer({ valid: false, reason: 'unknown_delegation' });

    expectFailure(result);
    expect(result.reason).toBe('unknown_delegation');
  });

  it('refuses a delegation the issuer reports issued in test mode — a verdict, not "could not check"', async () => {
    // The body proof.holdings answers for a delegation minted in test mode, where `test-verify`
    // completes a verification with no real check (h-fix-test-mode-trust-isolation).
    const result = await withEndpointAnswer({ valid: false, token_type: 'delegation', reason: 'test_environment' });

    expectFailure(result);
    expect(result.reason).toBe('test_environment');
    expect(result.outcome).toBe('invalid');
  });

  it('reports expired distinctly from revoked', async () => {
    const result = await withEndpointAnswer({ valid: false, reason: 'expired' });

    expectFailure(result);
    expect(result.reason).toBe('expired');
  });

  it('still reports a real revocation as revoked', async () => {
    const result = await withEndpointAnswer({ valid: false, reason: 'revoked' });

    expectFailure(result);
    expect(result.reason).toBe('revoked');
  });
});

describe('trust-policy validation', () => {
  it('drops an entry whose statusEndpoint is not https — the token would be POSTed in clear', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({});

    const result = await verifyDelegation(
      token,
      options({
        fetch: net.fetch,
        trustedIssuers: [{ issuer: ISSUER, jwksUri: JWKS_URI, statusEndpoint: 'http://issuer.test/validate' }],
      })
    );

    expectFailure(result);
    expect(result.reason).toBe('no_trust_policy');
    expect(net.calls).toEqual([]);
  });

  it('drops an entry with a non-https extra status origin', async () => {
    const token = await signJwt(delegationClaims(), key);

    const result = await verifyDelegation(
      token,
      options({
        fetch: mockFetch({}).fetch,
        trustedIssuers: [{ ...trustedIssuer, statusListOrigins: ['http://mirror.test'] }],
      })
    );

    expectFailure(result);
    expect(result.reason).toBe('no_trust_policy');
  });
});

describe('status list authenticity', () => {
  it('refuses a list that does not declare typ statuslist+jwt', async () => {
    // The one header separating a status list from every other JWT the issuer signs with the
    // same key.
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }), key);
    const plainJwt = await signJwt(
      {
        sub: STATUS_LIST_URI,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        status_list: { bits: 2, lst: 'eJwDAAAAAAE' },
      },
      key,
      { typ: 'JWT' }
    );
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_LIST_URI]: plainJwt });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    // The list is unusable (wrong typ), which now falls through to the endpoint
    // (h-delegation-verifier-status-fallthrough-gate) rather than dead-ending — the endpoint
    // isn't mocked, so the final reason is the endpoint's own unavailable, not the list's; what
    // this test defends is that the malformed list was actually read and rejected, not trusted.
    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('refuses a list with no exp — a freshness channel that never goes stale is not one', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }), key);
    const listNoExp = await signJwt(
      {
        sub: STATUS_LIST_URI,
        iat: Math.floor(Date.now() / 1000),
        status_list: { bits: 2, lst: 'eJwDAAAAAAE' },
      },
      key,
      { typ: 'statuslist+jwt' }
    );
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_LIST_URI]: listNoExp });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('refuses an oversized status-list response', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: 'x'.repeat(600 * 1024),
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(net.calls).toContain(STATUS_LIST_URI);
    expect(net.calls).toContain(STATUS_ENDPOINT);
  });

  it('accepts a well-formed list unchanged', async () => {
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 5, uri: STATUS_LIST_URI } } }), key);
    const net = mockFetch({
      [JWKS_URI]: jwksBody(key),
      [STATUS_LIST_URI]: await signStatusList(key, { 5: 0 }),
      [STATUS_ENDPOINT]: { json: { valid: true } },
    });

    const result = await verifyDelegation(token, options({ fetch: net.fetch }));

    expect(result.valid).toBe(true);
  });
});

describe('redirects are not followed', () => {
  it('asks fetch to error rather than follow on every outbound call', async () => {
    // The origin guard is only worth the hop it guards: with `follow`, any open redirect on
    // the issuer's origin carries the fetch off it, since the token controls the path.
    const seen: (RequestInit | undefined)[] = [];
    const token = await signJwt(delegationClaims({ status: { status_list: { idx: 1, uri: STATUS_LIST_URI } } }), key);
    const listToken = await signStatusList(key, { 1: 0 });
    const fetchImpl = async (input: string, init?: RequestInit) => {
      seen.push(init);
      if (input === JWKS_URI) {
        return new Response(JSON.stringify({ keys: [key.publicJwk] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (input === STATUS_LIST_URI) return new Response(listToken, { status: 200 });
      return new Response(JSON.stringify({ valid: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };

    await verifyDelegation(token, options({ fetch: fetchImpl }));

    // Two calls, not three: the list bit is valid, and h-delegation-verifier-status-
    // fallthrough-gate stops the endpoint round trip that used to follow it — exactly the
    // saving SC-1 is for. The third branch above stays in place (harmless, unreached) so this
    // test still proves the redirect policy on the endpoint too, should the gate ever change.
    expect(seen).toHaveLength(2);
    expect(seen.every((init) => init?.redirect === 'error')).toBe(true);
  });
});

describe('JWKS failure is not a forgery signal', () => {
  it('reports jwks_unavailable — not unknown_key — to CONCURRENT callers when the fetch fails', async () => {
    const token = await signJwt(delegationClaims(), key);
    let calls = 0;
    const fetchImpl = async () => {
      calls++;
      throw new Error('connection refused');
    };

    const results = await Promise.all(
      Array.from({ length: 6 }, () => verifyDelegation(token, options({ fetch: fetchImpl, statusCheck: 'skip' })))
    );

    expect(calls).toBe(1); // one in-flight fetch shared by all six
    for (const result of results) {
      expectFailure(result);
      expect(result.reason).toBe('jwks_unavailable');
    }
  });

  it('refuses an oversized JWKS response', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({ [JWKS_URI]: { body: 'x'.repeat(600 * 1024), status: 200 } });

    const result = await verifyDelegation(token, options({ fetch: net.fetch, statusCheck: 'skip' }));

    expectFailure(result);
    expect(result.reason).toBe('jwks_unavailable');
    expect(result.message).toMatch(/too large/);
  });
});
