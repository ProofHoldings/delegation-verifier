import { beforeEach, describe, expect, it } from 'vitest';
import { verifyProofToken } from '../proof.js';
import { resetJwksCache } from '../jwks.js';
import type { ProofVerifyOptions, TrustedIssuer } from '../types.js';
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

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function proofClaims(overrides: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    sub: 'verification-1',
    iat: now - 60,
    exp: now + 3600,
    proof_schema_version: '1.2',
    user_id: 'user-1',
    type: 'domain',
    channel: 'dns',
    identifier_hash: await sha256Hex('team.management'),
    verified_at: '2026-10-01T10:00:00.000Z',
    proof_id: 'ph_prf_00000000000000000000000000000001',
    jti: 'ph_jti_00000000000000000000000000000002',
    status: { status_list: { idx: 3, uri: STATUS_LIST_URI } },
    ...overrides,
  };
}

let key: TestKey;

beforeEach(async () => {
  resetJwksCache();
  key = await generateKey();
});

function options(overrides: Partial<ProofVerifyOptions> = {}): ProofVerifyOptions {
  return { trustedIssuers: [trustedIssuer], expected: { type: 'domain', identifier: 'team.management' }, ...overrides };
}

describe('verifyProofToken', () => {
  it('verifies a signed proof about the identifier the caller expects, its status read from the list', async () => {
    const token = await signJwt(await proofClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_LIST_URI]: await signStatusList(key, { 3: 0 }) });

    const result = await verifyProofToken(token, options({ fetch: net.fetch }));

    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.statusChecked).toBe(true);
    expect(result.proof).toMatchObject({
      issuer: ISSUER,
      type: 'domain',
      channel: 'dns',
      proofId: 'ph_prf_00000000000000000000000000000001',
    });
    expect(result.proof.verifiedAt?.toISOString()).toBe('2026-10-01T10:00:00.000Z');
    expect(net.calls).toEqual([JWKS_URI, STATUS_LIST_URI]);
  });

  it('refuses a genuine token about another identifier, without any network call', async () => {
    const token = await signJwt(await proofClaims(), key);
    const net = mockFetch({});

    const result = await verifyProofToken(token, options({ expected: { type: 'domain', identifier: 'other.example' }, fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('identifier_mismatch');
    expect(result.outcome).toBe('invalid');
    expect(net.calls).toEqual([]);
  });

  it('refuses a token of another proof type, without any network call', async () => {
    const token = await signJwt(await proofClaims(), key);
    const net = mockFetch({});

    const result = await verifyProofToken(token, options({ expected: { type: 'email', identifier: 'team.management' }, fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('proof_type_mismatch');
    expect(net.calls).toEqual([]);
  });

  it('refuses a delegation token handed in as a proof', async () => {
    const token = await signJwt(delegationClaims(), key);
    const net = mockFetch({});

    const result = await verifyProofToken(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('not_a_proof');
    expect(net.calls).toEqual([]);
  });

  it('refuses an expired proof and an untrusted issuer before the network', async () => {
    const now = Math.floor(Date.now() / 1000);
    const net = mockFetch({});

    const expired = await verifyProofToken(await signJwt(await proofClaims({ exp: now - 600 }), key), options({ fetch: net.fetch }));
    const untrusted = await verifyProofToken(await signJwt(await proofClaims({ iss: 'evil.example' }), key), options({ fetch: net.fetch }));

    expectFailure(expired);
    expect(expired.reason).toBe('expired');
    expectFailure(untrusted);
    expect(untrusted.reason).toBe('untrusted_issuer');
    expect(net.calls).toEqual([]);
  });

  it('refuses a token signed by a key the issuer does not publish', async () => {
    const stranger = await generateKey('test-key-1');
    const token = await signJwt(await proofClaims(), stranger);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyProofToken(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('bad_signature');
  });

  it('reports a proof the status list marks revoked', async () => {
    const token = await signJwt(await proofClaims(), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_LIST_URI]: await signStatusList(key, { 3: 1 }) });

    const result = await verifyProofToken(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('revoked');
    expect(result.message).toContain('proof');
    expect(result.message).not.toContain('delegation');
  });

  it('asks the status endpoint for a token with no status-list slot, and reads `superseded` as a verdict', async () => {
    const token = await signJwt(await proofClaims({ status: undefined }), key);
    const valid = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_ENDPOINT]: { json: { valid: true } } });
    expect((await verifyProofToken(token, options({ fetch: valid.fetch }))).valid).toBe(true);
    expect(valid.calls).toEqual([JWKS_URI, STATUS_ENDPOINT]);

    resetJwksCache();
    const superseded = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_ENDPOINT]: { json: { valid: false, reason: 'superseded' } } });
    const result = await verifyProofToken(token, options({ fetch: superseded.fetch }));
    expectFailure(result);
    expect(result.reason).toBe('superseded');
    expect(result.outcome).toBe('invalid');
  });

  it('reads a test-mode proof as `test_environment` (invalid), never status_unavailable', async () => {
    // The issuer answers a proof issued in test mode with this reason before any other status.
    const token = await signJwt(await proofClaims({ status: undefined }), key);
    const testMode = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_ENDPOINT]: { json: { valid: false, reason: 'test_environment' } } });
    const result = await verifyProofToken(token, options({ fetch: testMode.fetch }));
    expectFailure(result);
    expect(result.reason).toBe('test_environment');
    expect(result.outcome).toBe('invalid');
    expect(result.message).toBe('the issuer reports this proof was issued in test mode');
  });

  it('answers status_unavailable (unconfirmed) when neither status channel can be read', async () => {
    const token = await signJwt(await proofClaims({ status: undefined }), key);
    const net = mockFetch({ [JWKS_URI]: jwksBody(key), [STATUS_ENDPOINT]: { status: 503, body: '' } });

    const result = await verifyProofToken(token, options({ fetch: net.fetch }));

    expectFailure(result);
    expect(result.reason).toBe('status_unavailable');
    expect(result.outcome).toBe('unconfirmed');
  });

  it('requires the expectation: no expected identifier is invalid_options, never a skipped binding', async () => {
    const token = await signJwt(await proofClaims(), key);
    const net = mockFetch({});

    const result = await verifyProofToken(token, { trustedIssuers: [trustedIssuer], fetch: net.fetch } as unknown as ProofVerifyOptions);

    expectFailure(result);
    expect(result.reason).toBe('invalid_options');
    expect(net.calls).toEqual([]);
  });

  it('refuses with no_trust_policy when trustedIssuers is empty', async () => {
    const token = await signJwt(await proofClaims(), key);
    const result = await verifyProofToken(token, options({ trustedIssuers: [] }));
    expectFailure(result);
    expect(result.reason).toBe('no_trust_policy');
  });
});
