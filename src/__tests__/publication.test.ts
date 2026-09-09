import { beforeEach, describe, expect, it } from 'vitest';
import {
  DELEGATION_EXTENSION_URI,
  DELEGATION_META_KEY,
  REGISTRY_PUBLISHER_PROVIDED_KEY,
  extractDelegationPublications,
  verifyPublishedDelegation,
} from '../publication.js';
import { resetJwksCache } from '../jwks.js';
import { readStatusSlot } from '../status.js';
import type { TrustedIssuer } from '../types.js';
import {
  delegationClaims,
  expectFailure,
  generateKey,
  ISSUER,
  jwksBody,
  JWKS_URI,
  mockFetch,
  signJwt,
  STATUS_ENDPOINT,
  type TestKey,
} from './helpers.js';

const trustedIssuer: TrustedIssuer = { issuer: ISSUER, jwksUri: JWKS_URI, statusEndpoint: STATUS_ENDPOINT };
const RESOLVED_DELEGATE = { type: 'purl', value: 'pkg:npm/postmark-mcp' } as const;

let key: TestKey;

beforeEach(async () => {
  resetJwksCache();
  key = await generateKey();
});

describe('extractDelegationPublications (SC-8)', () => {
  it('reads the top-level MCP `_meta` carrier', () => {
    const card = { _meta: { [DELEGATION_META_KEY]: { token: 'tok' } } };
    expect(extractDelegationPublications(card)).toEqual([
      { location: `_meta["${DELEGATION_META_KEY}"]`, value: { token: 'tok' } },
    ]);
  });

  it('reads the registry publisher-provided carrier', () => {
    const card = {
      _meta: { [REGISTRY_PUBLISHER_PROVIDED_KEY]: { [DELEGATION_META_KEY]: { token: 'tok' } } },
    };
    expect(extractDelegationPublications(card)).toHaveLength(1);
  });

  it('reads the A2A extension carrier by uri', () => {
    const card = {
      capabilities: {
        extensions: [
          { uri: 'https://example.test/other', params: { token: 'no' } },
          { uri: DELEGATION_EXTENSION_URI, params: { token: 'tok' } },
        ],
      },
    };
    expect(extractDelegationPublications(card)).toEqual([
      { location: 'capabilities.extensions[1]', value: { token: 'tok' } },
    ]);
  });

  it('ignores a bare top-level key — no carrier reads it', () => {
    expect(extractDelegationPublications({ [DELEGATION_META_KEY]: { token: 'tok' } })).toEqual([]);
  });

  it('ignores non-object input', () => {
    expect(extractDelegationPublications(null)).toEqual([]);
    expect(extractDelegationPublications('card')).toEqual([]);
    expect(extractDelegationPublications([{ _meta: {} }])).toEqual([]);
  });
});

describe('verifyPublishedDelegation (SC-8)', () => {
  it('verifies a delegation published in an MCP server card', async () => {
    const token = await signJwt(delegationClaims(), key);
    const card = { name: 'io.example/mcp', _meta: { [DELEGATION_META_KEY]: { token } } };
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyPublishedDelegation(card, {
      trustedIssuers: [trustedIssuer],
      delegate: RESOLVED_DELEGATE,
      fetch: net.fetch,
      statusCheck: 'skip',
    });

    expect(result.valid).toBe(true);
  });

  it('verifies a delegation published in an A2A agent card', async () => {
    const token = await signJwt(delegationClaims(), key);
    const card = { capabilities: { extensions: [{ uri: DELEGATION_EXTENSION_URI, params: { token } }] } };
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyPublishedDelegation(card, {
      trustedIssuers: [trustedIssuer],
      delegate: RESOLVED_DELEGATE,
      fetch: net.fetch,
      statusCheck: 'skip',
    });

    expect(result.valid).toBe(true);
  });

  it('accepts the same token published in two carriers at once', async () => {
    const token = await signJwt(delegationClaims(), key);
    const card = {
      _meta: {
        [DELEGATION_META_KEY]: { token },
        [REGISTRY_PUBLISHER_PROVIDED_KEY]: { [DELEGATION_META_KEY]: { token } },
      },
    };
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyPublishedDelegation(card, {
      trustedIssuers: [trustedIssuer],
      delegate: RESOLVED_DELEGATE,
      fetch: net.fetch,
      statusCheck: 'skip',
    });

    expect(result.valid).toBe(true);
  });

  it('refuses to guess between two DIFFERENT published tokens', async () => {
    const first = await signJwt(delegationClaims(), key);
    const second = await signJwt(delegationClaims({ sub: 'ph_dlg_other' }), key);
    const card = {
      _meta: { [DELEGATION_META_KEY]: { token: first } },
      capabilities: { extensions: [{ uri: DELEGATION_EXTENSION_URI, params: { token: second } }] },
    };

    const result = await verifyPublishedDelegation(card, {
      trustedIssuers: [trustedIssuer],
      delegate: RESOLVED_DELEGATE,
      fetch: mockFetch({}).fetch,
    });

    expectFailure(result);
    expect(result.reason).toBe('multiple_publications');
  });

  it('reports no_publication for a card without one', async () => {
    const result = await verifyPublishedDelegation(
      { name: 'io.example/mcp' },
      { trustedIssuers: [trustedIssuer], delegate: RESOLVED_DELEGATE, fetch: mockFetch({}).fetch }
    );

    expectFailure(result);
    expect(result.reason).toBe('no_publication');
  });

  it("compares against the caller's artifact, not the card's own claim about itself", async () => {
    // The card names itself `pkg:npm/postmark-mcp` AND carries Postmark's genuine token —
    // but the caller is installing something else, and that is the fact that decides.
    const token = await signJwt(delegationClaims(), key);
    const card = { name: 'pkg:npm/postmark-mcp', _meta: { [DELEGATION_META_KEY]: { token } } };
    const net = mockFetch({ [JWKS_URI]: jwksBody(key) });

    const result = await verifyPublishedDelegation(card, {
      trustedIssuers: [trustedIssuer],
      delegate: { type: 'purl', value: 'pkg:npm/postmark-mcp-community' },
      fetch: net.fetch,
    });

    expectFailure(result);
    expect(result.reason).toBe('delegate_mismatch');
  });
});

describe('readStatusSlot byte order (SC-7)', () => {
  it('reads 2-bit slots lowest-index-first inside a byte', () => {
    // 0b11_10_01_00 — slot0 = 0, slot1 = 1, slot2 = 2, slot3 = 3
    const bytes = new Uint8Array([0b11100100]);
    expect(readStatusSlot(bytes, 0, 2)).toBe(0);
    expect(readStatusSlot(bytes, 1, 2)).toBe(1);
    expect(readStatusSlot(bytes, 2, 2)).toBe(2);
    expect(readStatusSlot(bytes, 3, 2)).toBe(3);
  });

  it('returns null past the end of the list and for a negative index', () => {
    const bytes = new Uint8Array([0b00000001]);
    expect(readStatusSlot(bytes, 4, 2)).toBeNull();
    expect(readStatusSlot(bytes, -1, 2)).toBeNull();
  });

  it('rejects a bits value that is not a power-of-two divisor of 8', () => {
    expect(readStatusSlot(new Uint8Array([0]), 0, 3)).toBeNull();
  });
});
