/**
 * Test helpers: a real RS256 issuer (WebCrypto keys, real signatures, real JWKS) and a
 * routing mock fetch that COUNTS requests — several tests assert that a rejection cost zero
 * outbound calls, which only a counting fetch can prove.
 */

import { expect } from 'vitest';
import type { FetchLike } from '../types.js';

export const ISSUER = 'test.issuer';
export const JWKS_URI = 'https://issuer.test/.well-known/jwks.json';
export const STATUS_LIST_URI = 'https://issuer.test/api/v1/proofs/status-list';
export const STATUS_ENDPOINT = 'https://issuer.test/api/v1/proofs/validate';

export interface TestKey {
  kid: string;
  publicJwk: JsonWebKey;
  privateKey: CryptoKey;
}

export async function generateKey(kid = 'test-key-1'): Promise<TestKey> {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { kid, publicJwk: { ...publicJwk, kid, alg: 'RS256', use: 'sig' }, privateKey: pair.privateKey };
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeSegment(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

export async function signJwt(
  payload: Record<string, unknown>,
  key: TestKey,
  header: Record<string, unknown> = {}
): Promise<string> {
  const fullHeader = { alg: 'RS256', typ: 'JWT', kid: key.kid, ...header };
  const signingInput = `${encodeSegment(fullHeader)}.${encodeSegment(payload)}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key.privateKey,
    new TextEncoder().encode(signingInput) as unknown as BufferSource
  );
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}

/** An unsigned-but-well-formed token, for the `alg: none` forgery case. */
export function unsignedJwt(payload: Record<string, unknown>, alg = 'none'): string {
  return `${encodeSegment({ alg, typ: 'JWT' })}.${encodeSegment(payload)}.`;
}

export function delegationClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    sub: 'ph_dlg_00000000000000000000000000000001',
    iat: now - 60,
    exp: now + 3600,
    token_type: 'delegation',
    delegation_schema_version: '2.0',
    user_id: 'user-1',
    principal: 'postmarkapp.com',
    delegate: 'pkg:npm/postmark-mcp',
    control_proof: 'ph_ctl_00000000000000000000000000000002',
    proof_id: 'ph_dlg_00000000000000000000000000000001',
    jti: 'ph_jti_00000000000000000000000000000003',
    ...overrides,
  };
}

async function deflate(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes as unknown as BlobPart]).stream().pipeThrough(new CompressionStream('deflate'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * A signed IETF status list where `statuses` maps slot index → status value
 * (0 valid, 1 revoked, 2 suspended). Byte packing mirrors the issuer implementation.
 */
export async function signStatusList(
  key: TestKey,
  statuses: Record<number, number>,
  overrides: { sub?: string; exp?: number; size?: number } = {}
): Promise<string> {
  const indices = Object.keys(statuses).map(Number);
  const maxIndex = Math.max(-1, ...indices);
  const slots = overrides.size ?? maxIndex + 1;
  const bytes = new Uint8Array(Math.max(1, Math.ceil((slots * 2) / 8)));
  for (const [index, value] of Object.entries(statuses)) {
    const idx = Number(index);
    bytes[Math.floor(idx / 4)] |= value << ((idx % 4) * 2);
  }
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    {
      sub: overrides.sub ?? STATUS_LIST_URI,
      iat: now,
      exp: overrides.exp ?? now + 3600,
      ttl: 300,
      status_list: { bits: 2, lst: base64Url(await deflate(bytes)) },
    },
    key,
    { typ: 'statuslist+jwt' }
  );
}

export interface MockFetch {
  fetch: FetchLike;
  calls: string[];
}

type RouteHandler = string | { status?: number; body?: string; json?: unknown } | (() => never);

/** Routing mock fetch. An unrouted URL throws — an unexpected request must fail loudly. */
export function mockFetch(routes: Record<string, RouteHandler>): MockFetch {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (input) => {
    const url = String(input);
    calls.push(url);
    const handler = routes[url];
    if (handler === undefined) throw new Error(`unexpected fetch: ${url}`);
    if (typeof handler === 'function') return handler();
    if (typeof handler === 'string') {
      return new Response(handler, { status: 200, headers: { 'content-type': 'application/jwt' } });
    }
    if (handler.json !== undefined) {
      return new Response(JSON.stringify(handler.json), {
        status: handler.status ?? 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response(handler.body ?? '', { status: handler.status ?? 200 });
  };
  return { fetch: fetchImpl, calls };
}

export function jwksBody(...keys: TestKey[]): { json: unknown } {
  return { json: { keys: keys.map((key) => key.publicJwk) } };
}

/** Narrowing assert so tests can read `.reason` without a cast. */
export function expectFailure(
  result: { valid: boolean } & Record<string, unknown>
): asserts result is { valid: false; reason: string; message: string } {
  expect(result.valid).toBe(false);
}
