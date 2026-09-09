/**
 * Minimal JWT surface: base64url decoding and an UNVERIFIED structural parse.
 *
 * Deliberately dependency-free and deliberately small — everything here runs BEFORE any
 * signature has been checked, so nothing it produces may be treated as a fact. The one thing
 * the caller may read from an unverified token is `iss`, and only to select which trusted
 * issuer's key set to check the signature against.
 */

export interface ParsedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** `<header>.<payload>` — the bytes the signature is over. */
  signingInput: string;
  signature: Uint8Array;
}

export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJsonSegment(segment: string): Record<string, unknown> | null {
  try {
    const text = new TextDecoder().decode(base64UrlToBytes(segment));
    const parsed: unknown = JSON.parse(text);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Structural parse. Null on anything that is not a three-part JWT with JSON object segments. */
export function parseJwt(token: string): ParsedJwt | null {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  // An EMPTY signature segment is structurally legal (that is what an `alg: none` token looks
  // like) and is deliberately parsed rather than rejected here: refusing it as "malformed"
  // would hide the far more useful answer the algorithm gate gives one step later — that the
  // verifier picks the algorithm, and this token asked for one that is not accepted.
  if (!headerSegment || !payloadSegment) return null;

  const header = decodeJsonSegment(headerSegment);
  const payload = decodeJsonSegment(payloadSegment);
  if (!header || !payload) return null;

  let signature: Uint8Array;
  try {
    signature = base64UrlToBytes(signatureSegment);
  } catch {
    return null;
  }

  return {
    header,
    payload,
    signingInput: `${headerSegment}.${payloadSegment}`,
    signature,
  };
}
