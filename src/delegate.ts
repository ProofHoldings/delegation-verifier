/**
 * Canonicalization of typed delegate identifiers.
 *
 * ⚠️ SECOND LOCKSTEP COPY. The authority is the issuer-side implementation
 * (`src/utils/delegateIdentifier.ts` in the proof.holdings backend), which produces the string
 * that gets SIGNED into a token's `delegate` claim. This file must produce the same string for
 * the same input, byte for byte, or a verifier reads a valid delegation as a mismatch. The
 * equivalence is pinned by the drift suite `src/__tests__/drift/delegation-verifier.test.ts`
 * in that repository, which runs one shared vector through both implementations.
 *
 * It is copied rather than imported for the reason the package exists at all: a gateway
 * verifying someone's delegation must not have to install the issuer's backend.
 */

import type { DelegateInput, DelegateType } from './types.js';

export const DELEGATE_TYPES: readonly DelegateType[] = ['url', 'purl'] as const;

/** Cap on the CANONICAL delegate string. */
export const DELEGATE_MAX_LENGTH = 512;

/** `pkg:type/[namespace/]name` — structure only; per-type case rules applied after. */
const PURL_RE = /^pkg:([a-z0-9.+-]+)\/(.+)$/i;

export class DelegateIdentifierError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DelegateIdentifierError';
  }
}

/**
 * Validate and canonicalize a typed delegate. Throws `DelegateIdentifierError` on rejection —
 * the caller turns that into an `invalid_options` failure, because an artifact identity that
 * cannot be canonicalized is a bug in the CALL, not evidence about the token.
 */
export function canonicalizeDelegate(input: DelegateInput): string {
  if (input.type === 'purl') return canonicalizePurl(input.value);
  if (input.type === 'url') return canonicalizeUrl(input.value);
  throw new DelegateIdentifierError(`unknown delegate type: ${String(input.type)}`);
}

function canonicalizePurl(value: string): string {
  const raw = value.trim();
  if (!raw) throw new DelegateIdentifierError('delegate must not be empty');
  if (/\s/.test(raw)) throw new DelegateIdentifierError('delegate must not contain whitespace');
  if (raw.includes('?')) {
    throw new DelegateIdentifierError('purl qualifiers are not allowed in a delegate');
  }
  if (raw.includes('#')) {
    throw new DelegateIdentifierError('purl subpath is not allowed in a delegate');
  }

  const match = raw.match(PURL_RE);
  if (!match) {
    throw new DelegateIdentifierError('delegate must be a purl of the form pkg:type/name');
  }

  const type = match[1].toLowerCase();
  let rest = match[2];

  // `@` in an npm scope (`pkg:npm/@acme/tool`) is legitimate; a trailing `@version` is not.
  if (findVersionSeparator(rest) !== -1) {
    throw new DelegateIdentifierError(
      'purl version is not allowed in a delegate — delegate the artifact, not a version'
    );
  }

  const segments = rest.split('/');
  if (segments.some((segment) => segment.length === 0)) {
    throw new DelegateIdentifierError('purl namespace and name must not be empty');
  }

  // Per-type case rules (purl-spec: type is case-insensitive and canonically lowercase; name
  // rules are per-type). npm and pypi are lowercase-only registries; pypi additionally treats
  // `_` and `-` as equivalent, canonically `-` (PEP 503).
  if (type === 'npm') {
    rest = segments.map((segment) => segment.toLowerCase()).join('/');
  } else if (type === 'pypi') {
    rest = segments.map((segment) => segment.toLowerCase().replace(/_/g, '-')).join('/');
  } else {
    rest = segments.join('/');
  }

  return enforceLength(`pkg:${type}/${rest}`);
}

/**
 * Index of an `@version` separator, or -1. A leading `@` on a path segment is a scope/user
 * marker (`@acme` in `pkg:npm/@acme/tool`), not a version.
 */
function findVersionSeparator(rest: string): number {
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] !== '@') continue;
    if (i === 0 || rest[i - 1] === '/') continue; // scope marker
    return i;
  }
  return -1;
}

function canonicalizeUrl(value: string): string {
  const raw = value.trim();
  if (!raw) throw new DelegateIdentifierError('delegate must not be empty');

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new DelegateIdentifierError('delegate must be a valid absolute URL');
  }

  if (parsed.protocol !== 'https:') {
    throw new DelegateIdentifierError('delegate URL must use https');
  }
  if (parsed.username || parsed.password) {
    throw new DelegateIdentifierError('delegate URL must not carry credentials');
  }
  if (parsed.search) {
    throw new DelegateIdentifierError('delegate URL must not carry a query string');
  }
  if (raw.includes('#')) {
    throw new DelegateIdentifierError('delegate URL must not carry a fragment');
  }

  // URL() already lowercases the host and strips an explicit default port; pathname keeps its
  // case. Trailing slash is canonicalized away except at the root, where it is always '/' — a
  // path of slashes only collapses to that root, so the result is idempotent.
  let pathname = parsed.pathname;
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.replace(/\/+$/, '') || '/';
  }

  return enforceLength(`https://${parsed.host}${pathname}`);
}

function enforceLength(canonical: string): string {
  if (canonical.length > DELEGATE_MAX_LENGTH) {
    throw new DelegateIdentifierError(`delegate is too long (max ${DELEGATE_MAX_LENGTH} characters)`);
  }
  return canonical;
}
