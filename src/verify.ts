/**
 * `verifyDelegation` — the chain: signature → principal → delegate → status.
 *
 * Order is deliberate. Everything that can be decided WITHOUT the network is decided first, so
 * a token from an untrusted issuer, a token about someone else's artifact and an expired token
 * all cost zero outbound requests. Only a token that has already survived those checks is
 * worth asking the issuer about.
 */

import { canonicalizeDelegate, DelegateIdentifierError } from './delegate.js';
import {
  DEFAULT_MAX_JWKS_AGE_MS,
  isSupportedAlgorithm,
  MAX_JWKS_AGE_CAP_MS,
  resolveVerificationKeys,
  verifyWithCandidates,
} from './jwks.js';
import type { KeySetOptions } from './jwks.js';
import { parseJwt } from './jwt.js';
import { checkDelegationStatus } from './status.js';
import { classifyFailureReason } from './types.js';
import type {
  FailureReason,
  FetchLike,
  KeySetStore,
  TrustedIssuer,
  VerificationFailure,
  VerificationResult,
  VerifyOptions,
} from './types.js';

/** Delegation token schema versions this verifier understands (major-compatible). */
const SUPPORTED_SCHEMA_MAJOR = '1';

const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;
const DEFAULT_TIMEOUT_MS = 5_000;

function fail(
  reason: FailureReason,
  message: string,
  extra: Pick<VerificationFailure, 'pullHint' | 'cacheAgeSeconds' | 'refreshHint'> = {}
): VerificationResult {
  return { valid: false, reason, outcome: classifyFailureReason(reason), message, ...extra };
}

function findTrustedIssuer(issuers: TrustedIssuer[], iss: unknown): TrustedIssuer | undefined {
  if (typeof iss !== 'string' || iss.length === 0) return undefined;
  return issuers.find((candidate) => candidate.issuer === iss);
}

function isHttpsUrl(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * A trust entry must be usable AND safe. Every URL it contributes is checked for https, not
 * just the JWKS: `statusEndpoint` receives the whole delegation token in a POST body, and both
 * it and `statusListOrigins` widen the set of origins a token may point the verifier at.
 */
function isValidIssuerEntry(entry: unknown): entry is TrustedIssuer {
  if (typeof entry !== 'object' || entry === null) return false;
  const candidate = entry as Partial<TrustedIssuer>;
  if (typeof candidate.issuer !== 'string' || candidate.issuer.length === 0) return false;
  if (!isHttpsUrl(candidate.jwksUri)) return false;
  if (candidate.statusEndpoint !== undefined && !isHttpsUrl(candidate.statusEndpoint)) return false;
  if (candidate.statusListOrigins !== undefined) {
    if (!Array.isArray(candidate.statusListOrigins)) return false;
    if (!candidate.statusListOrigins.every(isHttpsUrl)) return false;
  }
  return true;
}

function normalizePrincipal(value: string): string {
  return value.trim().toLowerCase();
}

export async function verifyDelegation(token: string, options: VerifyOptions): Promise<VerificationResult> {
  // ---------------------------------------------------------------- call-shape checks
  if (!options || typeof options !== 'object') {
    return fail('invalid_options', 'options are required');
  }
  if (!options.delegate) {
    return fail(
      'invalid_options',
      'delegate is required: the verifier compares the token against the artifact identity YOU resolved, never against what the card says about itself'
    );
  }

  let expectedDelegate: string;
  try {
    expectedDelegate = canonicalizeDelegate(options.delegate);
  } catch (error) {
    return fail(
      'invalid_options',
      error instanceof DelegateIdentifierError ? error.message : 'delegate could not be canonicalized'
    );
  }

  // Compared as exact strings, deliberately NOT through the issuer-side scope canonicalizer:
  // scope grammar is the issuer's, and running another issuer's `mcp:tools/call` through
  // proof.holdings' kebab-case rules would make the requirement unaskable rather than merely
  // over-constrained.
  let requiredScopes: string[] = [];
  if (options.requiredScopes !== undefined) {
    if (!Array.isArray(options.requiredScopes) || options.requiredScopes.some((entry) => typeof entry !== 'string')) {
      return fail('invalid_options', 'requiredScopes must be an array of strings');
    }
    requiredScopes = options.requiredScopes.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  }

  // Validated like every other option rather than trusted: this is the pin that closes the
  // sibling attack, and a non-string reaching `normalizePrincipal` would throw out of a
  // function whose whole contract is to RETURN a discriminated result — worst on the untyped
  // consumers this package is aimed at.
  if (options.expectedPrincipal !== undefined) {
    if (typeof options.expectedPrincipal !== 'string' || options.expectedPrincipal.trim().length === 0) {
      return fail('invalid_options', 'expectedPrincipal must be a non-empty string when supplied');
    }
  }

  if (options.maxJwksAgeMs !== undefined) {
    const age = options.maxJwksAgeMs;
    if (typeof age !== 'number' || !Number.isInteger(age) || age <= 0 || age > MAX_JWKS_AGE_CAP_MS) {
      return fail(
        'invalid_options',
        `maxJwksAgeMs must be a whole number of milliseconds from 1 to ${MAX_JWKS_AGE_CAP_MS} (25 days)`
      );
    }
  }
  if (options.keySetStore !== undefined) {
    const store = options.keySetStore as Partial<KeySetStore> | null;
    if (!store || typeof store.load !== 'function' || typeof store.save !== 'function') {
      return fail('invalid_options', 'keySetStore must provide load(jwksUri) and save(jwksUri, state)');
    }
  }
  if (options.onJwksEvent !== undefined && typeof options.onJwksEvent !== 'function') {
    return fail('invalid_options', 'onJwksEvent must be a function');
  }

  const issuers = Array.isArray(options.trustedIssuers) ? options.trustedIssuers.filter(isValidIssuerEntry) : [];
  if (issuers.length === 0) {
    return fail(
      'no_trust_policy',
      'trustedIssuers is empty: this verifier has no built-in trust list, so the caller must name the issuers it accepts (each with an https jwksUri)'
    );
  }

  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const clockToleranceSeconds = options.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;
  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);

  // ---------------------------------------------------------------- structural parse
  const parsed = parseJwt(token);
  if (!parsed) return fail('malformed_token', 'token is not a decodable three-part JWT');

  const issuer = findTrustedIssuer(issuers, parsed.payload.iss);
  if (!issuer) {
    return fail(
      'untrusted_issuer',
      `token issuer ${JSON.stringify(parsed.payload.iss)} is not in the supplied trust policy`
    );
  }

  const alg = parsed.header.alg;
  if (!isSupportedAlgorithm(alg)) {
    // The algorithm is chosen by the verifier, not by the token — `none` and HMAC forgeries
    // die here, before any key is fetched.
    return fail('unsupported_algorithm', `token algorithm ${JSON.stringify(alg)} is not accepted`);
  }

  // ---------------------------------------------------------------- claims (pre-network)
  const claims = parsed.payload;
  if (claims.token_type !== 'delegation') {
    return fail('not_a_delegation', `token_type must be "delegation", got ${JSON.stringify(claims.token_type)}`);
  }

  const schemaVersion = claims.delegation_schema_version;
  if (typeof schemaVersion !== 'string' || schemaVersion.split('.')[0] !== SUPPORTED_SCHEMA_MAJOR) {
    return fail(
      'unsupported_schema',
      `delegation_schema_version ${JSON.stringify(schemaVersion)} is not supported (this verifier understands ${SUPPORTED_SCHEMA_MAJOR}.x)`
    );
  }

  const { sub, principal, delegate, control_proof: controlProof, scope, iat, exp } = claims;
  if (
    typeof sub !== 'string' ||
    sub.length === 0 ||
    typeof principal !== 'string' ||
    principal.length === 0 ||
    typeof delegate !== 'string' ||
    delegate.length === 0 ||
    typeof controlProof !== 'string' ||
    controlProof.length === 0 ||
    !Array.isArray(scope) ||
    scope.length === 0 ||
    scope.some((entry) => typeof entry !== 'string') ||
    typeof iat !== 'number' ||
    typeof exp !== 'number'
  ) {
    return fail('malformed_claims', 'token is missing one of sub / principal / delegate / control_proof / scope / iat / exp');
  }

  if (nowSeconds > exp + clockToleranceSeconds) {
    return fail('expired', 'delegation expired');
  }
  if (nowSeconds + clockToleranceSeconds < iat) {
    return fail('not_yet_valid', 'delegation is not valid yet (iat is in the future)');
  }

  if (options.expectedPrincipal !== undefined) {
    if (normalizePrincipal(principal) !== normalizePrincipal(options.expectedPrincipal)) {
      return fail(
        'principal_mismatch',
        `delegation was issued by ${JSON.stringify(principal)}, not ${JSON.stringify(options.expectedPrincipal)}`
      );
    }
  }

  // Requirement (a) of the design: the token is a bearer artifact, so this comparison — against
  // an identity the CALLER resolved — is what stops a genuine token being copied into another
  // package's card.
  if (delegate !== expectedDelegate) {
    return fail(
      'delegate_mismatch',
      `delegation attests ${JSON.stringify(delegate)}, but the artifact you resolved is ${JSON.stringify(expectedDelegate)}`
    );
  }

  const grantedScopes = scope as string[];
  const grantedTrimmed = grantedScopes.map((entry) => entry.trim());
  const missing = requiredScopes.filter((required) => !grantedTrimmed.includes(required));
  if (missing.length > 0) {
    return fail('scope_not_granted', `delegation does not grant: ${missing.join(', ')}`);
  }

  // ---------------------------------------------------------------- signature
  const keySetOptions: KeySetOptions = {
    maxJwksAgeMs: options.maxJwksAgeMs ?? DEFAULT_MAX_JWKS_AGE_MS,
    keySetStore: options.keySetStore,
    onJwksEvent: options.onJwksEvent,
  };
  const resolution = await resolveVerificationKeys({
    jwksUri: issuer.jwksUri,
    kid: typeof parsed.header.kid === 'string' ? parsed.header.kid : undefined,
    alg,
    family: 'delegation',
    fetch: fetchImpl,
    timeoutMs,
    ...keySetOptions,
  });
  switch (resolution.kind) {
    case 'unavailable':
      // "I could not check" is not "the token is bad" — it gets its own reason.
      return fail('jwks_unavailable', resolution.message);
    case 'stale':
      return fail(
        'jwks_stale',
        `the issuer JWKS could not be refetched and the cached copy is older than maxJwksAgeMs (${keySetOptions.maxJwksAgeMs} ms)`,
        { cacheAgeSeconds: resolution.cacheAgeSeconds, refreshHint: { jwksUri: issuer.jwksUri, method: 'refreshJwks' } }
      );
    case 'revoked':
      // Decided before the signature: the key is revoked, whoever signed with it.
      return fail('key_revoked', `the issuer revoked signing key "${resolution.kid}"`, {
        pullHint: { issuerOrigin: new URL(issuer.jwksUri).origin, handle: sub },
      });
    case 'wrong_purpose':
      return fail('wrong_key_purpose', `signing key "${resolution.kid}" is not a delegation key`);
    case 'unknown':
      return fail('unknown_key', 'no key in the issuer JWKS matches this token');
    case 'keys':
      break;
  }

  const verdict = await verifyWithCandidates(resolution, alg, parsed.signingInput, parsed.signature, { iat, exp });
  if (verdict === 'bad_signature') return fail('bad_signature', 'token signature is invalid');
  if (verdict === 'outside_key_window') {
    return fail('outside_key_window', "token iat lies outside the signing key's window");
  }
  if (verdict === 'token_lifetime_exceeded') {
    return fail('token_lifetime_exceeded', "token exp lies beyond iat plus the signing key's max_token_lifetime");
  }

  const delegation = {
    issuer: issuer.issuer,
    principal,
    delegate,
    scope: grantedScopes,
    controlProof,
    delegationId: sub,
    issuedAt: new Date(iat * 1000),
    expiresAt: new Date(exp * 1000),
  };
  // See `VerificationSuccess.principalChecked`: an issuer binds `delegate` to nothing, so a
  // delegation naming someone else's artifact is a normal thing for any domain to mint. The
  // caller is told whether that half of the question was asked.
  const principalChecked = options.expectedPrincipal !== undefined;

  // ---------------------------------------------------------------- status
  if (options.statusCheck === 'skip') {
    return { valid: true, statusChecked: false, principalChecked, delegation };
  }

  const status = await checkDelegationStatus({
    token,
    claims,
    issuer,
    fetch: fetchImpl,
    timeoutMs,
    now,
    clockToleranceSeconds,
    keySetOptions,
  });

  switch (status.state) {
    case 'valid':
      return { valid: true, statusChecked: true, principalChecked, delegation };
    case 'revoked':
      return fail('revoked', status.message);
    case 'suspended':
      return fail('suspended', status.message);
    case 'expired':
      return fail('expired', status.message);
    case 'unknown':
      return fail('unknown_delegation', status.message);
    case 'untrusted_uri':
      return fail('status_uri_untrusted', status.message);
    case 'unavailable':
      // Fail CLOSED: an unchecked revocation channel is not evidence of validity.
      return fail('status_unavailable', status.message);
  }
}
