/**
 * `verifyProofToken` — the issuer's other token family: a proof that the holder of an identifier
 * (a domain, an email, a handle…) showed control of it. Same order as `verifyDelegation`: everything
 * decidable without the network first — trust policy, algorithm, claims, the expected type and the
 * expected identifier — so a token about someone else's value costs zero requests; then the
 * signature under the `proof` key family; then status (list first, endpoint when the list cannot say).
 *
 * The token never carries the identifier, only `identifier_hash` (SHA-256 of its canonical form), so
 * the caller states the identifier it expects — the same rule as `delegate`: a proof token is a bearer
 * artifact, and only the comparison against what the CALLER expects stops a genuine token being shown
 * beside another value. This package does not canonicalize identifiers (a phone needs a numbering-plan
 * library, and this package takes no dependencies): what is hashed is exactly what is passed.
 */

import { isSupportedAlgorithm, DEFAULT_MAX_JWKS_AGE_MS } from './jwks.js';
import type { KeySetOptions } from './jwks.js';
import { parseJwt } from './jwt.js';
import { checkDelegationStatus } from './status.js';
import { classifyFailureReason } from './types.js';
import type {
  FailureOutcome,
  FetchLike,
  ProofFailureReason,
  ProofVerificationFailure,
  ProofVerificationResult,
  ProofVerifyOptions,
  VerificationFailure,
} from './types.js';
import {
  checkTokenSignature,
  DEFAULT_CLOCK_TOLERANCE_SECONDS,
  DEFAULT_TIMEOUT_MS,
  findTrustedIssuer,
  isValidIssuerEntry,
  keySetOptionsProblem,
  NO_TRUST_POLICY_MESSAGE,
} from './verify.js';

const PROOF_ONLY_REASONS: ReadonlySet<ProofFailureReason> = new Set([
  'not_a_proof',
  'proof_type_mismatch',
  'identifier_mismatch',
  'superseded',
]);

function outcomeOf(reason: ProofFailureReason): FailureOutcome {
  // The four proof-only reasons are completed checks with a negative answer.
  return PROOF_ONLY_REASONS.has(reason) ? 'invalid' : classifyFailureReason(reason as VerificationFailure['reason']);
}

function fail(reason: ProofFailureReason, message: string, extra: Partial<ProofVerificationFailure> = {}): ProofVerificationFailure {
  return { ...extra, valid: false, reason, outcome: outcomeOf(reason), message };
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function verifyProofToken(token: string, options: ProofVerifyOptions): Promise<ProofVerificationResult> {
  // ---------------------------------------------------------------- call-shape checks
  if (!options || typeof options !== 'object') return fail('invalid_options', 'options are required');
  const expected = options.expected as Partial<ProofVerifyOptions['expected']> | undefined;
  if (
    !expected ||
    typeof expected.type !== 'string' ||
    expected.type.length === 0 ||
    typeof expected.identifier !== 'string' ||
    expected.identifier.length === 0
  ) {
    return fail(
      'invalid_options',
      'expected { type, identifier } is required: the verifier compares the token against the value YOU expect, never against nothing'
    );
  }
  const keySetProblem = keySetOptionsProblem(options);
  if (keySetProblem) return fail('invalid_options', keySetProblem);

  const issuers = Array.isArray(options.trustedIssuers) ? options.trustedIssuers.filter(isValidIssuerEntry) : [];
  if (issuers.length === 0) return fail('no_trust_policy', NO_TRUST_POLICY_MESSAGE);

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
    return fail('untrusted_issuer', `token issuer ${JSON.stringify(parsed.payload.iss)} is not in the supplied trust policy`);
  }
  const alg = parsed.header.alg;
  if (!isSupportedAlgorithm(alg)) {
    return fail('unsupported_algorithm', `token algorithm ${JSON.stringify(alg)} is not accepted`);
  }

  // ---------------------------------------------------------------- claims (pre-network)
  const claims = parsed.payload;
  // A proof token carries no `token_type`; every other family this issuer signs does.
  if (claims.token_type !== undefined) {
    return fail('not_a_proof', `a proof token carries no token_type, got ${JSON.stringify(claims.token_type)}`);
  }
  const { sub, type, identifier_hash: identifierHash, iat, exp } = claims;
  if (
    typeof sub !== 'string' ||
    sub.length === 0 ||
    typeof type !== 'string' ||
    typeof identifierHash !== 'string' ||
    typeof iat !== 'number' ||
    typeof exp !== 'number'
  ) {
    return fail('malformed_claims', 'token is missing one of sub / type / identifier_hash / iat / exp');
  }
  if (nowSeconds > exp + clockToleranceSeconds) return fail('expired', 'proof expired');
  if (nowSeconds + clockToleranceSeconds < iat) return fail('not_yet_valid', 'proof is not valid yet (iat is in the future)');

  if (type !== expected.type) {
    return fail('proof_type_mismatch', `the token proves a ${JSON.stringify(type)}, not a ${JSON.stringify(expected.type)}`);
  }
  if (identifierHash !== (await sha256Hex(expected.identifier))) {
    return fail('identifier_mismatch', `the token is not about ${JSON.stringify(expected.identifier)}`);
  }

  // ---------------------------------------------------------------- signature
  const keySetOptions: KeySetOptions = {
    maxJwksAgeMs: options.maxJwksAgeMs ?? DEFAULT_MAX_JWKS_AGE_MS,
    keySetStore: options.keySetStore,
    onJwksEvent: options.onJwksEvent,
  };
  const proofId = typeof claims.proof_id === 'string' ? claims.proof_id : null;
  const signatureFailure = await checkTokenSignature({
    parsed,
    alg,
    issuer,
    family: 'proof',
    handle: proofId ?? sub,
    iat,
    exp,
    fetch: fetchImpl,
    timeoutMs,
    keySetOptions,
  });
  if (signatureFailure) return signatureFailure;

  const verifiedAt = typeof claims.verified_at === 'string' ? new Date(claims.verified_at) : null;
  const proof = {
    issuer: issuer.issuer,
    proofId,
    type,
    channel: typeof claims.channel === 'string' ? claims.channel : null,
    identifierHash,
    verifiedAt: verifiedAt && !Number.isNaN(verifiedAt.getTime()) ? verifiedAt : null,
    issuedAt: new Date(iat * 1000),
    expiresAt: new Date(exp * 1000),
  };

  // ---------------------------------------------------------------- status
  if (options.statusCheck === 'skip') return { valid: true, statusChecked: false, proof };

  const status = await checkDelegationStatus({
    token,
    claims,
    issuer,
    fetch: fetchImpl,
    timeoutMs,
    now,
    clockToleranceSeconds,
    keySetOptions,
    subject: 'proof',
  });
  switch (status.state) {
    case 'valid':
      return { valid: true, statusChecked: true, proof };
    case 'revoked':
      return fail('revoked', status.message);
    case 'suspended':
      return fail('suspended', status.message);
    case 'expired':
      return fail('expired', status.message);
    case 'superseded':
      return fail('superseded', status.message);
    case 'test_environment':
      return fail('test_environment', status.message);
    case 'unknown':
      // "No record" is the issuer's delegation answer; for a proof it is not a stated withdrawal,
      // so it fails closed as unconfirmed rather than being reported as revoked.
      return fail('status_unavailable', status.message);
    case 'untrusted_uri':
      return fail('status_uri_untrusted', status.message);
    case 'unavailable':
      return fail('status_unavailable', status.message);
  }
}
