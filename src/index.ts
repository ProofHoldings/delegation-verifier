/**
 * @proof-holdings/delegation-verifier — issuer-agnostic verification of Proof of Delegation.
 *
 * A delegation says: the domain in `principal` authorized the artifact in `delegate`, and the
 * issuer checked that domain's control at issuance. It says nothing
 * about whether the artifact is safe, audited, or any good.
 *
 * ```ts
 * const result = await verifyPublishedDelegation(serverCard, {
 *   trustedIssuers: [{
 *     issuer: 'proof.holdings',
 *     jwksUri: 'https://api.proof.holdings/.well-known/jwks.json',
 *     statusEndpoint: 'https://api.proof.holdings/api/v1/proofs/validate',
 *   }],
 *   delegate: { type: 'purl', value: 'pkg:npm/postmark-mcp' }, // what YOU are installing
 *   expectedPrincipal: 'postmarkapp.com',
 * });
 * ```
 */

export { verifyDelegation } from './verify.js';
/** Proof tokens — the issuer's other family: control of a domain, an email, a handle… */
export { verifyProofToken } from './proof.js';
export {
  verifyPublishedDelegation,
  extractDelegationPublications,
  DELEGATION_META_KEY,
  DELEGATION_EXTENSION_URI,
  REGISTRY_PUBLISHER_PROVIDED_KEY,
} from './publication.js';
export type { FoundPublication } from './publication.js';
/**
 * The fourth carrier: a `_mcp.<domain>` TXT record naming the card that holds the publication.
 * Only the PARSE half is here — resolving it means a DNS query and a card fetch, and this package
 * is dependency-free on purpose. A consumer does the lookup with whatever resolver it already has
 * and hands the TXT values in.
 */
export {
  parseDelegationPointer,
  pointerRecordName,
  POINTER_VERSION,
  POINTER_RECORD_PREFIX,
} from './publication.js';
export type { PointerParseResult, PointerRejection } from './publication.js';
export {
  canonicalizeDelegate,
  delegateMatches,
  DelegateIdentifierError,
  DELEGATE_TYPES,
  DELEGATE_MAX_LENGTH,
} from './delegate.js';
export {
  clearTombstones,
  DEFAULT_MAX_JWKS_AGE_MS,
  getJwksDiagnostics,
  MAX_JWKS_AGE_CAP_MS,
  refreshJwks,
  resetJwksCache,
  SUPPORTED_ALGORITHMS,
} from './jwks.js';
export type { JwksDiagnostics, SupportedAlgorithm } from './jwks.js';
export { readStatusSlot } from './status.js';
/**
 * Renewal: is a token the issuer serves now a renewal of the expired one you found? Claims only — fetch
 * the candidate yourself, then verify it with `verifyDelegation` against the same trusted issuer.
 */
export { isRenewalOf, renewalVerdict, RENEWAL_CLOCK_TOLERANCE_SECONDS } from './renewal.js';
export type { RenewalCheck, RenewalRejection, RenewalToken } from './renewal.js';
export { classifyFailureReason } from './types.js';
export type {
  DelegateInput,
  DelegateType,
  FailureOutcome,
  FailureReason,
  ProofExpectation,
  ProofFailureReason,
  ProofVerificationFailure,
  ProofVerificationResult,
  ProofVerificationSuccess,
  ProofVerifyOptions,
  VerifiedProof,
  FetchLike,
  JwksEvent,
  JwksEventType,
  KeySetStore,
  TrustedIssuer,
  VerificationFailure,
  VerificationResult,
  VerificationSuccess,
  VerifiedDelegation,
  VerifyOptions,
} from './types.js';
