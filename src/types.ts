/**
 * Public types of the Proof of Delegation reference verifier.
 *
 * The library verifies a delegation token — an attestation that the domain in `principal`
 * authorized the artifact in `delegate` for a set of capability scopes. It attests NOTHING
 * about the artifact's quality, safety or the business behind it, and it is not a statement
 * that anyone "verified" the server.
 *
 * Two design rules separate this from an SDK, and both are load-bearing:
 *
 *   1. There is NO default trust list. `trustedIssuers` is supplied by the caller on every
 *      call — a verifier that trusts an issuer because the library shipped with its name
 *      hard-coded is a client for that issuer, not a verifier.
 *   2. `delegate` is REQUIRED. The token is a bearer artifact: anyone can copy a genuine
 *      token into their own package. The comparison that defeats that is against the artifact
 *      identity the CALLER resolved independently — never against what the card says about
 *      itself.
 */

/** A typed artifact identifier, canonicalized before comparison. */
export type DelegateType = 'url' | 'purl';

export interface DelegateInput {
  type: DelegateType;
  /** e.g. `pkg:npm/postmark-mcp` or `https://api.example.com/mcp` */
  value: string;
}

/**
 * One entry of the caller's trust policy.
 *
 * `statusEndpoint` is what lets the verifier see a revocation that a status list cannot show.
 * An issuer's status list carries one bit per proof, so it reports the delegation's OWN
 * revocation — but a delegation is only worth the domain control proof underneath it, and
 * that cascade is resolved by the issuer, not encoded in the delegation's own bit. The
 * endpoint contract is deliberately minimal: `POST` with `{"proof_token": "<jwt>"}` and a
 * JSON answer carrying at least `{"valid": boolean}` (optionally `reason`).
 */
export interface TrustedIssuer {
  /** Exact value the token's `iss` claim must equal. */
  issuer: string;
  /** Absolute https URL of the issuer's JWKS. */
  jwksUri: string;
  /** Absolute https URL of the issuer's public token-status endpoint. */
  statusEndpoint?: string;
  /**
   * Extra origins this issuer may serve its status list from. The origins of `jwksUri` and
   * `statusEndpoint` are always allowed; anything else must be listed here or the status-list
   * uri inside the token is refused WITHOUT being fetched.
   */
  statusListOrigins?: string[];
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface VerifyOptions {
  /** REQUIRED, no default. An empty list fails closed with `no_trust_policy`. */
  trustedIssuers: TrustedIssuer[];
  /** REQUIRED. The artifact identity the caller resolved independently. */
  delegate: DelegateInput;
  /**
   * The domain you expect to have authorized this artifact. Optional in the type, but omitting
   * it downgrades the answer — see `VerificationSuccess.principalChecked`. Compared after
   * trimming and lowercasing.
   */
  expectedPrincipal?: string;
  /**
   * Scopes the delegation must grant. Compared as EXACT strings against the token's own
   * `scope` (trimmed only): scope grammar belongs to the issuer, and imposing one issuer's
   * rules here would make another issuer's grants unaskable.
   */
  requiredScopes?: string[];
  /**
   * `required` (default) — the delegation's status list is checked, and the issuer's status
   * endpoint is asked too whenever the list cannot answer on its own (see `status.ts` for
   * exactly when); anything unreachable fails closed with `status_unavailable`. There is no
   * option to tolerate a transient `status_unavailable` — a caller wanting a grace window
   * around a flaky issuer must implement that itself (e.g. retry, or branch on `outcome:
   * 'unconfirmed'`); this library does not offer a built-in one.
   * `skip` — signature and claims only; the result carries `statusChecked: false`, which a
   * caller must treat as "revocation not checked", never as "not revoked".
   */
  statusCheck?: 'required' | 'skip';
  /** Seconds of leeway on `exp`/`iat`. Default 5. */
  clockToleranceSeconds?: number;
  /** Verification time; defaults to now. */
  now?: Date;
  /** Injected fetch (tests, proxies, non-Node runtimes). Defaults to global fetch. */
  fetch?: FetchLike;
  /** Per-request network timeout in ms. Default 5000. */
  timeoutMs?: number;
}

export type FailureReason =
  /** The call itself is wrong (missing `delegate`, malformed trust entry). */
  | 'invalid_options'
  /** `trustedIssuers` was empty — the library has no default trust. */
  | 'no_trust_policy'
  | 'malformed_token'
  | 'untrusted_issuer'
  | 'unsupported_algorithm'
  | 'unknown_key'
  | 'bad_signature'
  | 'jwks_unavailable'
  | 'not_a_delegation'
  | 'unsupported_schema'
  | 'expired'
  | 'not_yet_valid'
  | 'malformed_claims'
  | 'principal_mismatch'
  /** The token attests some OTHER artifact than the one the caller resolved. */
  | 'delegate_mismatch'
  | 'scope_not_granted'
  /** The status-list uri in the token does not belong to the trusted issuer. */
  | 'status_uri_untrusted'
  | 'status_unavailable'
  | 'revoked'
  | 'suspended'
  /** The issuer has no record of this delegation — distinct from "it could not answer". */
  | 'unknown_delegation'
  /** Card carries no delegation publication. */
  | 'no_publication'
  /** Card carries several publications — ambiguous, refused rather than guessed. */
  | 'multiple_publications';

export type FailureOutcome = 'invalid' | 'unconfirmed';

const UNCONFIRMED_REASONS: ReadonlySet<FailureReason> = new Set([
  'status_unavailable',
  'jwks_unavailable',
  'status_uri_untrusted',
]);

/**
 * Whether a `FailureReason` means "checked, and it's bad" (`invalid`) or "could not check"
 * (`unconfirmed`). The three status-channel reasons that mean the revocation check itself
 * failed are `unconfirmed`; every other reason is a completed check with a negative verdict,
 * including a call-shape error — `verifyDelegation` always receives a well-formed
 * `VerifyOptions` in practice, so those are `invalid` for exhaustiveness, not because they
 * occur.
 */
export function classifyFailureReason(reason: FailureReason): FailureOutcome {
  return UNCONFIRMED_REASONS.has(reason) ? 'unconfirmed' : 'invalid';
}

export interface VerifiedDelegation {
  issuer: string;
  /** The domain that authorized the artifact. */
  principal: string;
  /** Canonical artifact identifier, byte-equal to what the caller resolved. */
  delegate: string;
  scope: string[];
  /** Public handle of the domain control proof underneath this delegation. */
  controlProof: string;
  /** Public handle of the delegation itself (`ph_dlg_*` for proof.holdings). */
  delegationId: string;
  issuedAt: Date;
  expiresAt: Date;
}

export interface VerificationSuccess {
  valid: true;
  /** False only when `statusCheck: 'skip'` was requested. */
  statusChecked: boolean;
  /**
   * False when no `expectedPrincipal` was supplied — and then `valid: true` means LESS than it
   * looks like. An issuer binds `delegate` to nothing: the domain in `principal` is whatever
   * the requester proved control of, and the artifact is free-text they chose. So anyone who
   * can verify `evil.example` can mint a genuine, signature-valid delegation naming SOMEONE
   * ELSE's package. The required `delegate` argument defeats a COPIED token; only pinning
   * `principal` defeats a token minted by the wrong party.
   *
   * A caller that already knows whose artifact this is (an agent installing `postmark-mcp`
   * knows it expects `postmarkapp.com`) must pass `expectedPrincipal`. A caller that is
   * discovering who claims an artifact may legitimately leave it off — and must then present
   * the answer as "X says it authorized this", never as "verified".
   */
  principalChecked: boolean;
  delegation: VerifiedDelegation;
}

export interface VerificationFailure {
  valid: false;
  reason: FailureReason;
  /** `classifyFailureReason(reason)` — set for every failure, never left for the caller to derive. */
  outcome: FailureOutcome;
  message: string;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;
