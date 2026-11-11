/**
 * Public types of the Proof of Delegation reference verifier.
 *
 * The library verifies a delegation token — an attestation that the domain in `principal`
 * authorized the artifact in `delegate`. It attests NOTHING
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

/**
 * Where the verifier persists a key set between processes, so an applied tombstone survives a
 * restart (and a serverless cold start). Supplied by the caller — this package has no storage of
 * its own. `state` is an opaque string. A failing store never fails a verification.
 */
export interface KeySetStore {
  load(jwksUri: string): Promise<string | null | undefined> | string | null | undefined;
  save(jwksUri: string, state: string): Promise<void> | void;
}

export type JwksEventType =
  /** A tombstone was seen for the first time and is waiting for a confirming fetch. */
  | 'tombstone_pending'
  /** A second fetch at least 5 minutes later confirmed the tombstone. */
  | 'tombstone_applied'
  /** Anomaly: the tombstone names a key last seen live. Applied by the same rule. */
  | 'tombstone_for_live_key'
  /** A JWKS narrowed a confirmed key's window; applied only if a fetch 5+ minutes later agrees. */
  | 'window_narrowing_pending'
  /** A second fetch at least 5 minutes later served the same narrowed window; it now applies. */
  | 'window_narrowing_applied'
  /** A JWKS moved a confirmed key's window wider and was refused whole. */
  | 'window_widening_rejected'
  /** A JWKS served new key material under a confirmed kid; the first-seen key is kept. */
  | 'key_material_changed'
  /** A confirmed registry key stopped being served before its retention ended. */
  | 'kid_vanished'
  /** The caller's `keySetStore` failed to load or save. */
  | 'store_error';

export interface JwksEvent {
  type: JwksEventType;
  jwksUri: string;
  kid?: string;
  message: string;
}

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
  /** Per-request network timeout in ms, also bounding each `keySetStore` call. Default 5000. */
  timeoutMs?: number;
  /**
   * How old a cached key set may be when a refetch FAILS. Under the bound the verifier keeps
   * using the cache's confirmed keys; over it, the answer is `jwks_stale`. A healthy issuer is still refetched
   * every 10 minutes. Default 24h. Above 25 days is `invalid_options`: the issuer publishes its
   * next key about 30 days ahead, and a cache older than that can miss it.
   */
  maxJwksAgeMs?: number;
  /** Persist the key set (tombstones included) across processes. */
  keySetStore?: KeySetStore;
  /** Receives key-set anomalies and tombstone progress. Default: ignored. */
  onJwksEvent?: (event: JwksEvent) => void;
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
  /** The issuer revoked the signing key (an applied JWKS tombstone). Carries `pullHint`. */
  | 'key_revoked'
  /** A refetch failed and the cached key set is older than `maxJwksAgeMs`. */
  | 'jwks_stale'
  /** The signing key belongs to another key family than this token. */
  | 'wrong_key_purpose'
  /** The token's `iat` lies outside the signing key's window (5 minutes of skew allowed). */
  | 'outside_key_window'
  /** `exp` lies beyond `iat` plus the signing key's `max_token_lifetime`. */
  | 'token_lifetime_exceeded'
  | 'not_a_delegation'
  /** The token's `delegation_schema_version` major is not 2 (a 1.x token carries `scope`). */
  | 'unsupported_version'
  | 'expired'
  | 'not_yet_valid'
  | 'malformed_claims'
  | 'principal_mismatch'
  /** The token attests some OTHER artifact than the one the caller resolved. */
  | 'delegate_mismatch'
  /** The status-list uri in the token does not belong to the trusted issuer. */
  | 'status_uri_untrusted'
  | 'status_unavailable'
  | 'revoked'
  | 'suspended'
  /** The issuer has no record of this delegation — distinct from "it could not answer". */
  | 'unknown_delegation'
  /** The issuer reports the delegation (or, for `verifyProofToken`, the proof) was issued in test mode — a refusal, not "could not check". */
  | 'test_environment'
  /** Card carries no delegation publication. */
  | 'no_publication'
  /** Card carries several publications — ambiguous, refused rather than guessed. */
  | 'multiple_publications';

export type FailureOutcome = 'invalid' | 'unconfirmed';

const UNCONFIRMED_REASONS: ReadonlySet<FailureReason> = new Set([
  'status_unavailable',
  'jwks_unavailable',
  'jwks_stale',
  'status_uri_untrusted',
]);

/**
 * Whether a `FailureReason` means "checked, and it's bad" (`invalid`) or "could not check"
 * (`unconfirmed`). The reasons in `UNCONFIRMED_REASONS` mean the key or revocation check itself
 * could not run, and are `unconfirmed`; every other reason is a completed check with a negative verdict,
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
  /** Public handle of the domain control proof underneath this delegation. */
  controlProof: string;
  /** Public handle of the delegation itself (`ph_dlg_*` for proof.holdings). */
  delegationId: string;
  issuedAt: Date;
  expiresAt: Date;
  /**
   * Where the issuer serves the CURRENT version of this delegation's token (the token's `renewal_url`
   * claim), so a copy that has expired can be followed to its renewal. Present only when it is https
   * and on the trusted issuer's own origin — the origin of its `jwksUri` or `statusEndpoint`, or one
   * of its `statusListOrigins`, the rule the status-list uri follows — so a token can never send a
   * verifier to a host it names itself. Never fetched here: fetch it, then verify what it serves with
   * `verifyDelegation` and `isRenewalOf`. `null` when the token carries none or it was refused.
   */
  renewalUrl: string | null;
  /** Why a `renewal_url` the token carried was refused; absent when it was accepted or there was none. */
  renewalUrlRejected?: RenewalUrlRejection;
}

/** `not_https`: another scheme. `off_origin`: not an origin of the trusted issuer. `malformed`: not a URL, or one
 * with userinfo, a backslash, whitespace or a non-printable-ASCII character (strings URL parsers disagree on). */
export type RenewalUrlRejection = 'not_https' | 'off_origin' | 'malformed';

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
  /**
   * `key_revoked` only: where a re-signed token can be fetched — the trusted issuer's origin and
   * the token's own handle. The handle is read from a token whose signature was NOT checked (its
   * key is revoked), so treat it as an address to ask, never as a verified identity.
   */
  pullHint?: { issuerOrigin: string; handle: string };
  /** `jwks_stale` only: age of the cached key set in seconds, or null when unknown. */
  cacheAgeSeconds?: number | null;
  /** `jwks_stale` only: what to refetch, and the exported function that does it. */
  refreshHint?: { jwksUri: string; method: 'refreshJwks' };
  /**
   * `expired` only: the token's `renewal_url`, under the rule `VerifiedDelegation.renewalUrl` states —
   * an expired copy is the case the claim exists for. Read from claims whose signature is not checked
   * at this point, which the origin rule makes safe: it can only name the trusted issuer, and whatever
   * it serves is verified in full. `null` when the token carries none or it was refused.
   */
  renewalUrl?: string | null;
  /** `expired` only: why a `renewal_url` the token carried was refused. */
  renewalUrlRejected?: RenewalUrlRejection;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;

/**
 * Proof tokens (`verifyProofToken`): the issuer's OTHER token family — a statement that the holder
 * of an identifier (a domain, an email, a handle…) proved control of it. Same keys document, its own
 * key family (`proof`), and it never carries the identifier itself: `identifier_hash` is the SHA-256
 * of its canonical form. So the caller supplies that canonical form, exactly as `delegate` is
 * supplied for a delegation — the token is a bearer artifact, and the comparison against what the
 * CALLER expects is what stops a genuine token being shown beside someone else's identifier.
 */
export interface ProofExpectation {
  /** The proof type the token must carry in its `type` claim, e.g. `domain`, `email`, `social`. */
  type: string;
  /**
   * The identifier in the issuer's canonical form (proof.holdings: a domain lowercased without
   * `www.`, an email lowercased, a phone in E.164, a handle lowercased without `@`). Hashed with
   * SHA-256 and compared to `identifier_hash`; this package does not canonicalize, so a value in
   * another form answers `identifier_mismatch`.
   */
  identifier: string;
}

export interface ProofVerifyOptions extends Omit<VerifyOptions, 'delegate' | 'expectedPrincipal'> {
  /** REQUIRED. What the caller expects this proof to be about. */
  expected: ProofExpectation;
}

export type ProofFailureReason =
  | FailureReason
  /** The token is not a proof token (it carries `token_type`, e.g. a delegation). */
  | 'not_a_proof'
  /** The token proves another type of identifier than the one expected. */
  | 'proof_type_mismatch'
  /** The token is about another identifier than the one expected. */
  | 'identifier_mismatch'
  /** The issuer has re-issued this proof; the token shown is no longer the current one. */
  | 'superseded';

export interface VerifiedProof {
  issuer: string;
  /** The stable public handle of the proof, when the token carries one. */
  proofId: string | null;
  type: string;
  /** How control was shown (e.g. `dns`, `x`, `ethereum`), as the token says; null when absent. */
  channel: string | null;
  identifierHash: string;
  verifiedAt: Date | null;
  issuedAt: Date;
  expiresAt: Date;
}

export interface ProofVerificationSuccess {
  valid: true;
  /** False only when `statusCheck: 'skip'` was requested. */
  statusChecked: boolean;
  proof: VerifiedProof;
}

export interface ProofVerificationFailure extends Omit<VerificationFailure, 'reason'> {
  reason: ProofFailureReason;
}

export type ProofVerificationResult = ProofVerificationSuccess | ProofVerificationFailure;
