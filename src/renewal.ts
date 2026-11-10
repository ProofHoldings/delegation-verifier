/**
 * Is a candidate token a RENEWAL of the delegation token found? (m-delegation-publish-registries B.11b)
 *
 * An issuer may renew a delegation in place: the same delegation re-signed with a later `exp`, keeping
 * its handle (`sub`), `jti`, `principal` and `delegate`; the old token stays valid until its own `exp`.
 * A published copy therefore goes stale without being withdrawn. A caller that finds an expired copy can
 * ask the issuer for the delegation's current token and, if this says it is a renewal, verify THAT one.
 *
 * Claims only, and no I/O: like DNS pointer resolution, fetching the current token is the caller's job
 * (proof.holdings serves it at `GET /api/v1/proofs/delegation-token/:handle`). The caller must then run
 * `verifyDelegation(candidate, …)` against the SAME trusted issuer, with the same `delegate` and with
 * `expectedPrincipal` set to the found token's principal — this function never vouches for a signature.
 * One hop only: a candidate is compared with the token found, never with another candidate.
 *
 * The rule is the MCP delegation gate's renewal pickup (`docs/mcp-delegation-gate-contract.md` § 6a, in
 * its order, with its reason names), plus the same `iss` and `principal`, which the gate checks during its
 * signature step. The shared cases in `sdks/shared/fixtures/mcp_delegation_gate/pickup_lineage.json`
 * (`"mode": "renewal"`) pin it, as they pin the three gates and the issuer's claim lookup.
 */

import { parseJwt } from './jwt.js';

/** The contract's `lineage_clock_tolerance_ms`, in seconds. */
export const RENEWAL_CLOCK_TOLERANCE_SECONDS = 5;

/** A token as the rule reads it: its `kid` and its decoded claims. */
export interface RenewalToken {
  kid: string | null;
  token: string;
  claims: Record<string, unknown>;
}

export type RenewalRejection =
  | 'old_token_unreadable'
  | 'same_token'
  | 'malformed_response'
  | 'lineage_sub'
  | 'lineage_jti'
  | 'lineage_delegate'
  | 'iat_before_old'
  | 'iat_in_future'
  | 'exp_not_widened'
  | 'lineage_iss'
  | 'lineage_principal';

export type RenewalCheck = { renewal: true } | { renewal: false; reason: RenewalRejection };

const DELEGATION_HANDLE = /^ph_dlg_[a-f0-9]{32}$/;

interface LineageClaims {
  iss: string;
  sub: string;
  jti: string;
  principal: string;
  delegate: string;
  iat: number;
  exp: number;
}

function lineageClaims(claims: Record<string, unknown>): LineageClaims | null {
  const { iss, sub, jti, principal, delegate, iat, exp } = claims;
  if (
    typeof iss !== 'string' ||
    typeof sub !== 'string' ||
    !DELEGATION_HANDLE.test(sub) ||
    typeof jti !== 'string' ||
    jti.length === 0 ||
    typeof principal !== 'string' ||
    typeof delegate !== 'string' ||
    typeof iat !== 'number' ||
    !Number.isFinite(iat) ||
    typeof exp !== 'number' ||
    !Number.isFinite(exp)
  ) {
    return null;
  }
  return { iss, sub, jti, principal, delegate, iat, exp };
}

/** `'accepted'`, or the first rule `candidate` fails against `found`. */
export function renewalVerdict(found: RenewalToken, candidate: RenewalToken, nowMs: number): 'accepted' | RenewalRejection {
  const before = lineageClaims(found.claims);
  if (!before) return 'old_token_unreadable';
  if (candidate.token === found.token) return 'same_token';
  if (typeof candidate.kid !== 'string' || candidate.kid.length === 0) return 'malformed_response';
  const after = lineageClaims(candidate.claims);
  if (!after) return 'malformed_response';
  if (after.sub !== before.sub) return 'lineage_sub';
  if (after.jti !== before.jti) return 'lineage_jti';
  // Byte-exact on purpose, unlike `delegateMatches`: a renewal must not change its signed identity.
  if (after.delegate !== before.delegate) return 'lineage_delegate';
  if (after.iat < before.iat) return 'iat_before_old';
  if (after.iat > Math.floor(nowMs / 1000) + RENEWAL_CLOCK_TOLERANCE_SECONDS) return 'iat_in_future';
  if (after.exp <= before.exp) return 'exp_not_widened';
  if (after.iss !== before.iss) return 'lineage_iss';
  if (after.principal !== before.principal) return 'lineage_principal';
  return 'accepted';
}

function view(token: string): RenewalToken | null {
  const parsed = parseJwt(token);
  if (!parsed) return null;
  return { kid: typeof parsed.header.kid === 'string' ? parsed.header.kid : null, token, claims: parsed.payload };
}

/**
 * Whether `candidate` is a renewal of the delegation token `found`, judged on their claims alone. A
 * `{ renewal: true }` answer is NOT a verification: verify `candidate` with `verifyDelegation` next.
 */
export function isRenewalOf(found: string, candidate: string, options: { now?: Date } = {}): RenewalCheck {
  const before = view(found);
  if (!before) return { renewal: false, reason: 'old_token_unreadable' };
  const after = view(candidate) ?? { kid: null, token: candidate, claims: {} };
  const nowMs = (options.now ?? new Date()).getTime();
  // An invalid Date reads as NaN, and every comparison with NaN is false: the future-iat rule would
  // pass any candidate. A caller's mistake is refused rather than answered.
  if (!Number.isFinite(nowMs)) throw new RangeError('isRenewalOf: options.now is not a valid Date');
  const verdict = renewalVerdict(before, after, nowMs);
  return verdict === 'accepted' ? { renewal: true } : { renewal: false, reason: verdict };
}
