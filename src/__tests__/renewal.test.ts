/**
 * `isRenewalOf` / `renewalVerdict` — is a candidate token a RENEWAL of the one found
 * (m-delegation-publish-registries B.11b)? Claims only: this package does no fetch for it, and the
 * caller verifies the candidate itself with `verifyDelegation` against the SAME trusted issuer.
 *
 * The rule is the MCP gate's renewal pickup (`docs/mcp-delegation-gate-contract.md` § 6a), so the shared
 * `"mode": "renewal"` cases of `sdks/shared/fixtures/mcp_delegation_gate/pickup_lineage.json` — run by the
 * three gates and by the issuer's claim lookup — run here unchanged.
 */

import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { isRenewalOf, RENEWAL_CLOCK_TOLERANCE_SECONDS, renewalVerdict, type RenewalToken } from '../renewal.js';

interface LineageCase {
  id: string;
  mode?: 'rotation' | 'renewal';
  old?: RenewalToken;
  pulled: RenewalToken;
  expect: string;
}

// The shared fixtures live in the monorepo only; the published package's mirror runs without them.
const FIXTURES = new URL('../../../../sdks/shared/fixtures/mcp_delegation_gate/', import.meta.url);
const HAS_SHARED_FIXTURES = existsSync(FIXTURES);
const read = (name: string) => JSON.parse(readFileSync(new URL(name, FIXTURES), 'utf8'));
// vitest still runs a skipped suite's body to collect it, so the read waits on the same gate.
const lineage = (
  HAS_SHARED_FIXTURES ? read('pickup_lineage.json') : { old: {}, now: 0, cases: [] }
) as { old: RenewalToken; now: number; cases: LineageCase[] };
const renewalCases = lineage.cases.filter((c) => c.mode === 'renewal');

describe.skipIf(!HAS_SHARED_FIXTURES)('renewalVerdict — the shared renewal lineage cases', () => {
  it('has renewal cases to run', () => {
    expect(renewalCases.length).toBeGreaterThan(0);
  });

  it.each(renewalCases.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    expect(renewalVerdict(c.old ?? lineage.old, c.pulled, lineage.now)).toBe(c.expect);
  });

  it('uses the contract clock tolerance', () => {
    expect(RENEWAL_CLOCK_TOLERANCE_SECONDS * 1000).toBe(read('constants.json').lineage_clock_tolerance_ms);
  });
});

describe('isRenewalOf — two tokens', () => {
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const NOW = Date.UTC(2026, 10, 9);
  const base = {
    iss: 'proof.holdings',
    sub: 'ph_dlg_0123456789abcdef0123456789abcdef',
    jti: 'ph_jti_one',
    principal: 'example.com',
    delegate: 'pkg:npm/example-mcp',
    iat: NOW / 1000 - 86_400,
    exp: NOW / 1000 + 86_400,
  };
  const jwt = (claims: Record<string, unknown>, kid: string | null = 'dlg-2026-11') =>
    `${b64({ alg: 'ES256', ...(kid ? { kid } : {}) })}.${b64(claims)}.sig`;
  const found = jwt(base);

  it('accepts the same delegation re-signed with a later exp', () => {
    expect(isRenewalOf(found, jwt({ ...base, iat: NOW / 1000, exp: base.exp + 30 * 86_400 }), { now: new Date(NOW) })).toEqual({
      renewal: true,
    });
  });

  it.each([
    ['another issuer', { iss: 'someone.else' }, 'lineage_iss'],
    ['another principal', { principal: 'other.example' }, 'lineage_principal'],
    ['another handle', { sub: 'ph_dlg_ffffffffffffffffffffffffffffffff' }, 'lineage_sub'],
    ['another jti', { jti: 'ph_jti_two' }, 'lineage_jti'],
    ['another delegate', { delegate: 'pkg:npm/other' }, 'lineage_delegate'],
    // Lineage is BYTE-EXACT even where matching folds case: a replacement token must carry the
    // very delegate that was signed, or it changed its signed identity (m-delegate-case-parity).
    ['the delegate in other letter case', { delegate: 'pkg:npm/Example-MCP' }, 'lineage_delegate'],
    ['the same exp', { exp: base.exp }, 'exp_not_widened'],
  ])('refuses a candidate with %s', (_what, change, reason) => {
    expect(isRenewalOf(found, jwt({ ...base, iat: NOW / 1000, exp: base.exp + 30 * 86_400, ...change }), { now: new Date(NOW) })).toEqual({
      renewal: false,
      reason,
    });
  });

  it('refuses a Composer renewal whose delegate differs only by case', () => {
    const composer = { ...base, delegate: 'pkg:composer/Foo/Bar' };
    const candidate = jwt({ ...composer, delegate: 'pkg:composer/foo/bar', iat: NOW / 1000, exp: base.exp + 30 * 86_400 });
    expect(isRenewalOf(jwt(composer), candidate, { now: new Date(NOW) })).toEqual({ renewal: false, reason: 'lineage_delegate' });
  });

  it('throws on an invalid `now` rather than skipping the future-iat rule', () => {
    const farFuture = jwt({ ...base, iat: NOW / 1000 + 10 * 365 * 86_400, exp: base.exp + 20 * 365 * 86_400 });
    expect(() => isRenewalOf(found, farFuture, { now: new Date(Number.NaN) })).toThrow(RangeError);
  });

  it('refuses the same token, and anything that is not a token', () => {
    expect(isRenewalOf(found, found)).toEqual({ renewal: false, reason: 'same_token' });
    expect(isRenewalOf('junk', found)).toEqual({ renewal: false, reason: 'old_token_unreadable' });
    expect(isRenewalOf(found, 'junk')).toEqual({ renewal: false, reason: 'malformed_response' });
  });
});
