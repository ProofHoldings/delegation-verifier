# @proof-holdings/delegation-verifier

Verify a **Proof of Delegation**: a signed statement that the controller of a domain authorized
a specific agent artifact — an npm package, a container, an endpoint — for a set of capability
scopes.

You do not need an account with anyone to use this. It runs against public surfaces only, and
it has **no built-in trust list**: you name the issuers you accept.

```bash
npm install @proof-holdings/delegation-verifier
```

Zero runtime dependencies. Node ≥ 18 (or any runtime with WebCrypto, `fetch` and
`DecompressionStream` — Deno, Bun, Cloudflare Workers).

## What a valid result means — and what it does not

A verified delegation says exactly one thing:

> The controller of `principal` authorized `delegate` for these scopes, and the issuer checked
> that control when it signed.

It is **not** a statement that the artifact is safe, audited, maintained, or endorsed, and it is
not a review of the business behind the domain. Do not render it as a generic "verified" badge.

## Usage

```ts
import { verifyPublishedDelegation } from '@proof-holdings/delegation-verifier';

const result = await verifyPublishedDelegation(serverCard, {
  // No defaults: you decide whose signature means anything to you.
  trustedIssuers: [
    {
      issuer: 'proof.holdings',
      jwksUri: 'https://api.proof.holdings/.well-known/jwks.json',
      statusEndpoint: 'https://api.proof.holdings/api/v1/proofs/validate',
    },
  ],
  // The artifact YOU resolved — the package you are installing, the endpoint you are calling.
  delegate: { type: 'purl', value: 'pkg:npm/postmark-mcp' },
  expectedPrincipal: 'postmarkapp.com',
  requiredScopes: ['send-email'],
});

if (result.valid) {
  // `result.principalChecked` / `result.statusChecked` say how much was actually asked.
  console.log(`${result.delegation.principal} authorized ${result.delegation.delegate}`);
} else {
  console.warn(`not verified: ${result.reason} — ${result.message}`);
}
```

`verifyDelegation(token, options)` is the same check when you already hold the token instead of
a card.

### `delegate` is required, and this is the point

A published delegation token is a **bearer artifact**. Anyone can copy a genuine token out of
one card and paste it into another. The check that defeats that is comparing the token's
`delegate` claim against the artifact identity **you resolved independently** — the package
name you are about to `npm install`, the URL you are about to call. Never pass a value you read
out of the card being verified: a card describing itself is not evidence about itself.

That is why `delegate` is a required argument rather than an optional one, and why omitting it
is reported as `invalid_options` instead of quietly skipping the comparison.

### `expectedPrincipal` closes the OTHER half

An issuer binds `delegate` to nothing. The domain in `principal` is whatever the requester
proved control of; the artifact is a value they chose. So anyone who can verify `evil.example`
can mint a genuine, signature-valid, non-revoked delegation naming **someone else's** package.

`delegate` stops a token being *copied*; only pinning `principal` stops one being *minted by
the wrong party*. Pass `expectedPrincipal` whenever you know whose artifact you think this is —
which is nearly always, since you know what you are installing.

A result without it is still returned, because a directory or a lookup UI legitimately asks
"who claims this artifact?" — but it carries `principalChecked: false`, and it must be
presented as *"X says it authorized this"*, never as *verified*.

## The chain

1. **Trust policy** — the token's `iss` must be one you named. No trust list, no verification.
2. **Signature** — RS256/ES256 against the issuer's JWKS. The algorithm is chosen by the
   verifier, never read from the token, so `alg: none` and HMAC forgeries die before any key is
   fetched. Key sets are cached; an unknown `kid` triggers at most one refetch per 30s.
3. **Claims** — `token_type`, schema version, `exp`/`iat` (5s tolerance by default), and the
   required claim set.
4. **Principal** — pinned to the domain you expect, when you supply one. See above: without it
   the answer says who *claims* the artifact, not that the right party did.
5. **Delegate** — canonicalized and compared byte-for-byte with the identity you resolved.
6. **Status** — two channels, both authenticated:
   - the IETF Token Status List the token points at (`status.status_list`), whose uri is
     refused unless it belongs to your trusted issuer, and whose signature is checked against
     the same key set;
   - the issuer's status endpoint, which is the only thing that can report the **cascade**: a
     delegation is worth no more than the domain control proof beneath it, and a revoked domain
     proof does not flip the delegation's own status-list bit.

   Status checking is **fail-closed**: if either channel cannot answer, the result is
   `status_unavailable`, not "valid". Pass `statusCheck: 'skip'` to check signature and claims
   only — the result then carries `statusChecked: false`, which means *revocation was not
   checked*, never *not revoked*.

### What happens when the domain proof underneath is renewed for a shorter period

A delegation's own `exp` can never exceed its control (domain) proof's remaining lifetime at
issuance — the issuer rejects a longer request rather than truncating it. proof.holdings applies
the same rule on the OTHER side, at every later renewal of the domain proof itself: the renewal
call still succeeds, but if the requested duration would shorten the domain proof's expiry below
an already-issued delegation's own `exp`, the requested value is not honoured — the domain proof
is kept at (at least) the longest-lived delegation's expiry instead, with no error returned. A
delegate's token therefore never silently outlives the domain proof it depends on — you do not
need to re-check more often just because the domain owner renewed their proof for a shorter term
than before.

### Issuer status endpoint contract

`POST <statusEndpoint>` with `{"proof_token": "<jwt>"}` answering JSON with at least
`{"valid": boolean}` and optionally `{"reason": "revoked" | "suspended" | ...}`.

## Failure reasons

Every failure carries an `outcome: 'invalid' | 'unconfirmed'` beside `reason` —
`classifyFailureReason(reason)` if you need it standalone. `unconfirmed` means the revocation
check itself could not run; treat it as "not checked", never as "checked and fine". Everything
else is `invalid`: a completed check with a negative verdict, including a call-shape error (those
are unreachable once your own call is well-formed, and are classified for completeness, not
because they occur in practice).

| `reason` | `outcome` | Meaning |
| --- | --- | --- |
| `invalid_options` | `invalid` | The call is wrong — usually a missing or uncanonicalizable `delegate`. |
| `no_trust_policy` | `invalid` | `trustedIssuers` was empty. There is no default. |
| `malformed_token` | `invalid` | Not a decodable JWT. |
| `untrusted_issuer` | `invalid` | Signed by someone you did not name. |
| `unsupported_algorithm` | `invalid` | The token asked for an algorithm this verifier does not accept. |
| `unknown_key` / `bad_signature` | `invalid` | No matching key, or the signature does not hold. |
| `jwks_unavailable` | `unconfirmed` | Could not read the key set — "I could not check", not "it is bad". |
| `not_a_delegation` / `unsupported_schema` | `invalid` | Wrong token type or a schema major this version does not understand. |
| `expired` / `not_yet_valid` / `malformed_claims` | `invalid` | Claim-level rejections. |
| `principal_mismatch` | `invalid` | Issued by a different domain than you expected. |
| `delegate_mismatch` | `invalid` | **Attests a different artifact than the one you resolved.** |
| `scope_not_granted` | `invalid` | Does not grant a scope you required. |
| `status_uri_untrusted` | `unconfirmed` | The status-list uri in the token is not the issuer's. Not fetched. |
| `status_unavailable` | `unconfirmed` | Revocation could not be checked. Fail closed. |
| `revoked` / `suspended` | `invalid` | Withdrawn, or reversibly paused. |
| `unknown_delegation` | `invalid` | The issuer has no record of it — distinct from "could not answer". |
| `no_publication` / `multiple_publications` | `invalid` | The card carries no delegation, or several different ones. |

### Why the status endpoint is not always called, and what that leaves uncovered

A `valid`/`revoked`/`suspended` read from the token's status list ends the revocation check right
there — no request to the issuer's status endpoint. That is safe **for any issuer that adopts a
status list at all**: the IETF draft's premise is that the list is the issuer's authoritative
revocation channel, so an issuer publishing one is committing to encode everything relevant to
that token's validity in it. An issuer that keeps a side-channel revocation reason out of its own
published list is not honoring the channel it chose to publish — a fact about that issuer, not
something a generic verifier can special-case.

The endpoint still fires for the cases the bit structurally cannot answer: a token with no
status-list claim at all, `unknown_delegation` ("no record of this handle" is distinguishable
from "a record that is dead" only by a live call), and — for issuers whose validity cascades
through something else, like a domain control proof underneath a delegation — an EXPIRY driven by
that something else, which a status-list bit never encodes (only revoked/suspended are, by the
same draft's own vocabulary). For proof.holdings specifically, that cascade-expiry gap is bounded,
not eliminated: a delegation can no longer be minted longer than its underlying control proof, and
a control cannot be re-issued shorter than an outstanding delegation without capping the
reissue to cover it — but a control shortened before that guarantee existed, or a reissue that hit
its own rare fail-open path, can still leave a delegation whose list bit and own `exp` claim both
read fine while its issuer would answer `expired`. This is a known, accepted trade-off — not
silently assumed away.

### One thing a failure reason is not

Claims are checked before the signature (cheap rejections first, and no `valid: true` is
reachable without a verified signature). A consequence: on a *forged* token the `reason` is
attacker-chosen — anyone can produce `delegate_mismatch` or `principal_mismatch` with an
unsigned JWT. Read a failure as "this did not verify", never as attested evidence about who
tried.

### A reason reports the FIRST failure, not the only one

The checks are ordered, and the first one to fail returns. `expired` in particular is decided
*before* `expectedPrincipal` and `delegate` are compared, so an expired token yields `expired`
whatever the pins are — an expired delegation genuinely issued for your artifact and an expired
token copied into a stranger's card are indistinguishable in the reason alone. The same holds
upward: `untrusted_issuer` supersedes everything after it.

So a failure reason tells you where the walk stopped, not what the remaining checks would have
said: they never ran. Do not build policy on the assumption that a reason implies the later
checks were evaluated — only `valid: true` means every check passed.

## Where delegations are published

Three sanctioned carriers live INSIDE a card and are all read by `verifyPublishedDelegation`:

- MCP server card — `_meta["holdings.proof/delegation"]`
- MCP official registry — the same key nested under
  `_meta["io.modelcontextprotocol.registry/publisher-provided"]`
- A2A agent card — an entry in `capabilities.extensions[]` with
  `uri: "https://proof.holdings/delegation"`

Each carries `{ "token": "<jwt>", "docs"?: "<url>" }`.

### The fourth carrier: a DNS pointer

`_mcp.<domain>` may hold a TXT record naming the card that carries the delegation:

```
_mcp.example.com.  IN TXT  "v=proofdlg1; card=https://example.com/.well-known/mcp/server.json"
```

It holds **no token** — DNS is a channel with no confidentiality and cached copies at resolvers
nobody controls. It exists so a reader can start from a DOMAIN rather than from an artifact, which
is the only route open to an owner who cannot publish a file on their own host: the card it names
may live anywhere.

Resolving it means a DNS query and an HTTP fetch, and this package has no dependencies, so it ships
only the pure half. Do the lookup with whatever resolver you already have and hand the TXT values
in:

```ts
import { parseDelegationPointer, pointerRecordName, verifyPublishedDelegation } from '@proof-holdings/delegation-verifier';
import { resolveTxt } from 'node:dns/promises';

// `resolveTxt` THROWS on NXDOMAIN, and "the domain publishes nothing" is a different fact from
// "the lookup failed" — collapsing them reports a network blip as "not delegated".
let records: string[][] = [];
try {
  records = await resolveTxt(pointerRecordName('example.com')); // '_mcp.example.com'
} catch (error) {
  // ENOTFOUND is "no such name", ENODATA is "the name exists with no TXT" — both mean the domain
  // publishes no pointer. Anything else is a lookup FAILURE, which is a different fact.
  const code = (error as NodeJS.ErrnoException).code;
  if (code !== 'ENOTFOUND' && code !== 'ENODATA') throw error;
}

const pointer = parseDelegationPointer(records.map((chunks) => chunks.join('')));
if (!pointer.ok) throw new Error(pointer.reason);

// `redirect: 'error'` matters: the grammar guarantees https at the START of the fetch, not at the
// end of a redirect chain, and the card is the thing carrying the delegation.
const response = await fetch(pointer.card, { redirect: 'error' });
if (!response.ok) throw new Error(`card fetch failed: ${response.status}`);
const card = await response.json();
const result = await verifyPublishedDelegation(card, {
  trustedIssuers,
  delegate: { type: 'purl', value: 'pkg:npm/example-mcp' }, // resolved by YOU, not read from the card
  expectedPrincipal: 'example.com',                          // the domain whose pointer you followed
});
```

`parseDelegationPointer` answers `{ ok: true, card }` or `{ ok: false, reason }`, where `reason` is
one of `no_pointer`, `version_not_first`, `missing_card`, `duplicate_field`, `invalid_card_url`,
`ambiguous_pointer`, `token_in_dns`. Two behaviours worth knowing:

- A record whose first field is not `v=proofdlg1` is **not ours** and is skipped silently. The MCP
  discovery draft (`draft-morrison-mcp-dns-discovery`) publishes `v=mcp1` at the same name, and the
  two coexist by ignoring each other.
- A record of ours that is malformed is a refusal **even when a well-formed one sits beside it**, and
  two well-formed records naming different cards are `ambiguous_pointer`. A zone in a contradictory
  state is not a zone to guess about — the same reason `verifyPublishedDelegation` refuses a card
  that publishes two different tokens.

A pointer is discovery, never evidence. Following one tells you where to look; whether the delegation
is real is still decided by `verifyPublishedDelegation` against the issuer's keys and status.

## License

MIT
