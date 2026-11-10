# @proof-holdings/delegation-verifier

[![Proof of Delegation](https://proof.holdings/badge/npm/@proof-holdings/delegation-verifier)](https://proof.holdings/npm/@proof-holdings/delegation-verifier)

Verify a **Proof of Delegation**: a signed statement that the controller of a domain authorized
a specific agent artifact — an npm package, a container, an endpoint.

You do not need an account with anyone to use this. It runs against public surfaces only, and
it has **no built-in trust list**: you name the issuers you accept.

```bash
npm install @proof-holdings/delegation-verifier
```

Zero runtime dependencies. Node ≥ 18 (or any runtime with WebCrypto, `fetch` and
`DecompressionStream` — Deno, Bun, Cloudflare Workers).

## What a valid result means — and what it does not

A verified delegation says exactly one thing:

> The controller of `principal` authorized `delegate`, and the issuer checked that control when
> it signed.

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
   fetched. Key sets are cached; an unknown `kid` triggers at most one refetch per 30s. The
   signing key's purpose, window and tombstone are checked here too — see
   [Key rotation](#key-rotation-and-the-key-set-cache).
3. **Claims** — `token_type`, schema version, `exp`/`iat` (5s tolerance by default), and the
   required claim set.
4. **Principal** — pinned to the domain you expect, when you supply one. See above: without it
   the answer says who *claims* the artifact, not that the right party did.
5. **Delegate** — the token's `delegate` and the identity you resolved are both canonicalized
   by the same per-registry rule, then compared exactly (`delegateMatches`): npm, PyPI and Composer
   names ignore case (PyPI also folds `-`, `_`, `.`), a Go module path and a URL path keep theirs.
6. **Status** — two channels, both authenticated, asked in order:
   - the IETF Token Status List the token points at (`status.status_list`), whose uri is
     refused unless it belongs to your trusted issuer, and whose signature is checked against
     the same key set. A readable `valid`, `revoked` or `suspended` slot is the answer, and the
     check stops there. An issuer whose validity cascades folds a revoked or suspended domain
     control proof beneath the delegation into this same slot (proof.holdings does);
   - the issuer's status endpoint, asked only when the list gives no answer: the token carries
     no status-list claim, or the list cannot be read, is not the trusted issuer's, or holds no
     valid/revoked/suspended value for the token's slot. One thing
     only the endpoint can report is an **expiry** inherited from the domain control proof, which
     a list slot never encodes. A delegation whose own slot and own `exp` both read fine is
     therefore not re-checked for it — an accepted residual, explained in
     [Why the status endpoint is not always called](#why-the-status-endpoint-is-not-always-called-and-what-that-leaves-uncovered).

   Status checking is **fail-closed**: if neither channel gives an answer, the result is
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

## Key rotation and the key-set cache

An issuer's JWKS may carry several keys at once. Beside the standard members, a key may declare
`proof_purpose` (`proof`, `delegation` or `status-list`), a window (`not_before`, `not_after`,
`max_token_lifetime` — integer seconds) or `proof_legacy: true`; revoked keys are listed in a
top-level `proof_tombstones: [{ "kid", "revoked_at" }]`. A key set without these members verifies
exactly as before. Once any key carries `proof_purpose`:

- a delegation must be signed by a `delegation` key or a legacy one (`wrong_key_purpose`);
- its `iat` must lie in the key's window, ± 5 minutes (`outside_key_window`), and its `exp` no later
  than `iat + max_token_lifetime` (`token_lifetime_exceeded`) — legacy keys skip both;
- a token without `kid` is tried against legacy keys only.

The status list's own signing key is held to the same rules as a `status-list` key; a list signed by
a key that fails them counts as unreadable, exactly like a list that could not be fetched.

**One response is never trusted for long.** A new key verifies from its first sighting, so an
emergency key works at once. But the verifier only *remembers* a key carrying `proof_purpose` or
`proof_legacy` — keeps it after it disappears from the JWKS, refuses new key material under its
`kid`, refuses whole a document that widens its window — once two fetches at least 5 minutes apart
served it unchanged; until then the next document replaces or drops it. A narrower window and a
tombstone wait for the same confirmation: a tombstone applies only when a fetch at least 5 minutes
after its first sighting still carries it (a fetch in between that drops it starts over;
`refreshJwks` forces the second fetch), and once applied it stays until `revoked_at` + 365 days or
`clearTombstones()`, whatever later documents say.

The key set is refetched every 10 minutes. When a refetch fails, the cache's confirmed keys keep
answering until it is `maxJwksAgeMs` old, then the answer is `jwks_stale`; an applied tombstone
answers `key_revoked` at any age. A failed refetch of a cached set is retried at most once per 30s.
The cache lives in the process, keyed by `jwksUri`.

| Option | Default | Meaning |
| --- | --- | --- |
| `maxJwksAgeMs` | 24 h | How old the cache may be when a refetch fails. Above 25 days, non-integer or ≤ 0 is `invalid_options`. |
| `keySetStore` | none | `{ load(jwksUri), save(jwksUri, state) }`, sync or async, opaque string state. Persists the key set — tombstones included — across restarts and cold starts. A failing store never fails a verification. |
| `onJwksEvent` | ignored | Receives `{ type, jwksUri, kid?, message }`: `tombstone_pending`, `tombstone_applied`, `tombstone_for_live_key`, `window_narrowing_pending`, `window_narrowing_applied`, `window_widening_rejected`, `key_material_changed`, `kid_vanished`, `store_error`. |
| `timeoutMs` | 5000 | Bounds each network request and each `keySetStore` call. |

Exported alongside `verifyDelegation`:

- `refreshJwks({ jwksUri, fetch?, timeoutMs?, keySetStore?, onJwksEvent? })` — refetch now,
  ignoring the TTL and cooldowns; resolves `{ ok: true }` or `{ ok: false, message }`. The method a
  `jwks_stale` result's `refreshHint` names.
- `clearTombstones({ jwksUri?, keySetStore? })` — the manual reset: forgets applied and pending
  tombstones for one key set (and its persisted copy), or for every set in memory.
- `getJwksDiagnostics(jwksUri)` — cache age, whether the registry is live, vanished keys, pending and
  applied tombstones; `null` for a key set this process has never used.
- `DEFAULT_MAX_JWKS_AGE_MS`, `MAX_JWKS_AGE_CAP_MS` — to validate your own configuration against the
  same bounds.

## Renewed delegations

An issuer may renew a delegation in place: the same delegation re-signed with a later `exp`, keeping its
handle, `jti`, `principal` and `delegate`. A published copy then goes stale without being withdrawn, and
`verifyDelegation` answers it `expired` on its own date. To follow the renewal, fetch the delegation's
current token from its issuer yourself, check it with `isRenewalOf`, and verify it like any other token.

Where to fetch it is in the token: a proof.holdings delegation carries a `renewal_url` claim, the address
its current version is served at (`https://api.proof.holdings/api/v1/proofs/delegation-token/<handle>`),
the same for every token of the delegation. A verified result passes it on as `delegation.renewalUrl` only
when it is https and on an origin of the trusted issuer — its `jwksUri`, its `statusEndpoint`, or one of
its `statusListOrigins`, the rule the status-list uri follows — so a token cannot send you to a host it
names itself. A refused claim does not fail the delegation: `renewalUrl` is `null` and
`renewalUrlRejected` says why (`not_https`, `off_origin`, or `malformed` for a claim that is not a URL, or
carries userinfo, a backslash, whitespace or a character outside printable ASCII — strings URL parsers
disagree on); the URL passed on is the parsed one's serialization, never the claim's own text;
`renewalUrl` is `null` with no reason for a token that carries none, such as one issued before the
claim existed. An `expired` failure carries the same two fields, under the same rule — an expired copy is
the case the claim exists for; no other failure does. The package never fetches it. Fetch it with
`redirect: 'error'`, as the status-list fetch does: the path is the token's to choose, and on an expired copy
the signature has not been checked yet, so a redirect anywhere on the issuer's origin must not take you off it:

```ts
const found = await verifyDelegation(foundToken, { trustedIssuers, delegate });
if (!found.valid && found.reason === 'expired' && found.renewalUrl) {
  const { token: currentToken } = await (await fetch(found.renewalUrl, { redirect: 'error' })).json();
  const check = isRenewalOf(foundToken, currentToken);
  if (check.renewal) {
    const result = await verifyDelegation(currentToken, {
      trustedIssuers, // the SAME trusted issuer as for the found token
      delegate,
      expectedPrincipal: principalOfTheFoundToken,
    });
  }
}
```

`isRenewalOf` compares claims only and makes no request: `{ renewal: true }` is not a verification. It
follows one hop — the candidate is compared with the token you found — and refuses another `iss`, handle,
`jti`, `principal` or `delegate`, an `iat` before the found token's, and an `exp` that is not later
(`renewal: false` with a `reason`).

## Failure reasons

Every failure carries an `outcome: 'invalid' | 'unconfirmed'` beside `reason` —
`classifyFailureReason(reason)` if you need it standalone. `unconfirmed` means the revocation
check itself could not run; treat it as "not checked", never as "checked and fine". Everything
else is `invalid`: a completed check with a negative verdict, including a call-shape error (those
are unreachable once your own call is well-formed, and are classified for completeness, not
because they occur in practice).

| `reason` | `outcome` | Meaning |
| --- | --- | --- |
| `invalid_options` | `invalid` | The call is wrong — usually a missing or uncanonicalizable `delegate`, or the `requiredScopes` option, removed in 0.2.0 with the `scope` claim (refused rather than ignored, so no caller reads a valid answer as "my scopes were granted"). |
| `no_trust_policy` | `invalid` | `trustedIssuers` was empty. There is no default. |
| `malformed_token` | `invalid` | Not a decodable JWT. |
| `untrusted_issuer` | `invalid` | Signed by someone you did not name. |
| `unsupported_algorithm` | `invalid` | The token asked for an algorithm this verifier does not accept. |
| `unknown_key` / `bad_signature` | `invalid` | No matching key, or the signature does not hold. |
| `jwks_unavailable` | `unconfirmed` | Could not read the key set, or could not refetch it for an unknown `kid` — "I could not check", not "it is bad". |
| `jwks_stale` | `unconfirmed` | A refetch failed and the cached key set is older than `maxJwksAgeMs`. Carries `cacheAgeSeconds` (null when unknown) and `refreshHint: { jwksUri, method: 'refreshJwks' }`. |
| `key_revoked` | `invalid` | The issuer revoked the signing key (an applied JWKS tombstone). Carries `pullHint: { issuerOrigin, handle }` — where to ask for a re-signed token. The handle is read from a token whose signature was not checked: an address to ask, not a verified identity. |
| `wrong_key_purpose` | `invalid` | The signing key belongs to another key family than a delegation. |
| `outside_key_window` | `invalid` | The token's `iat` lies outside the signing key's window (5 minutes of skew allowed). |
| `token_lifetime_exceeded` | `invalid` | `exp` lies beyond `iat` plus the signing key's `max_token_lifetime`. |
| `not_a_delegation` / `unsupported_version` | `invalid` | Wrong token type, or a `delegation_schema_version` major other than 2 (a 1.x token, which still carries `scope`, is refused before any network call). |
| `expired` / `not_yet_valid` / `malformed_claims` | `invalid` | Claim-level rejections. |
| `principal_mismatch` | `invalid` | Issued by a different domain than you expected. |
| `delegate_mismatch` | `invalid` | **Attests a different artifact than the one you resolved.** |
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

The endpoint is asked only when the list gives no answer: the token carries no status-list claim,
or the list cannot be read, is not the trusted issuer's, or holds no valid/revoked/suspended value
for the token's slot. It is the only channel that can report two things the bit structurally
cannot — `unknown_delegation` ("no record of this handle" is distinguishable from "a record that
is dead" only by a live call) and, for issuers whose validity cascades through something else, like
a domain control proof underneath a delegation, an EXPIRY driven by that something else, which a
status-list bit never encodes (only revoked/suspended are, by the same draft's own vocabulary) —
so when the list does answer, neither is checked. For proof.holdings specifically, that
cascade-expiry gap is bounded, not eliminated: a delegation can no longer be minted longer than its
underlying control proof, and a control cannot be re-issued shorter than an outstanding delegation
without capping the reissue to cover it — but a control shortened before that guarantee existed, or a
reissue that hit its own rare fail-open path, can still leave a delegation whose list bit and own
`exp` claim both read fine while its issuer would answer `expired`. This is a known, accepted trade-off — not
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
