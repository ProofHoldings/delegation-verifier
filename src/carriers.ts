/**
 * Where a delegation may be published, and how to read it back.
 *
 * ⚠️ SECOND LOCKSTEP COPY of two issuer-side pieces: the extraction half of
 * `scripts/delegation-publication-shared.ts`, and the pointer parser in
 * `src/services/delegationPointer/pointer.ts`. Both are pinned by the drift suite
 * `src/__tests__/drift/delegation-verifier.test.ts` in that repository — a carrier the
 * publisher writes to and the verifier does not read makes a real delegation invisible.
 *
 * FOUR sanctioned carriers, and the fourth is shaped unlike the others. Three are LOCATIONS
 * INSIDE A CARD, each holding the publication itself, because three registries reserve
 * different keys:
 *   - MCP server card: `_meta["holdings.proof/delegation"]`
 *   - MCP official registry: nested under `_meta["io.modelcontextprotocol.registry/publisher-provided"]`
 *   - A2A agent card: `capabilities.extensions[]` with `uri: "https://proof.holdings/delegation"`
 *     (A2A cards have no `_meta`)
 * The fourth is a DNS record — `_mcp.<domain>` TXT — which holds NO publication at all: it holds
 * the ADDRESS of a card that does. The first three are read from an artifact one already has; the
 * pointer is read from a domain, and leads to the card. Format:
 * `docs/delegation-dns-pointer.md` in the issuer repository.
 *
 * Deliberately free of any crypto import: a consumer that only wants to know whether a card
 * claims a delegation at all pays nothing for the verification machinery. For the same reason
 * pointer RESOLUTION — the DNS query and the card fetch — is not here: it is Node-only I/O and
 * lives in the issuer repository, while the parsing below stays pure.
 */

export const DELEGATION_META_KEY = 'holdings.proof/delegation';
export const DELEGATION_EXTENSION_URI = 'https://proof.holdings/delegation';
export const REGISTRY_PUBLISHER_PROVIDED_KEY = 'io.modelcontextprotocol.registry/publisher-provided';

export interface FoundPublication {
  location: string;
  value: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Every delegation publication a card carries, across all sanctioned locations. */
export function extractDelegationPublications(card: unknown): FoundPublication[] {
  if (!isRecord(card)) return [];
  const found: FoundPublication[] = [];

  const meta = card._meta;
  if (isRecord(meta)) {
    if (meta[DELEGATION_META_KEY] !== undefined) {
      found.push({ location: `_meta["${DELEGATION_META_KEY}"]`, value: meta[DELEGATION_META_KEY] });
    }
    const publisherProvided = meta[REGISTRY_PUBLISHER_PROVIDED_KEY];
    if (isRecord(publisherProvided) && publisherProvided[DELEGATION_META_KEY] !== undefined) {
      found.push({
        location: `_meta["${REGISTRY_PUBLISHER_PROVIDED_KEY}"]["${DELEGATION_META_KEY}"]`,
        value: publisherProvided[DELEGATION_META_KEY],
      });
    }
  }

  const capabilities = card.capabilities;
  if (isRecord(capabilities) && Array.isArray(capabilities.extensions)) {
    capabilities.extensions.forEach((extension, index) => {
      if (isRecord(extension) && extension.uri === DELEGATION_EXTENSION_URI) {
        found.push({ location: `capabilities.extensions[${index}]`, value: extension.params });
      }
    });
  }

  return found;
}

// ---------------------------------------------------------------------------------------------
// The DNS pointer (fourth carrier). LOCKSTEP COPY of `src/services/delegationPointer/pointer.ts`
// in the issuer repository; the build half is deliberately absent, since a verifier never
// publishes. Format and rejection vocabulary: `docs/delegation-dns-pointer.md`.
// ---------------------------------------------------------------------------------------------

export const POINTER_VERSION = 'proofdlg1';
export const POINTER_RECORD_PREFIX = '_mcp';

export type PointerRejection =
  | 'no_pointer'
  | 'version_not_first'
  | 'missing_card'
  | 'duplicate_field'
  | 'invalid_card_url'
  | 'ambiguous_pointer'
  | 'token_in_dns';

export type PointerParseResult = { ok: true; card: string } | { ok: false; reason: PointerRejection };

/** The DNS name a domain publishes its pointer at. */
export function pointerRecordName(domain: string): string {
  return `${POINTER_RECORD_PREFIX}.${domain}`;
}

/**
 * A card URL is an absolute https URL with no userinfo, no query and no fragment — the same
 * restrictions `canonicalizeDelegate` places on a url-typed delegate.
 */
function isValidCardUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return (
    url.protocol === 'https:' &&
    url.username === '' &&
    url.password === '' &&
    url.search === '' &&
    url.hash === ''
  );
}

/**
 * Three base64url runs separated by dots is only a CANDIDATE — `discovery.mcp-servers.engineering`
 * matches that shape too. What settles it is decoding: a JWT's first segment is a JSON object
 * carrying `alg`, and a hostname label is not.
 *
 * Every CONSECUTIVE triple is examined, deliberately. A scan over non-overlapping regex matches
 * misses a token whenever anything dotted precedes it, because the earlier match consumes the
 * token's header as its own third run — `abcd.efgh.<token>` then reads as clean. A code review
 * found that live, and the fixtures meant to prove the rule all happened to place the token where
 * nothing preceded it.
 */
const RUN_SEPARATOR = /[^A-Za-z0-9_.-]+/;
const MIN_HEADER_RUN = 4;
const MIN_PAYLOAD_RUN = 4;
const MIN_SIGNATURE_RUN = 2;

function decodeBase64Url(segment: string): string | null {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
  const remainder = padded.length % 4;
  if (remainder === 1) return null;
  try {
    return atob(remainder === 0 ? padded : padded + '='.repeat(4 - remainder));
  } catch {
    return null;
  }
}

/**
 * Two facts about text that base64url-decodes to a JSON object whose FIRST BYTE is `{`, both
 * checked numerically rather than assumed (an earlier attempt anchored on the prefix `ey`, which
 * is wrong: `{\n` encodes to `ewo`):
 *
 *   - its first character is always `e` — the high six bits of `0x7B` are `011110`, index 30;
 *   - its first FOUR characters decode to three bytes whose first byte is `{`.
 *
 * The `{`-first qualifier is the honest statement of the limit, not a technicality: a header that
 * begins with LEGAL JSON whitespace (` {"alg":…}`) is not seen. That is unreachable for a genuine
 * token — the header is signing input, so it cannot be re-spaced without breaking the signature —
 * and it fails CLOSED for a reader implementing this spec, but the rule has to say what it checks.
 *
 * The four-character probe is what keeps the offset walk linear with a small constant. Anchoring
 * on `e` alone is not enough: a value made of 65 000 `e`s passes that filter at every offset, and a
 * review's cost case measured 242 ms against this version's 6.6 ms on exactly that shape — a 37x
 * gap, not the ~3x an average across mixed shapes suggested. The probe costs
 * one 4-character decode per offset and rejects it immediately.
 */
const HEADER_FIRST_CHAR = 'e';
const HEADER_PROBE_CHARS = 4;
const JSON_OBJECT_OPEN = '{';

/**
 * How much of a segment is decoded once the probe matches, and therefore the LONGEST header this
 * scan can recognise. It is a real, documented boundary rather than an implementation detail: a
 * token whose header exceeds it is not detected. 4096 characters is ~3 KB of decoded JSON, which
 * covers an ordinary header (~40-80 characters) and one carrying an `x5c` certificate chain, while
 * keeping the walk linear — without it, decoding "the rest of the segment" at every offset is
 * O(L²), and a review measured 4193 ms of blocked processing on one 64 KB value an attacker
 * chooses. See `docs/delegation-dns-pointer.md` for the boundary as published.
 */
export const MAX_HEADER_CHARS = 4096;

/** Does this text carry a JWT anywhere inside it? */
export function carriesJwt(text: string): boolean {
  for (const run of text.split(RUN_SEPARATOR)) {
    const segments = run.split('.');
    for (let index = 0; index + 2 < segments.length; index++) {
      if (
        segments[index + 1].length < MIN_PAYLOAD_RUN ||
        segments[index + 2].length < MIN_SIGNATURE_RUN
      ) {
        continue;
      }
      // The header may START anywhere inside its segment, not only at a run boundary: `-`, `_`
      // and alphanumerics are all base64url-legal, so `delegation-<jwt>` puts the prefix and the
      // header in ONE segment and decoding the whole thing fails. A review found that after the
      // first fix, on fixtures that all happened to place a `/` or `=` immediately before the
      // token.
      const header = segments[index];
      for (let start = 0; header.length - start >= MIN_HEADER_RUN; start++) {
        if (header[start] !== HEADER_FIRST_CHAR) continue;
        const probe = decodeBase64Url(header.slice(start, start + HEADER_PROBE_CHARS));
        if (probe === null || probe[0] !== JSON_OBJECT_OPEN) continue;

        const decoded = decodeBase64Url(header.slice(start, start + MAX_HEADER_CHARS));
        if (decoded === null) continue;
        try {
          const parsed: unknown = JSON.parse(decoded);
          if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) && 'alg' in parsed) {
            return true;
          }
        } catch {
          // Not a JWT header; keep looking.
        }
      }
    }
  }
  return false;
}

type SinglePointer =
  | { kind: 'not_ours' }
  | { kind: 'ok'; card: string }
  | { kind: 'bad'; reason: PointerRejection };

function parseOneRecord(raw: string): SinglePointer {
  const fields = raw
    .split(';')
    .map((field) => field.trim())
    .filter((field) => field.length > 0);

  const versionIndex = fields.indexOf(`v=${POINTER_VERSION}`);
  if (versionIndex === -1) return { kind: 'not_ours' };
  if (versionIndex !== 0) return { kind: 'bad', reason: 'version_not_first' };

  const seen = new Set<string>(['v']);
  let card: string | undefined;

  for (const field of fields.slice(1)) {
    const separator = field.indexOf('=');
    if (separator <= 0) continue;
    const key = field.slice(0, separator);
    if (!/^[a-z0-9-]+$/.test(key)) continue;
    if (key !== 'card' && key !== 'v') continue;
    if (seen.has(key)) return { kind: 'bad', reason: 'duplicate_field' };
    seen.add(key);
    card = field.slice(separator + 1);
  }

  if (card === undefined) return { kind: 'bad', reason: 'missing_card' };
  if (!isValidCardUrl(card)) return { kind: 'bad', reason: 'invalid_card_url' };
  return { kind: 'ok', card };
}

/**
 * Read the pointer out of the TXT values published at `_mcp.<domain>`.
 *
 * Several records may share that name — the MCP discovery draft permits it, so a zone may hold a
 * `v=mcp1` record beside ours. Records that are not ours are skipped silently. Any record of ours
 * that is malformed is a refusal even when another of ours is fine: a zone holding a broken proof
 * record is in an unknown state, and reading the other one is guessing which the owner meant. Two
 * well-formed records of ours naming DIFFERENT cards is `ambiguous_pointer`, for the same reason
 * `verifyPublishedDelegation` refuses a card publishing two different tokens.
 */
export function parseDelegationPointer(txtValues: string[]): PointerParseResult {
  // Checked across the whole set BEFORE anything is believed about any record: a token in this
  // zone's `_mcp` name is a bearer artifact loose in a channel with cached copies nobody controls,
  // whoever put it there.
  if (txtValues.some((value) => carriesJwt(value))) return { ok: false, reason: 'token_in_dns' };

  const ours: SinglePointer[] = [];
  for (const value of txtValues) {
    const parsed = parseOneRecord(value);
    if (parsed.kind !== 'not_ours') ours.push(parsed);
  }

  if (ours.length === 0) return { ok: false, reason: 'no_pointer' };

  // With two malformed records of ours, the FIRST in the array decides which reason is reported,
  // and resolvers rotate RRsets — so two runs against one zone can name different reasons. Both
  // copies agree for any given input (which is what the lockstep suite pins) and both answers are
  // refusals; only the diagnostic label moves.
  const broken = ours.find((entry): entry is { kind: 'bad'; reason: PointerRejection } => entry.kind === 'bad');
  if (broken) return { ok: false, reason: broken.reason };

  const cards = new Set(ours.map((entry) => (entry as { kind: 'ok'; card: string }).card));
  if (cards.size > 1) return { ok: false, reason: 'ambiguous_pointer' };

  return { ok: true, card: [...cards][0] };
}

/** The distinct delegation tokens a card publishes. */
export function collectPublishedTokens(card: unknown): string[] {
  const tokens = new Set<string>();
  for (const publication of extractDelegationPublications(card)) {
    if (isRecord(publication.value) && typeof publication.value.token === 'string' && publication.value.token) {
      tokens.add(publication.value.token);
    }
  }
  return [...tokens];
}
