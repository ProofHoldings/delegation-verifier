/**
 * Verifying the delegation a card publishes.
 *
 * The carrier layout itself lives in `carriers.ts` (kept crypto-free so it can be read without
 * pulling in the verification machinery); this module is the part that decides.
 */

import { collectPublishedTokens } from './carriers.js';
import { classifyFailureReason } from './types.js';
import type { VerificationResult, VerifyOptions } from './types.js';
import { verifyDelegation } from './verify.js';

export {
  DELEGATION_META_KEY,
  DELEGATION_EXTENSION_URI,
  REGISTRY_PUBLISHER_PROVIDED_KEY,
  extractDelegationPublications,
  parseDelegationPointer,
  pointerRecordName,
  POINTER_VERSION,
  POINTER_RECORD_PREFIX,
} from './carriers.js';
export type { FoundPublication, PointerParseResult, PointerRejection } from './carriers.js';

/**
 * Verify the delegation an MCP server card or A2A agent card publishes.
 *
 * `options.delegate` still means what it means everywhere else: the artifact identity YOU
 * resolved — the npm package you are about to install, the endpoint you are about to call —
 * NOT a field read out of this card. A card that describes itself is not evidence about
 * itself.
 */
export async function verifyPublishedDelegation(
  card: unknown,
  options: VerifyOptions
): Promise<VerificationResult> {
  const tokens = collectPublishedTokens(card);
  if (tokens.length === 0) {
    return {
      valid: false,
      reason: 'no_publication',
      outcome: classifyFailureReason('no_publication'),
      message: 'card carries no delegation publication in any sanctioned location',
    };
  }
  if (tokens.length > 1) {
    return {
      valid: false,
      reason: 'multiple_publications',
      outcome: classifyFailureReason('multiple_publications'),
      message: `card publishes ${tokens.length} different delegation tokens — refusing to guess which one it means`,
    };
  }
  return verifyDelegation(tokens[0], options);
}
