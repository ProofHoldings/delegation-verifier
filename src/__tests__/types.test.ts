import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { classifyFailureReason } from '../types.js';
import type { FailureOutcome, FailureReason } from '../types.js';

const TYPES_PATH = new URL('../types.ts', import.meta.url);

function readFailureReasonUnion(): string[] {
  const source = readFileSync(TYPES_PATH, 'utf-8');
  const match = source.match(/export type FailureReason =\s*([\s\S]*?);/);
  if (!match) {
    throw new Error('FailureReason union not found in types.ts — has it moved or been renamed?');
  }
  return [...match[1].matchAll(/'([a-z_]+)'/g)].map((entry) => entry[1]);
}

const UNCONFIRMED: FailureReason[] = ['status_unavailable', 'jwks_unavailable', 'jwks_stale', 'status_uri_untrusted'];

describe('classifyFailureReason (h-delegation-verifier-status-fallthrough-gate SC-3)', () => {
  it('positive control: the source scan actually finds reasons', () => {
    // A regex that stopped matching would make the completeness check below pass vacuously.
    expect(readFailureReasonUnion().length).toBeGreaterThan(15);
  });

  it('covers every FailureReason declared in types.ts, with no member left untested', () => {
    const declared = readFailureReasonUnion();
    const tested = new Set<string>(UNCONFIRMED);
    for (const reason of declared) {
      if (!UNCONFIRMED.includes(reason as FailureReason)) tested.add(reason);
    }
    expect([...tested].sort()).toEqual([...declared].sort());
  });

  it.each(UNCONFIRMED)('%s is unconfirmed — the check itself could not run', (reason) => {
    expect(classifyFailureReason(reason)).toBe('unconfirmed');
  });

  it.each(
    readFailureReasonUnion().filter((reason) => !UNCONFIRMED.includes(reason as FailureReason))
  )('%s is invalid — a completed check with a negative verdict', (reason) => {
    expect(classifyFailureReason(reason as FailureReason)).toBe('invalid');
  });

  it('a hypothetical reason added later without updating UNCONFIRMED defaults to invalid, not silently unconfirmed', () => {
    const outcome: FailureOutcome = classifyFailureReason('some_future_reason' as FailureReason);
    expect(outcome).toBe('invalid');
  });
});
