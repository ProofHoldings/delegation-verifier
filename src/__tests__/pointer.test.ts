/**
 * The DNS pointer, from OUTSIDE the package.
 *
 * Every case here imports through `../index.js` rather than `../carriers.js`, and that is the
 * point: a parser that exists in the file but is not exported makes "the reference verifier reads
 * the fourth carrier" true of the source tree and false of every consumer. The behaviour itself is
 * pinned against the issuer's copy by `src/__tests__/drift/delegation-verifier.test.ts` in the
 * issuer repository; what this file adds is reachability, and the package's own coverage of a copy
 * that until now was only ever executed by that other repository's suite.
 */

import { describe, expect, it } from 'vitest';
import {
  parseDelegationPointer,
  pointerRecordName,
  POINTER_VERSION,
  POINTER_RECORD_PREFIX,
} from '../index.js';

const CARD = 'https://example.com/.well-known/mcp/server.json';

describe('the pointer is reachable from the package entry point', () => {
  it('exports the parser and its constants', () => {
    expect(typeof parseDelegationPointer).toBe('function');
    expect(POINTER_VERSION).toBe('proofdlg1');
    expect(POINTER_RECORD_PREFIX).toBe('_mcp');
    expect(pointerRecordName('example.com')).toBe('_mcp.example.com');
  });

  it('reads a well-formed pointer', () => {
    expect(parseDelegationPointer([`v=${POINTER_VERSION}; card=${CARD}`])).toEqual({ ok: true, card: CARD });
  });

  it('leaves a record belonging to the MCP discovery draft alone', () => {
    expect(parseDelegationPointer(['v=mcp1; url=https://example.com/mcp'])).toEqual({
      ok: false,
      reason: 'no_pointer',
    });
  });

  it('refuses to pick between two of ours naming different cards', () => {
    expect(
      parseDelegationPointer([
        `v=${POINTER_VERSION}; card=https://a.example/c.json`,
        `v=${POINTER_VERSION}; card=https://b.example/c.json`,
      ])
    ).toEqual({ ok: false, reason: 'ambiguous_pointer' });
  });

  it.each([
    ['as the card value', (t: string) => `v=${POINTER_VERSION}; card=${t}`],
    // The shape a code review used to slip a real token past this check: anything dot-separated in
    // front of it hid the token from a scan over non-overlapping matches. Kept here as well as in
    // the issuer repository's drift vector, because a bug shared by both copies is exactly the one
    // a lockstep comparison cannot see.
    ['behind a dotted pair in the card URL', (t: string) => `v=${POINTER_VERSION}; card=https://cards.example.com/v1beta.rel2024.${t}`],
    ['behind a dotted pair in an unknown field', (t: string) => `v=${POINTER_VERSION}; card=${CARD}; note=abcd.efgh.${t}`],
    ['glued to a hyphen inside the card URL', (t: string) => `v=${POINTER_VERSION}; card=https://example.com/delegation-${t}`],
    ['glued to a letter inside the card URL', (t: string) => `v=${POINTER_VERSION}; card=https://example.com/x${t}`],
  ])('refuses a token %s', (_label, build) => {
    const token = [
      Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url'),
      Buffer.from(JSON.stringify({ sub: 'ph_dlg_x' })).toString('base64url'),
      'c2ln',
    ].join('.');

    expect(parseDelegationPointer([build(token)])).toEqual({ ok: false, reason: 'token_in_dns' });
  });

  it('does not mistake a three-label hostname for a token', () => {
    const card = 'https://discovery.mcp-servers.engineering/card.json';
    expect(parseDelegationPointer([`v=${POINTER_VERSION}; card=${card}`])).toEqual({ ok: true, card });
  });
});
