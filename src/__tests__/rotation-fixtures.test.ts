/**
 * Runs the shared key-rotation cases (`sdks/shared/fixtures/jwks_rotation/rotation_cases.json`)
 * through `verifyDelegation`. The same file drives the four SDKs, so a rule this package reads
 * differently from them fails here, not in production. Step semantics: the README beside the file.
 */

import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { clearTombstones, getJwksDiagnostics, refreshJwks, resetJwksCache, setJwksClockForTests } from '../jwks.js';
import { verifyDelegation } from '../verify.js';
import type { FetchLike, KeySetStore, VerifyOptions } from '../types.js';

interface FixtureStep {
  at: number;
  jwks: string | null;
  status_list?: string;
  action?: 'refresh' | 'reload' | 'clear_tombstones';
  verify?: string;
  status_check?: boolean;
  expect: {
    result?: string;
    fetches: number;
    pull_hint_handle?: string;
    cache_age_seconds?: number;
    events?: string[];
    vanished_kids?: string[];
  };
}

interface FixtureCase {
  name: string;
  spec_case: string;
  families: string[];
  requires?: string[];
  max_jwks_age_seconds?: number;
  steps: FixtureStep[];
}

interface Fixture {
  context: {
    issuer: string;
    jwks_uri: string;
    issuer_origin: string;
    status_list_uri: string;
    delegate: { type: 'url' | 'purl'; value: string };
    expected_principal: string;
    default_max_jwks_age_seconds: number;
  };
  documents: Record<string, unknown>;
  tokens: Record<string, { jwt: string; family: string }>;
  status_lists: Record<string, { jwt: string }>;
  cases: FixtureCase[];
}

const fixture = JSON.parse(
  readFileSync(new URL('../../../../sdks/shared/fixtures/jwks_rotation/rotation_cases.json', import.meta.url), 'utf8')
) as Fixture;

/** Token families this package verifies, and the optional capabilities it has. */
const FAMILIES = new Set(['delegation', 'status-list']);
const CAPABILITIES = new Set(['persistence']);

const runnable = fixture.cases.filter(
  (testCase) =>
    testCase.families.every((family) => FAMILIES.has(family)) &&
    (testCase.requires ?? []).every((capability) => CAPABILITIES.has(capability))
);

function memoryStore(): KeySetStore {
  const saved = new Map<string, string>();
  return {
    load: (jwksUri) => saved.get(jwksUri) ?? null,
    save: (jwksUri, state) => {
      saved.set(jwksUri, state);
    },
  };
}

afterEach(() => {
  setJwksClockForTests(null);
  resetJwksCache();
});

describe('shared key-rotation fixtures (h-verifier-jwks-multikey SC-1..SC-9)', () => {
  it('runs a meaningful share of the shared cases — a filter that skips everything must not pass', () => {
    expect(runnable.length).toBeGreaterThanOrEqual(20);
    expect(runnable.map((testCase) => testCase.name)).toEqual(
      expect.arrayContaining([
        'unknown_status_list_kid',
        'tombstone_persists_across_reload',
        'clear_tombstones_lifts_applied_tombstone',
        'tolerant_mode',
      ])
    );
  });

  it.each(runnable.map((testCase) => [testCase.name, testCase] as const))('%s', async (_name, testCase) => {
    const { context } = fixture;
    resetJwksCache();
    const store = memoryStore();
    let current: FixtureStep = testCase.steps[0];
    let jwksFetches = 0;
    let events: string[] = [];

    setJwksClockForTests({ monotonicMs: () => current.at * 1000, wallMs: () => current.at * 1000 });

    const routedFetch: FetchLike = async (input, init) => {
      expect(init?.redirect).toBe('error');
      const url = String(input);
      if (url === context.jwks_uri) {
        jwksFetches += 1;
        if (current.jwks === null) return new Response('unavailable', { status: 503 });
        return new Response(JSON.stringify(fixture.documents[current.jwks]), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url === context.status_list_uri) {
        if (!current.status_list) return new Response('not found', { status: 404 });
        return new Response(fixture.status_lists[current.status_list].jwt, { status: 200 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    };

    const onJwksEvent = (event: { type: string }) => {
      events.push(event.type);
    };

    for (const step of testCase.steps) {
      current = step;
      jwksFetches = 0;
      events = [];
      const where = `${testCase.name} @ t0+${step.at - fixture.cases[0].steps[0].at}s`;

      if (step.action === 'refresh') {
        await refreshJwks({ jwksUri: context.jwks_uri, fetch: routedFetch, keySetStore: store, onJwksEvent });
      } else if (step.action === 'reload') {
        resetJwksCache();
      } else if (step.action === 'clear_tombstones') {
        await clearTombstones({ jwksUri: context.jwks_uri, keySetStore: store });
      }

      if (step.verify) {
        const options: VerifyOptions = {
          trustedIssuers: [{ issuer: context.issuer, jwksUri: context.jwks_uri }],
          delegate: context.delegate,
          expectedPrincipal: context.expected_principal,
          statusCheck: step.status_check ? 'required' : 'skip',
          now: new Date(step.at * 1000),
          fetch: routedFetch,
          maxJwksAgeMs: (testCase.max_jwks_age_seconds ?? context.default_max_jwks_age_seconds) * 1000,
          keySetStore: store,
          onJwksEvent,
        };
        const result = await verifyDelegation(fixture.tokens[step.verify].jwt, options);
        const outcome = result.valid ? 'valid' : result.reason;
        expect(outcome, `${where}: ${result.valid ? '' : result.message}`).toBe(step.expect.result);
        if (step.expect.pull_hint_handle !== undefined) {
          expect(result.valid ? undefined : result.pullHint, where).toEqual({
            issuerOrigin: context.issuer_origin,
            handle: step.expect.pull_hint_handle,
          });
        }
        if (step.expect.cache_age_seconds !== undefined) {
          expect(result.valid ? undefined : result.cacheAgeSeconds, where).toBe(step.expect.cache_age_seconds);
          expect(result.valid ? undefined : result.refreshHint, where).toEqual({
            jwksUri: context.jwks_uri,
            method: 'refreshJwks',
          });
        }
      }

      expect(jwksFetches, `${where}: JWKS fetches`).toBe(step.expect.fetches);
      for (const expected of step.expect.events ?? []) {
        expect(events, `${where}: events`).toContain(expected);
      }
      if (step.expect.vanished_kids !== undefined) {
        expect(getJwksDiagnostics(context.jwks_uri)?.vanishedKids, where).toEqual(step.expect.vanished_kids);
      }
    }
  });
});
