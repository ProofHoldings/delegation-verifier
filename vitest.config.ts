import { existsSync } from 'node:fs';
import { configDefaults, defineConfig } from 'vitest/config';

// `sdks/shared/fixtures` — the cases every verifier runs — exists only in the monorepo. The public
// mirror (ProofHoldings/delegation-verifier) has no copy, and the fixture README forbids one, so there
// the suite that cannot even load without it is left out; it runs on every pull request to the
// monorepo. `verify.test.ts` reads one fixture too, and gates that read itself.
const HAS_SHARED_FIXTURES = existsSync(new URL('../../sdks/shared/fixtures', import.meta.url));

export default defineConfig({
  test: {
    include: ['src/__tests__/**/*.test.ts'],
    exclude: [...configDefaults.exclude, ...(HAS_SHARED_FIXTURES ? [] : ['src/__tests__/rotation-fixtures.test.ts'])],
    environment: 'node',
  },
});
