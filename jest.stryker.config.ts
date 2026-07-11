import type { Config } from 'jest'

// Explicit `.ts` extension is required: Stryker loads this config in a child
// process via native ESM `import()`, and Node's ESM resolver (type-stripping,
// Node 24+) does not guess extensions — an extensionless './jest.config' throws
// ERR_MODULE_NOT_FOUND in the sandbox.
import base from './jest.config.ts'

/**
 * Stryker-only Jest configuration.
 *
 * Layer: config.
 *
 * Wraps the base unit-test config (`jest.config.ts`) with Stryker's
 * instrumented Node test environment so that `coverageAnalysis: "perTest"`
 * can map every mutant to the exact tests that cover it. The base config is
 * left untouched (its `testEnvironment` stays the plain `'node'`) so that a
 * normal `pnpm test` never depends on the mutation-testing toolchain.
 *
 * The four React specs override the environment to jsdom via a
 * `@jest-environment` docblock; those docblocks point at Stryker's jsdom
 * wrapper, which is transparent when Stryker is not running. Only used by
 * `stryker run` through `jest.configFile` in `stryker.config.json`.
 */
const config: Config = {
  ...base,
  testEnvironment: '@stryker-mutator/jest-runner/jest-env/node'
}

export default config
