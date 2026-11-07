/**
 * @fileoverview Jest configuration for `scripts/mutate-const-tables.mjs`.
 * @layer config
 *
 * The same unit tests as `jest.config.ts`, with ts-jest's type check turned off. The script removes
 * entries from `as const` tables one at a time and counts a mutant as killed when the test command
 * fails; a type check would fail on a removed property that other code reads, which a test did not
 * catch, so it would report as killed mutants Stryker would not. Not used by `pnpm test`.
 */
import type { Config } from 'jest'

import base from './jest.config.ts'

const config: Config = {
  ...base,
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/../tsconfig.jest.json', diagnostics: false }]
  }
}

export default config
