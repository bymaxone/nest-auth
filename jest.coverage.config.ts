import type { Config } from 'jest'

/**
 * Aggregated Jest configuration for unit + E2E coverage.
 *
 * Discovers both unit specs in `src/` and E2E specs in `test/e2e/` in a single
 * Jest run, and instruments every source file under `src/` regardless of which
 * suite touched it. Lines covered exclusively by E2E tests count toward the
 * 100% threshold, and vice-versa.
 *
 * Use this for release-time validation (`pnpm test:cov:all`) and CI gates.
 * Day-to-day development should still prefer the faster `pnpm test:cov`,
 * which only runs the unit suite.
 */
const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: '.',
  testMatch: [
    '<rootDir>/src/**/*.spec.ts',
    '<rootDir>/src/**/*.spec.tsx',
    '<rootDir>/test/e2e/**/*.e2e-spec.ts'
  ],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: '<rootDir>/tsconfig.e2e.json'
      }
    ]
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    'src/**/*.tsx',
    '!src/**/*.spec.ts',
    '!src/**/*.spec.tsx',
    '!src/**/*.test.ts',
    '!src/**/__tests__/**',
    '!src/**/index.ts',
    '!src/**/*.d.ts'
  ],
  coverageReporters: ['text', 'lcov', 'clover'],
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100
    }
  },
  testTimeout: 30_000,
  clearMocks: true,
  restoreMocks: true,
  passWithNoTests: process.env['CI'] !== 'true'
}

export default config
