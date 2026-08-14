import type { Config } from 'jest'

/**
 * Jest configuration for end-to-end tests.
 *
 * Lives separately from the unit-test config (`jest.config.ts`) so that the
 * coverage thresholds enforced for the unit suite never interfere with E2E
 * runs, and so that E2E specs can be discovered under `test/e2e/` rather than
 * inside `src/`.
 */
const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: 'test/e2e',
  testMatch: ['**/*.e2e-spec.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  // Mirror the subpath aliases declared in tsconfig.json "paths" so e2e tests
  // and production code resolve the same module instance.
  moduleNameMapper: {
    '^@bymax-one/nest-auth$': '<rootDir>/../../src/server/index.ts',
    '^@bymax-one/nest-auth/shared$': '<rootDir>/../../src/shared/index.ts',
    '^@bymax-one/nest-auth/client$': '<rootDir>/../../src/client/index.ts',
    '^@bymax-one/nest-auth/react$': '<rootDir>/../../src/react/index.ts',
    '^@bymax-one/nest-auth/nextjs$': '<rootDir>/../../src/nextjs/index.ts',
    '^server-only$': '<rootDir>/../stubs/server-only.ts'
  },
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        tsconfig: '<rootDir>/../../tsconfig.e2e.json'
      }
    ]
  },
  testTimeout: 30_000,
  // The same bounds `jest.config.ts` and `jest.coverage.config.ts` carry, from #41 ("bound
  // mutation and jest memory to stop OOM restarts"). This config was the one place they were
  // never applied, and E2E is where they matter most: every spec boots a full Nest application
  // with its own ioredis-mock, so per-worker memory grows with the number of spec files rather
  // than with the number of tests.
  //
  // The symptom is not an assertion failure. Adding E2E specs made three unrelated suites fail
  // intermittently — password reset, platform MFA, refresh-token reuse — alongside `Test suite
  // failed to run`, which is a worker dying rather than a test disagreeing. Which suites break
  // depends on how Jest happens to distribute files across workers, so it reads as a flake in
  // whatever spec was added last.
  maxWorkers: '50%',
  workerIdleMemoryLimit: '1GB',
  clearMocks: true,
  restoreMocks: true,
  passWithNoTests: process.env['CI'] !== 'true'
}

export default config
