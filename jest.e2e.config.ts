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
    '^@bymax-one/nest-auth/nextjs$': '<rootDir>/../../src/nextjs/index.ts'
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
  clearMocks: true,
  restoreMocks: true,
  passWithNoTests: process.env['CI'] !== 'true'
}

export default config
