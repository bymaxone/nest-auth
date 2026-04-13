import type { Config } from 'jest'

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: 'src',
  testMatch: ['**/*.spec.ts', '**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        tsconfig: '<rootDir>/../tsconfig.jest.json'
      }
    ]
  },
  collectCoverageFrom: ['**/*.ts', '!**/*.spec.ts', '!**/*.test.ts', '!**/index.ts', '!**/*.d.ts'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    },
    // Paths are relative to the project root (where jest.config.ts lives), not rootDir
    './src/server/crypto/': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95
    },
    './src/server/guards/': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95
    }
  },
  coverageReporters: ['text', 'lcov', 'clover'],
  clearMocks: true,
  restoreMocks: true,
  // Only skip "no tests" error in local dev — CI must always have tests
  passWithNoTests: process.env['CI'] !== 'true'
}

export default config
