import type { Config } from 'jest'

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: 'src',
  testMatch: ['**/*.spec.ts', '**/*.spec.tsx', '**/*.test.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json'],
  // Mirror the subpath aliases declared in tsconfig.json "paths" so that tests
  // exercise the exact same import specifiers that consumers and the tsup
  // bundler use. Without this, tests would need relative imports while build
  // uses package specifiers — an easy source of drift.
  moduleNameMapper: {
    '^@bymax-one/nest-auth$': '<rootDir>/server/index.ts',
    '^@bymax-one/nest-auth/shared$': '<rootDir>/shared/index.ts',
    '^@bymax-one/nest-auth/client$': '<rootDir>/client/index.ts',
    '^@bymax-one/nest-auth/react$': '<rootDir>/react/index.ts',
    '^@bymax-one/nest-auth/nextjs$': '<rootDir>/nextjs/index.ts'
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: '<rootDir>/../tsconfig.jest.json'
      }
    ]
  },
  collectCoverageFrom: [
    '**/*.ts',
    '**/*.tsx',
    '!**/*.spec.ts',
    '!**/*.spec.tsx',
    '!**/*.test.ts',
    '!**/__tests__/**',
    '!**/index.ts',
    '!**/*.d.ts'
  ],
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
