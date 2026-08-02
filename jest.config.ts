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
    '^@bymax-one/nest-auth/nextjs$': '<rootDir>/nextjs/index.ts',
    '^server-only$': '<rootDir>/../test/stubs/server-only.ts'
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
  // 100% across the board. The lib already meets it (verified via test:cov:all),
  // so the day-to-day `pnpm test:cov` enforces the same hard gate as the release
  // `test:cov:all` — no drift between local and CI. A global 100% makes the
  // former per-directory 95% overrides (crypto/, guards/) redundant.
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100
    }
  },
  coverageReporters: ['text', 'lcov', 'clover'],
  // Bound peak memory: cap the worker pool at half the cores and recycle any
  // worker that grows past ~1GB. ts-jest reloads the whole module graph per
  // worker, so an unbounded pool multiplies memory (workers × module graph);
  // recycling also stops slow heap growth from accumulating across many files.
  // Under Stryker the jest-runner sets its own worker model, so these are inert
  // there — Stryker's own `concurrency` / `maxTestRunnerReuse` bound that path.
  maxWorkers: '50%',
  workerIdleMemoryLimit: '1GB',
  clearMocks: true,
  restoreMocks: true,
  // Only skip "no tests" error in local dev — CI must always have tests
  passWithNoTests: process.env['CI'] !== 'true'
}

export default config
