import type { Config } from 'jest'

import base from './jest.e2e.config.ts'

/**
 * Jest configuration for the real-Redis end-to-end run (`pnpm test:e2e:redis`).
 *
 * The same harness and the same suites as `jest.e2e.config.ts`, pointed at a Redis server the
 * global setup starts in a container, for the suites whose behaviour rests on Lua scripts or on
 * semantics `ioredis-mock` only approximates. The list below is curated, with a reason per group;
 * a suite that only exercises HTTP shape gains nothing from a real server and stays on the mock.
 */
const config: Config = {
  ...base,
  globalSetup: '<rootDir>/real-redis/global-setup.ts',
  globalTeardown: '<rootDir>/real-redis/global-teardown.ts',
  testMatch: [
    // Atomic refresh-token rotation, the grace window and reuse detection: Lua scripts, and the
    // mock returns `undefined` where Redis returns nil.
    '<rootDir>/refresh-concurrency.e2e-spec.ts',
    '<rootDir>/refresh-reuse-detection.e2e-spec.ts',
    '<rootDir>/identifier-key-rotation.e2e-spec.ts',
    // Session index, eviction and the live-session checks: SET members, `sd:` records, the
    // grace-pointer reads.
    '<rootDir>/session-eviction.e2e-spec.ts',
    '<rootDir>/sessions-flow.e2e-spec.ts',
    '<rootDir>/live-session-required.e2e-spec.ts',
    // Revocation and the token epoch across a password change.
    '<rootDir>/password-reset-flow.e2e-spec.ts',
    '<rootDir>/auth-flow.e2e-spec.ts',
    // Single-use claims, counters and TTLs: MFA codes and recovery codes, invitations, email
    // change, WebSocket tickets.
    '<rootDir>/mfa-flow.e2e-spec.ts',
    '<rootDir>/mfa-recovery-codes-flow.e2e-spec.ts',
    '<rootDir>/invitations-flow.e2e-spec.ts',
    '<rootDir>/invitation-claim-window.e2e-spec.ts',
    '<rootDir>/email-change-flow.e2e-spec.ts',
    '<rootDir>/ws-ticket-expiry.e2e-spec.ts',
    // Rate limiting and brute-force counters.
    '<rootDir>/rate-limit.e2e-spec.ts',
    '<rootDir>/negative-paths.e2e-spec.ts',
    '<rootDir>/platform-auth-flow.e2e-spec.ts'
  ],
  // The container, the Docker client and one ioredis connection per bootstrap leave handles
  // Jest cannot trace; the run ends when the suites do.
  forceExit: true,
  // One container and its connection budget are shared by every worker.
  maxWorkers: 2,
  testTimeout: 60_000
}

export default config
