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
    // A session born in one script: the records written with it, each with its own lifetime.
    '<rootDir>/login-atomic-session-write.e2e-spec.ts',
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
    // The WebSocket guard consuming a ticket: the record is read back from the server.
    '<rootDir>/ws-guard.e2e-spec.ts',
    // The workspace membership cache: two Lua scripts and version counters whose order and
    // retention only a real server proves.
    '<rootDir>/workspace-access.e2e-spec.ts',
    // The sweep over host reads: its workspace calls run the membership cache's scripts.
    '<rootDir>/host-read-sweep.e2e-spec.ts',
    // The OTP attempt counter as the verify script reads it, an empty string included.
    '<rootDir>/real-redis/otp-attempts.e2e-spec.ts',
    // A command the server answers with a reply error, which names the command that failed.
    '<rootDir>/real-redis/reply-error.e2e-spec.ts',
    // Rate limiting and brute-force counters.
    '<rootDir>/rate-limit.e2e-spec.ts',
    '<rootDir>/negative-paths.e2e-spec.ts',
    '<rootDir>/platform-auth-flow.e2e-spec.ts',
    // A client that answers integers as strings: only a real client builds that reply.
    '<rootDir>/real-redis/string-replies.e2e-spec.ts',
    // A store that stops answering: the suite pauses and stops its own container.
    '<rootDir>/real-redis/redis-outage.e2e-spec.ts',
    // A revocation the server refuses by ACL: only a real server refuses a key a script declares.
    '<rootDir>/real-redis/partial-revoke.e2e-spec.ts',
    // A client with `keyPrefix`: the names the scripts build must be the ones the client writes.
    '<rootDir>/real-redis/key-prefix.e2e-spec.ts'
  ],
  testPathIgnorePatterns: ['/node_modules/'],
  // The container, the Docker client and one ioredis connection per bootstrap leave handles
  // Jest cannot trace; the run ends when the suites do.
  forceExit: true,
  // One container and its connection budget are shared by every worker.
  maxWorkers: 2,
  testTimeout: 60_000
}

export default config
