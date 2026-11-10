/**
 * @fileoverview Pins every value in `DEFAULT_OPTIONS` as one object, so a changed, dropped or
 * added default appears as a diff in this file and goes through review.
 *
 * The defaults are security-relevant (token lifetimes, lockout budget, which controllers mount),
 * and `resolveOptions` spreads them under whatever the host supplies. A value that drifts here
 * changes every deployment that did not set it, and no behavioural test names it.
 */

import { DEFAULT_OPTIONS } from './default-options'

/** The reviewed defaults. Edit this object and `default-options.ts` together, in one change. */
const EXPECTED_DEFAULTS = {
  jwt: {
    accessExpiresIn: '15m',
    accessCookieMaxAgeMs: 900_000,
    refreshExpiresInDays: 7,
    absoluteSessionLifetimeDays: 30,
    algorithm: 'HS256',
    refreshGraceWindowSeconds: 30
  },
  password: {
    minLength: 15,
    costFactor: 131_072,
    blockSize: 8,
    parallelization: 1,
    blocklist: []
  },
  tokenDelivery: 'cookie',
  cookies: {
    accessTokenName: 'access_token',
    refreshTokenName: 'refresh_token',
    sessionSignalName: 'has_session',
    refreshCookiePath: '/auth',
    mfaTempCookiePath: '/auth/mfa',
    sameSite: 'lax',
    trustedOrigins: []
  },
  rateLimit: { enabled: true },
  mfa: { recoveryCodeCount: 8, totpWindow: 1 },
  sessions: { enabled: false, defaultMaxSessions: 5 },
  bruteForce: { maxAttempts: 5, windowSeconds: 900 },
  passwordReset: { method: 'token', tokenTtlSeconds: 600, otpTtlSeconds: 600, otpLength: 6 },
  emailVerification: { required: true, otpTtlSeconds: 600 },
  platform: { enabled: false },
  emailChange: { tokenTtlSeconds: 3_600 },
  invitations: { enabled: false, tokenTtlSeconds: 172_800 },
  apiKeys: {
    enabled: false,
    pepper: '',
    scopes: [],
    header: 'x-api-key',
    prefix: 'bak',
    lastUsedFlushSeconds: 60,
    auditMode: 'best-effort'
  },
  controllers: {
    auth: true,
    mfa: false,
    passwordReset: true,
    sessions: false,
    platform: false,
    oauth: false,
    invitations: false,
    emailChange: false,
    workspaces: false,
    workspaceInvitations: false
  },
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  redisNamespace: 'auth',
  routePrefix: 'auth',
  userStatusCacheTtlSeconds: 60
}

describe('DEFAULT_OPTIONS', () => {
  it('equals the reviewed defaults, group by group and value by value', () => {
    // Arrange / Act: the exported object is the subject, nothing is resolved or mocked.
    // Assert: strict equality fails on any extra, missing or changed key, including a number
    // that moved by one.
    expect(DEFAULT_OPTIONS).toStrictEqual(EXPECTED_DEFAULTS)
  })
})
