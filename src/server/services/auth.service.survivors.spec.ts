/**
 * AuthService — the effects of the refresh, the issue of tokens and the logout that a mutation of the
 * conditions around them would change: a session record rotated where sessions are off, an issue
 * gated on verification only where it is required, and an index revoked for no owner or no index.
 * Kept apart from `auth.service.spec.ts` because that file is already over the size limit.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { removeStoredSession } from '../utils/remove-session'
import { expectEvent } from '../__tests__/log-events'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AccountStatusService } from './account-status.service'
import { AuthService } from './auth.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

jest.mock('../utils/remove-session', () => ({ removeStoredSession: jest.fn() }))

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  passwordHash: 'scrypt:salt:hash',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}
const AUTH_RESULT = { user: USER, accessToken: 'access.jwt', rawRefreshToken: 'raw-refresh-uuid' }

const mockUserRepo = { findById: jest.fn() }
const mockHooks = { afterLogout: jest.fn() }
const mockRedis = {
  readSessionOwner: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  getUserTokenEpoch: jest.fn()
}
const mockTokenManager = {
  issueTokens: jest.fn(),
  reissueTokens: jest.fn(),
  verifyIgnoringExpiry: jest.fn()
}
const mockSessionService = {
  createSession: jest.fn(),
  rotateSession: jest.fn()
}

/** An `AuthService` over the doubles above, with the given sessions and verification options. */
async function build(sessionsEnabled: boolean, verificationRequired = false): Promise<AuthService> {
  const options = {
    jwt: { secret: JWT_SECRET },
    hmacKey: HMAC_KEY,
    previousHmacKeys: [],
    emailVerification: { required: verificationRequired, otpTtlSeconds: 600 },
    blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
    bruteForce: { maxAttempts: 5, windowSeconds: 900 },
    sessions: { enabled: sessionsEnabled, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
  }
  const module = await Test.createTestingModule({
    providers: [
      AuthService,
      { provide: BYMAX_AUTH_OPTIONS, useValue: options },
      { provide: GUARDED_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} },
      { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
      { provide: PasswordService, useValue: {} },
      { provide: TokenManagerService, useValue: mockTokenManager },
      { provide: BruteForceService, useValue: {} },
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: OtpService, useValue: {} },
      { provide: SessionService, useValue: mockSessionService },
      { provide: AccountStatusService, useValue: {} }
    ]
  }).compile()
  return module.get(AuthService)
}

beforeEach(() => {
  jest.resetAllMocks()
})

describe('AuthService.refresh', () => {
  // Scenario: a refresh with sessions off. Expected: the session index is not asked to rotate a record. Why: with sessions off there is no
  // `sd:` record to move to the new token, and the call would write one for a session nobody listed.
  it('does not rotate a session record when sessions are off', async () => {
    const service = await build(false)
    mockTokenManager.reissueTokens.mockResolvedValue({
      session: { userId: 'u1', tenantId: 't1', role: 'member' },
      accessToken: 'new.access',
      rawRefreshToken: 'new-refresh'
    })
    mockUserRepo.findById.mockResolvedValue({ ...USER, id: 'u1', tenantId: 't1' })
    mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
      role: 'member',
      tenantId: 't1',
      mfaEnabled: false
    })
    mockRedis.getUserTokenEpoch.mockResolvedValue(0)

    await service.refresh('old-refresh', '1.2.3.4', 'Browser')

    expect(mockSessionService.rotateSession).not.toHaveBeenCalled()
  })
})

describe('AuthService.issueTokensForUserId', () => {
  // Scenario: an unverified account while verification is not required. Expected: tokens are issued, and the event of the issue names
  // the user and the tenant. Why: the gate on verification applies only where it is required, and the event is how an issue is traced.
  it('issues tokens to an unverified user when verification is not required, and logs who got them', async () => {
    const service = await build(false)
    const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
    mockUserRepo.findById.mockResolvedValue({ ...USER, emailVerified: false })
    mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

    const result = await service.issueTokensForUserId('user-1', 'tenant-1', '1.2.3.4', 'Browser')

    expect(result).toBe(AUTH_RESULT)
    expectEvent(logSpy, 'AUTH_TOKENS_ISSUED', { userId: USER.id, tenantId: USER.tenantId })
    logSpy.mockRestore()
  })

  // Scenario: a verified account while verification is required. Expected: tokens are issued. Why: the gate refuses the unverified only.
  it('issues tokens to a verified user when verification is required', async () => {
    const service = await build(false, true)
    mockUserRepo.findById.mockResolvedValue({ ...USER, emailVerified: true })
    mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

    await expect(
      service.issueTokensForUserId('user-1', 'tenant-1', '1.2.3.4', 'Browser')
    ).resolves.toBe(AUTH_RESULT)
  })
})

describe('AuthService.logout and the index of sessions', () => {
  beforeEach(() => {
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(undefined)
    mockHooks.afterLogout.mockResolvedValue(undefined)
    mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ jti: 'jti1', exp: 9_999_999_999 })
  })

  // Scenario: the stored session names no owner, and neither does the marker of an earlier attempt. Expected: the index is not asked to
  // revoke anything. Why: a revoke for an empty user id names a key that belongs to nobody, and would read as a revocation that happened.
  it('skips the index revoke when no owner is known', async () => {
    const service = await build(true)
    mockRedis.readSessionOwner.mockResolvedValue({ userId: '', tenantId: 'tenant-1' })

    const owner = await service.logout('access.jwt', 'raw-refresh-token')

    expect(owner).toBe('')
    expect(removeStoredSession).not.toHaveBeenCalled()
  })

  // Scenario: the library runs with sessions off and the stored session names its owner. Expected: the index is not asked to revoke.
  // Why: there is no index to revoke from when sessions are off.
  it('skips the index revoke when sessions are off', async () => {
    const service = await build(false)
    mockRedis.readSessionOwner.mockResolvedValue({ userId: USER.id, tenantId: USER.tenantId })

    const owner = await service.logout('access.jwt', 'raw-refresh-token')

    expect(owner).toBe(USER.id)
    expect(removeStoredSession).not.toHaveBeenCalled()
  })
})
