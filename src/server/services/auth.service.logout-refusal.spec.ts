/**
 * AuthService.logout — what a refused revocation write does.
 *
 * Logout is a promise that the caller's credentials stop working. It writes three things that keep
 * that promise: the access-token blacklist entry, the refresh session and its rotation grace
 * pointer. When the store refuses one of them, answering success would claim a revocation that did
 * not happen, so every write is attempted and the first failure is raised after the rest have run.
 * Kept apart from `auth.service.spec.ts` because it is a separate responsibility and that file is
 * already over the size limit.
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
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertRootIsStandard } from '../utils/object-prototype-guard'
import { AccountStatusService } from './account-status.service'
import { AuthService } from './auth.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const RAW_REFRESH = 'raw-refresh-token'
const HASH = createHash('sha256').update(RAW_REFRESH).digest('hex')
const JTI = 'jti-under-test'

const mockRedis = { readSessionOwner: jest.fn(), set: jest.fn(), del: jest.fn(), get: jest.fn() }
const mockTokenManager = { verifyIgnoringExpiry: jest.fn() }
const mockSessionService = { removeSession: jest.fn() }
const mockHooks = { afterLogout: jest.fn() }

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

/** What a store under memory pressure answers to a write it refuses. */
const STORE_REFUSED = new Error('OOM command not allowed when used memory > maxmemory')
const OTHER_REFUSAL = new Error('READONLY You can not write against a read only replica')

/** Lets a fire-and-forget hook settle before the assertion reads it. */
async function flushMicrotasks(ticks = 4): Promise<void> {
  for (let i = 0; i < ticks; i += 1) await Promise.resolve()
}

describe('AuthService.logout when the verification of the access token refuses', () => {
  let service: AuthService

  beforeEach(async () => {
    jest.resetAllMocks()
    mockRedis.readSessionOwner.mockResolvedValue({ userId: 'user-1', tenantId: 'tenant-1' })
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(undefined)
    mockSessionService.removeSession.mockResolvedValue(undefined)
    mockHooks.afterLogout.mockResolvedValue(undefined)
    mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
      jti: JTI,
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 900
    })

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: GUARDED_USER_REPOSITORY, useValue: {} },
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
    service = module.get(AuthService)
  })

  /** What the guard throws while a key is planted on the root: the library's own refusal, made by the guard itself. */
  const refusal = (): unknown => {
    Object.defineProperty(Object.prototype, 'sessions', {
      value: 1,
      configurable: true,
      enumerable: true,
      writable: true
    })
    try {
      assertRootIsStandard()
    } catch (error) {
      return error
    } finally {
      Reflect.deleteProperty(Object.prototype, 'sessions')
    }
    return undefined
  }

  // Scenario: the verification of the access token, which logout makes to decide what to blacklist, refuses with the library's own
  // refusal (a key is planted on the root). Expected: logout rejects with that refusal and writes no blacklist entry. Why: a
  // `catch` that turns every failure into "nothing to blacklist" would answer success for a logout whose access token is still valid.
  it('rejects with the refusal and does not answer success', async () => {
    const thrown = refusal()
    mockTokenManager.verifyIgnoringExpiry.mockImplementation(() => {
      throw thrown
    })

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(thrown)

    expect(mockRedis.set).not.toHaveBeenCalled()
  })

  // Scenario: the same verification failing the ordinary way (a malformed or foreign token). Expected: logout still completes
  // and writes no blacklist entry. Why: the control: only the refusal is let through, the tolerance for a token nobody can verify stays.
  it('still completes when the token simply does not verify', async () => {
    mockTokenManager.verifyIgnoringExpiry.mockImplementation(() => {
      throw new Error('invalid signature')
    })

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toEqual(expect.any(String))

    expect(mockRedis.set).not.toHaveBeenCalled()
  })
})
