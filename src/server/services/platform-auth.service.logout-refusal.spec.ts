/**
 * PlatformAuthService.logout — what a refused revocation write does.
 *
 * Logout is a promise that the administrator's credentials stop working. It writes the access-token
 * blacklist entry, the refresh session and its rotation grace pointer, and prunes the session index.
 * When the store refuses a write, answering success would claim a revocation that did not happen,
 * so every write is attempted and the first failure is raised after the rest have run. Kept apart
 * from `platform-auth.service.spec.ts` because it is a separate responsibility.
 */

import { createHash } from 'node:crypto'

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_PLATFORM_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertRootIsStandard } from '../utils/object-prototype-guard'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { PlatformAuthService } from './platform-auth.service'
import { TokenManagerService } from './token-manager.service'

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const RAW_REFRESH = 'raw-platform-refresh-token'
const HASH = createHash('sha256').update(RAW_REFRESH).digest('hex')
const JTI = 'platform-jti-under-test'
const ADMIN_ID = 'admin-1'

const mockRedis = {
  readSessionOwner: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  get: jest.fn(),
  srem: jest.fn()
}
const mockTokenManager = { verifyPlatformIgnoringExpiry: jest.fn() }
const mockHooks = { afterPlatformLogout: jest.fn() }

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: []
}

/** What a store under memory pressure answers to a write it refuses. */
const STORE_REFUSED = new Error('OOM command not allowed when used memory > maxmemory')
const OTHER_REFUSAL = new Error('READONLY You can not write against a read only replica')

/** Lets a fire-and-forget hook settle before the assertion reads it. */
async function flushMicrotasks(ticks = 4): Promise<void> {
  for (let i = 0; i < ticks; i += 1) await Promise.resolve()
}

describe('PlatformAuthService.logout when the verification of the access token refuses', () => {
  let service: PlatformAuthService

  beforeEach(async () => {
    jest.resetAllMocks()
    mockRedis.readSessionOwner.mockResolvedValue({ userId: ADMIN_ID, tenantId: undefined })
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(undefined)
    mockRedis.srem.mockResolvedValue(1)
    mockHooks.afterPlatformLogout.mockResolvedValue(undefined)
    mockTokenManager.verifyPlatformIgnoringExpiry.mockReturnValue({
      jti: JTI,
      sub: ADMIN_ID,
      exp: Math.floor(Date.now() / 1000) + 900
    })

    const module = await Test.createTestingModule({
      providers: [
        PlatformAuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: GUARDED_PLATFORM_USER_REPOSITORY, useValue: {} },
        { provide: PasswordService, useValue: {} },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: {} },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
      ]
    }).compile()
    service = module.get(PlatformAuthService)
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
    mockTokenManager.verifyPlatformIgnoringExpiry.mockImplementation(() => {
      throw thrown
    })

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(thrown)

    expect(mockRedis.set).not.toHaveBeenCalled()
  })

  // Scenario: the same verification failing the ordinary way (a malformed or foreign token). Expected: logout still completes
  // and writes no blacklist entry. Why: the control: only the refusal is let through, the tolerance for a token nobody can verify stays.
  it('still completes when the token simply does not verify', async () => {
    mockTokenManager.verifyPlatformIgnoringExpiry.mockImplementation(() => {
      throw new Error('invalid signature')
    })

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toEqual(expect.any(String))

    expect(mockRedis.set).not.toHaveBeenCalled()
  })
})
