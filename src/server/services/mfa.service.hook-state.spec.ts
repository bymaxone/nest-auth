/**
 * MfaService — the account the MFA hooks are handed.
 *
 * `afterMfaEnabled` and `afterMfaDisabled` run after the transition has been written, so the
 * account they receive has to describe the state the transition produced, not the record read
 * before it. These cases pin that for every site that fires the hooks, on both identity planes.
 * Kept apart from `mfa.service.spec.ts` because it is a separate responsibility and that file is
 * already over the size limit.
 */

import { createHash } from 'node:crypto'

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { encrypt } from '../crypto/aes-gcm'
import { generateHotp, generateTotpSecret } from '../crypto/totp'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MfaService } from './mfa.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

/** TEST FIXTURE ONLY: a structurally valid 32-byte AES-256-GCM key, not a credential. */
const VALID_ENCRYPTION_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')

/** TEST FIXTURE ONLY: not a real JWT secret. */
const JWT_SECRET = 'nest-auth-test-jwt-secret-32chars+'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

/** The fields that must never reach a hook, whatever the transition. */
const SECRET_FIELDS = ['passwordHash', 'mfaSecret', 'mfaRecoveryCodes'] as const

const DASHBOARD_BASE = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  passwordHash: 'hash'
}

const PLATFORM_BASE = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01'),
  passwordHash: 'hash'
}

const mockUserRepo = { findById: jest.fn(), updateMfa: jest.fn(), updateLastLogin: jest.fn() }
const mockPlatformUserRepo = {
  findById: jest.fn(),
  updateMfa: jest.fn(),
  updateLastLogin: jest.fn()
}

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  getdel: jest.fn(),
  setnx: jest.fn(),
  sadd: jest.fn(),
  srem: jest.fn(),
  expire: jest.fn(),
  setIfAbsent: jest.fn(),
  eval: jest.fn(),
  invalidateUserSessions: jest.fn(),
  bumpUserTokenEpoch: jest.fn()
}

const mockTokenManager = { issueTokens: jest.fn(), issuePlatformTokens: jest.fn() }
const mockBruteForce = {
  isLockedOut: jest.fn(),
  recordFailure: jest.fn(),
  resetFailures: jest.fn()
}
const mockPasswordService = { hash: jest.fn(), compare: jest.fn() }
const mockEmailProvider = {
  sendMfaEnabledNotification: jest.fn(),
  sendMfaDisabledNotification: jest.fn()
}
const mockHooks = { afterMfaEnabled: jest.fn(), afterMfaDisabled: jest.fn() }
const mockSessionService = { createSession: jest.fn(), revokeSession: jest.fn() }

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  mfa: {
    encryptionKey: VALID_ENCRYPTION_KEY,
    issuer: 'TestApp',
    totpWindow: 1,
    recoveryCodeCount: 2
  },
  sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

type Plane = 'dashboard' | 'platform'

/** A record as the repository holds it with MFA in the given state. */
function recordFor(plane: Plane, mfaEnabled: boolean, secret: string | null) {
  const base = plane === 'dashboard' ? DASHBOARD_BASE : PLATFORM_BASE
  return {
    ...base,
    mfaEnabled,
    mfaSecret: secret,
    mfaRecoveryCodes: mfaEnabled ? ['$scrypt$hashed$code1'] : null
  }
}

/** The repository for a plane, and the id and tenant argument the service is called with. */
function planeInputs(plane: Plane) {
  return plane === 'dashboard'
    ? { repo: mockUserRepo, userId: 'user-1', tenantId: 'tenant-1' as string | undefined }
    : { repo: mockPlatformUserRepo, userId: 'admin-1', tenantId: undefined }
}

/** The account a hook was handed on its first call. */
function handedTo(hook: jest.Mock): Record<string, unknown> {
  expect(hook).toHaveBeenCalledTimes(1)
  return hook.mock.calls[0]?.[0] as Record<string, unknown>
}

describe('MfaService — the account handed to the MFA hooks', () => {
  let service: MfaService

  beforeEach(async () => {
    jest.resetAllMocks()

    mockRedis.get.mockResolvedValue(null)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(true)
    mockRedis.setnx.mockResolvedValue(true)
    mockRedis.sadd.mockResolvedValue(1)
    mockRedis.srem.mockResolvedValue(1)
    mockRedis.expire.mockResolvedValue(undefined)
    mockRedis.setIfAbsent.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockRedis.bumpUserTokenEpoch.mockResolvedValue(undefined)
    mockUserRepo.updateMfa.mockResolvedValue(undefined)
    mockPlatformUserRepo.updateMfa.mockResolvedValue(undefined)
    mockBruteForce.isLockedOut.mockResolvedValue(false)
    mockBruteForce.recordFailure.mockResolvedValue(undefined)
    mockBruteForce.resetFailures.mockResolvedValue(undefined)
    mockPasswordService.compare.mockResolvedValue(true)
    mockEmailProvider.sendMfaEnabledNotification.mockResolvedValue(undefined)
    mockEmailProvider.sendMfaDisabledNotification.mockResolvedValue(undefined)

    const module = await Test.createTestingModule({
      providers: [
        MfaService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: SessionService, useValue: mockSessionService },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
      ]
    }).compile()

    service = module.get(MfaService)
  })

  /** A TOTP secret and a code that is valid for it right now. */
  function totpFixture(): { base32: string; code: string; encryptedSecret: string } {
    const { base32 } = generateTotpSecret()
    return {
      base32,
      code: generateHotp(base32, Math.floor(Date.now() / 1000 / 30)),
      encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
    }
  }

  // Scenario: enrolment completes. Expected: the hook is told MFA is now enabled. Why: it runs after
  // the second factor was written, and a handler that audits or alerts on the account would
  // otherwise record the state from before the transition.
  it.each(['dashboard', 'platform'] as const)(
    'hands afterMfaEnabled an account with MFA enabled on the %s plane',
    async (plane) => {
      const { repo, userId, tenantId } = planeInputs(plane)
      const before = recordFor(plane, false, null)
      repo.findById.mockResolvedValue(before)
      const { code, encryptedSecret } = totpFixture()
      const setupData = {
        encryptedSecret,
        hashedCodes: ['$scrypt$hashed$code1'],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.getdel.mockResolvedValue(JSON.stringify(setupData))

      await service.verifyAndEnable(userId, code, '1.2.3.4', 'Browser', plane, tenantId)

      const account = handedTo(mockHooks.afterMfaEnabled)
      expect(account['mfaEnabled']).toBe(true)
      expect(account['id']).toBe(userId)
      for (const field of SECRET_FIELDS) expect(account).not.toHaveProperty(field)
      // The repository's own record is not rewritten by building the projection.
      expect(before.mfaEnabled).toBe(false)
    }
  )

  // Scenario: the user disables MFA with a valid code. Expected: the hook is told MFA is now off.
  it.each(['dashboard', 'platform'] as const)(
    'hands afterMfaDisabled an account with MFA disabled after disable on the %s plane',
    async (plane) => {
      const { repo, userId, tenantId } = planeInputs(plane)
      const { code, encryptedSecret } = totpFixture()
      const before = recordFor(plane, true, encryptedSecret)
      repo.findById.mockResolvedValue(before)

      await service.disable(userId, code, '1.2.3.4', 'Browser', plane, tenantId)

      const account = handedTo(mockHooks.afterMfaDisabled)
      expect(account['mfaEnabled']).toBe(false)
      expect(account['id']).toBe(userId)
      for (const field of SECRET_FIELDS) expect(account).not.toHaveProperty(field)
      expect(before.mfaEnabled).toBe(true)
    }
  )

  // Scenario: an administrator removes the second factor. Expected: the same, because this path
  // fires the same hook and a handler cannot tell which path produced the call.
  it.each(['dashboard', 'platform'] as const)(
    'hands afterMfaDisabled an account with MFA disabled after resetMfa on the %s plane',
    async (plane) => {
      const { repo, userId, tenantId } = planeInputs(plane)
      const before = recordFor(plane, true, 'PLACEHOLDER_ENCRYPTED_SECRET')
      repo.findById.mockResolvedValue(before)

      await service.resetMfa(userId, plane, tenantId)

      const account = handedTo(mockHooks.afterMfaDisabled)
      expect(account['mfaEnabled']).toBe(false)
      expect(account['id']).toBe(userId)
      for (const field of SECRET_FIELDS) expect(account).not.toHaveProperty(field)
      expect(before.mfaEnabled).toBe(true)
    }
  )

  // Scenario: every other field of the account. Expected: unchanged by the projection, including the
  // tenant that separates the dashboard shape from the platform one.
  it('keeps the rest of the account intact for the hook', async () => {
    const { code, encryptedSecret } = totpFixture()
    mockUserRepo.findById.mockResolvedValue(recordFor('dashboard', true, encryptedSecret))

    await service.disable('user-1', code, '1.2.3.4', 'Browser', 'dashboard', 'tenant-1')

    expect(handedTo(mockHooks.afterMfaDisabled)).toEqual({
      id: 'user-1',
      email: 'user@example.com',
      name: 'Test User',
      role: 'member',
      status: 'active',
      tenantId: 'tenant-1',
      emailVerified: true,
      lastLoginAt: null,
      createdAt: new Date('2026-01-01'),
      mfaEnabled: false
    })
  })
})
