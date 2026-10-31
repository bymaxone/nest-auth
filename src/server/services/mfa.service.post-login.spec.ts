/**
 * MfaService — what runs when a challenge completes.
 *
 * Completing the challenge is the login for an MFA account: the password step (or the OAuth
 * callback) stopped short of recording it, so this is the one place the last-login time can move
 * and the host's `afterLogin` hook can run. Neither may change the outcome of a challenge that
 * has already passed. Kept apart from `mfa.service.spec.ts` because it is a separate
 * responsibility and that file is already over the size limit.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MfaService } from './mfa.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

/** TEST FIXTURE ONLY: a structurally valid 32-byte AES-256-GCM key, not a credential. */
const VALID_ENCRYPTION_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')

const SAFE_USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const AUTH_USER_MFA_ENABLED = {
  ...SAFE_USER,
  passwordHash: 'hash',
  mfaEnabled: true,
  mfaSecret: 'PLACEHOLDER_ENCRYPTED_SECRET', // replaced per test with a real encrypted value
  mfaRecoveryCodes: ['$scrypt$hashed$code1', '$scrypt$hashed$code2']
}

const SAFE_ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01')
}

const MOCK_AUTH_RESULT = {
  user: SAFE_USER,
  accessToken: 'access.jwt',
  rawRefreshToken: 'mock-refresh-token-dashboard'
}

const mockUserRepo = {
  findById: jest.fn(),
  updateMfa: jest.fn(),
  updateLastLogin: jest.fn()
}

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

const mockTokenManager = {
  verifyMfaTempToken: jest.fn(),
  consumeMfaTempToken: jest.fn(),
  issueTokens: jest.fn(),
  issuePlatformTokens: jest.fn()
}

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

const mockHooks = { afterLogin: jest.fn() }

const mockSessionService = {
  createSession: jest.fn(),
  revokeSession: jest.fn(),
  rotateSession: jest.fn()
}

// TEST FIXTURE ONLY: a derived key the service never checks against a real secret here.
const mockOptions = {
  jwt: { secret: 'nest-auth-test-jwt-secret-32chars+' },
  hmacKey: 'f'.repeat(64),
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

describe('MfaService — challenge completion side effects', () => {
  let service: MfaService

  beforeEach(async () => {
    jest.resetAllMocks()
    jest.useFakeTimers()
    jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))

    mockRedis.get.mockResolvedValue(null)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(true)
    mockRedis.setnx.mockResolvedValue(true)
    mockRedis.sadd.mockResolvedValue(1)
    mockRedis.srem.mockResolvedValue(1)
    mockRedis.expire.mockResolvedValue(undefined)
    mockRedis.setIfAbsent.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockTokenManager.consumeMfaTempToken.mockResolvedValue(true)
    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard',
      tenantId: 'tenant-1',
      jti: 'jti-test-1'
    })
    mockTokenManager.issueTokens.mockResolvedValue(MOCK_AUTH_RESULT)
    mockBruteForce.isLockedOut.mockResolvedValue(false)
    mockBruteForce.recordFailure.mockResolvedValue(undefined)
    mockBruteForce.resetFailures.mockResolvedValue(undefined)

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

  afterEach(() => {
    jest.useRealTimers()
  })

  // Completing the challenge is the login for an MFA account: the password step (or the OAuth
  // callback) stopped short of recording it, so this is the one place the last-login time can
  // move. Without it an MFA account's last login never changes.
  it.each([
    ['dashboard', 'user-1'],
    ['platform', 'admin-1']
  ] as const)('should record the last login when a %s challenge completes', async (context, id) => {
    const { encrypt } = await import('../crypto/aes-gcm')
    const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
    const { base32 } = generateTotpSecret()
    const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
    mockRedis.setnx.mockResolvedValue(true)
    mockUserRepo.updateLastLogin.mockResolvedValue(undefined)
    mockPlatformUserRepo.updateLastLogin.mockResolvedValue(undefined)
    const account = {
      ...(context === 'dashboard' ? AUTH_USER_MFA_ENABLED : SAFE_ADMIN),
      passwordHash: 'hash',
      mfaEnabled: true,
      mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
      mfaRecoveryCodes: []
    }
    if (context === 'dashboard') {
      mockUserRepo.findById.mockResolvedValue(account)
    } else {
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: id,
        context: 'platform',
        jti: 'jti-last-login'
      })
      mockPlatformUserRepo.findById.mockResolvedValue(account)
      mockTokenManager.issuePlatformTokens.mockResolvedValue({
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'token'
      })
    }

    await service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')
    await Promise.resolve()
    await Promise.resolve()

    if (context === 'dashboard') {
      expect(mockUserRepo.updateLastLogin).toHaveBeenCalledTimes(1)
      expect(mockUserRepo.updateLastLogin).toHaveBeenCalledWith({
        id,
        tenantId: SAFE_USER.tenantId
      })
      expect(mockPlatformUserRepo.updateLastLogin).not.toHaveBeenCalled()
    } else {
      expect(mockPlatformUserRepo.updateLastLogin).toHaveBeenCalledTimes(1)
      expect(mockPlatformUserRepo.updateLastLogin).toHaveBeenCalledWith(id)
      expect(mockUserRepo.updateLastLogin).not.toHaveBeenCalled()
    }
  })

  // The platform plane has its own label, so an operator can tell which store failed.
  it('should complete the platform challenge when recording the last login fails', async () => {
    const { encrypt } = await import('../crypto/aes-gcm')
    const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
    const { base32 } = generateTotpSecret()
    const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
    mockRedis.setnx.mockResolvedValue(true)
    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'admin-1',
      context: 'platform',
      jti: 'jti-platform-last-login'
    })
    mockPlatformUserRepo.findById.mockResolvedValue({
      ...SAFE_ADMIN,
      passwordHash: 'hash',
      mfaEnabled: true,
      mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
      mfaRecoveryCodes: []
    })
    mockTokenManager.issuePlatformTokens.mockResolvedValue({
      admin: SAFE_ADMIN,
      accessToken: 'platform.jwt',
      rawRefreshToken: 'token'
    })
    mockPlatformUserRepo.updateLastLogin.mockRejectedValue(new Error('db down'))
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

    await expect(
      service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')
    ).resolves.toBeDefined()
    await Promise.resolve()
    await Promise.resolve()

    expect(error.mock.calls.map((c) => String(c[0])).join('\n')).toContain(
      'challenge: platform updateLastLogin failed'
    )
  })

  // A failing last-login write must not undo a challenge that already passed.
  it('should complete the challenge when recording the last login fails', async () => {
    const { encrypt } = await import('../crypto/aes-gcm')
    const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
    const { base32 } = generateTotpSecret()
    const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
    mockRedis.setnx.mockResolvedValue(true)
    mockUserRepo.findById.mockResolvedValue({
      ...AUTH_USER_MFA_ENABLED,
      mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
    })
    mockUserRepo.updateLastLogin.mockRejectedValue(new Error('db down'))
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

    await expect(service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')).resolves.toBe(
      MOCK_AUTH_RESULT
    )
    await Promise.resolve()
    await Promise.resolve()

    expect(error.mock.calls.map((c) => String(c[0])).join('\n')).toContain('updateLastLogin failed')
  })

  // A hook that throws SYNCHRONOUSLY must not undo a challenge that has already passed and
  // issued its tokens, on either plane; the failure is logged by label only, never by the text
  // the host's hook wrote.
  it.each(['dashboard', 'platform'] as const)(
    'should complete the %s challenge when afterLogin throws synchronously',
    async (context) => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined)
      mockPlatformUserRepo.updateLastLogin.mockResolvedValue(undefined)
      const account = {
        ...(context === 'dashboard' ? AUTH_USER_MFA_ENABLED : SAFE_ADMIN),
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      }
      if (context === 'dashboard') {
        mockUserRepo.findById.mockResolvedValue(account)
      } else {
        mockTokenManager.verifyMfaTempToken.mockResolvedValue({
          userId: 'admin-1',
          context: 'platform',
          jti: 'jti-sync-throw'
        })
        mockPlatformUserRepo.findById.mockResolvedValue(account)
        mockTokenManager.issuePlatformTokens.mockResolvedValue({
          admin: SAFE_ADMIN,
          accessToken: 'platform.jwt',
          rawRefreshToken: 'token'
        })
      }
      mockHooks.afterLogin.mockImplementation(() => {
        throw new Error('host secret=XYZ')
      })
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      await expect(
        service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeDefined()

      const lines = error.mock.calls.map((c) => String(c[0]))
      expect(lines.some((l) => l.includes('challenge: afterLogin hook threw'))).toBe(true)
      expect(lines.join('\n')).not.toContain('XYZ')
    }
  )
})
