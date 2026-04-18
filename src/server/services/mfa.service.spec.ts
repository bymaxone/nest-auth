/**
 * @fileoverview Tests for MfaService — TOTP setup, verify-enable, challenge, and disable flows.
 *
 * All external dependencies (Redis, repositories, email, brute-force) are mocked.
 * The AES-256-GCM encrypt/decrypt functions are exercised with a real key to avoid
 * mocking crypto internals, consistent with the project's testing guidelines.
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
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MfaService } from './mfa.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

/**
 * Valid 32-byte AES-256-GCM key for testing encrypt/decrypt.
 * TEST FIXTURE ONLY — not a real credential.
 * A deterministic key derived from a constant, safe to use in tests and
 * structurally valid for AES-256-GCM (exactly 32 bytes).
 */
const VALID_ENCRYPTION_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

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

const AUTH_USER_MFA_DISABLED = {
  ...SAFE_USER,
  passwordHash: 'hash',
  mfaEnabled: false,
  mfaSecret: null,
  mfaRecoveryCodes: null
}

const AUTH_USER_MFA_ENABLED = {
  ...SAFE_USER,
  passwordHash: 'hash',
  mfaEnabled: true,
  mfaSecret: 'PLACEHOLDER_ENCRYPTED_SECRET', // replaced per-test with a real encrypted value
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

const mockUserRepo = {
  findById: jest.fn(),
  updateMfa: jest.fn()
}

const mockPlatformUserRepo = {
  findById: jest.fn(),
  updateMfa: jest.fn()
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
  invalidateUserSessions: jest.fn()
}

const mockTokenManager = {
  verifyMfaTempToken: jest.fn(),
  issueTokens: jest.fn(),
  issuePlatformTokens: jest.fn()
}

const mockBruteForce = {
  isLockedOut: jest.fn(),
  recordFailure: jest.fn(),
  resetFailures: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn(),
  compare: jest.fn()
}

const mockEmailProvider = {
  sendMfaEnabledNotification: jest.fn(),
  sendMfaDisabledNotification: jest.fn()
}

const mockHooks = {
  afterMfaEnabled: jest.fn(),
  afterMfaDisabled: jest.fn(),
  afterLogin: jest.fn()
}

// TEST FIXTURE ONLY — not a real JWT secret.
const JWT_SECRET = 'nest-auth-test-jwt-secret-32chars+'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  mfa: {
    encryptionKey: VALID_ENCRYPTION_KEY,
    issuer: 'TestApp',
    totpWindow: 1,
    recoveryCodeCount: 2
  },
  sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

const mockSessionService = {
  createSession: jest.fn(),
  revokeSession: jest.fn(),
  rotateSession: jest.fn()
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('MfaService', () => {
  let service: MfaService

  beforeEach(async () => {
    // resetAllMocks clears both call history and mock implementations, preventing state bleed.
    // All default return values are configured below.
    jest.resetAllMocks()

    // Default safe mocks — override per-test as needed
    mockRedis.get.mockResolvedValue(null)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(undefined)
    mockRedis.sadd.mockResolvedValue(1)
    mockRedis.srem.mockResolvedValue(1)
    mockRedis.expire.mockResolvedValue(undefined)
    mockRedis.setIfAbsent.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
    mockUserRepo.updateMfa.mockResolvedValue(undefined)
    mockBruteForce.isLockedOut.mockResolvedValue(false)
    mockBruteForce.recordFailure.mockResolvedValue(undefined)
    mockBruteForce.resetFailures.mockResolvedValue(undefined)
    mockPasswordService.hash.mockResolvedValue('$scrypt$hashed')
    mockPasswordService.compare.mockResolvedValue(false)
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

  // ---------------------------------------------------------------------------
  // setup
  // ---------------------------------------------------------------------------

  describe('setup', () => {
    // Verifies that setup returns a valid Base32 TOTP secret, QR URI, and recovery codes.
    it('should return a Base32 secret, qrCodeUri, and recoveryCodes on first call', async () => {
      const result = await service.setup('user-1')

      expect(result.secret).toMatch(/^[A-Z2-7]+$/)
      expect(result.qrCodeUri).toMatch(/^otpauth:\/\/totp\//)
      expect(result.recoveryCodes).toHaveLength(2)
    })

    // Verifies that setup stores the pending setup data in Redis with a 600s TTL.
    it('should store setup data in Redis via setIfAbsent', async () => {
      await service.setup('user-1')

      expect(mockRedis.setIfAbsent).toHaveBeenCalledWith(
        expect.stringMatching(/^mfa_setup:/),
        expect.any(String),
        600
      )
    })

    // Verifies that setup throws MFA_ALREADY_ENABLED when MFA is already active.
    it('should throw MFA_ALREADY_ENABLED when mfaEnabled is true', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: true })

      try {
        await service.setup('user-1')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_ALREADY_ENABLED })
        })
      }
    })

    // Verifies that setup throws TOKEN_INVALID when the user is not found.
    it('should throw TOKEN_INVALID when user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.setup('unknown-user')).rejects.toThrow(AuthException)
    })

    // Verifies the rare race-condition branch: the fast-path GET returns null
    // (no setup pending), the service generates fresh data, then setIfAbsent
    // loses the race against another concurrent setup, and the second GET (after
    // setIfAbsent) also returns null because the winner's key already expired.
    // Service falls back to redis.set with its own freshly generated data.
    it('should fall back to redis.set when fast-path GET, setIfAbsent and second GET all return null/false', async () => {
      mockRedis.get.mockResolvedValue(null) // both fast-path and post-setIfAbsent GETs return null
      mockRedis.setIfAbsent.mockResolvedValue(false) // racing request claimed the key first

      const result = await service.setup('user-1')

      // Service regenerates and stores new setup data via set()
      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^mfa_setup:/),
        expect.any(String),
        expect.any(Number)
      )
      expect(result.secret).toMatch(/^[A-Z2-7]+$/)
    })

    // Verifies the recovery branch where the fast-path GET misses but a concurrent
    // request claims the SET-NX key first. The post-setIfAbsent GET retrieves
    // the winner's payload and the loser returns it for idempotency.
    it('should return winner setup data when fast-path GET is null but setIfAbsent loses the race', async () => {
      const winningSecret = 'WINNERSECRETBASE32ABCDEFGHIJKLMN'
      const winningCodes = ['AAAA-BBBB-CCCC', 'DDDD-EEEE-FFFF']
      const { encrypt } = await import('../crypto/aes-gcm')
      const winnerSetupData = {
        encryptedSecret: encrypt(winningSecret, VALID_ENCRYPTION_KEY),
        hashedCodes: ['hash1', 'hash2'],
        encryptedPlainCodes: encrypt(JSON.stringify(winningCodes), VALID_ENCRYPTION_KEY)
      }

      mockRedis.get
        .mockResolvedValueOnce(null) // fast-path GET — no setup pending yet
        .mockResolvedValueOnce(JSON.stringify(winnerSetupData)) // post-setIfAbsent — winner wrote it
      mockRedis.setIfAbsent.mockResolvedValue(false)

      const result = await service.setup('user-1')

      expect(result.secret).toBe(winningSecret)
      expect(result.recoveryCodes).toEqual(winningCodes)
      // redis.set must NOT be called — we returned the winner's data, not our own
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Verifies that DEFAULT_RECOVERY_CODE_COUNT (8) is used when recoveryCodeCount is absent from mfa options.
    it('should use DEFAULT_RECOVERY_CODE_COUNT when recoveryCodeCount is not configured', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const optionsWithoutCount = {
        jwt: { secret: JWT_SECRET },
        hmacKey: HMAC_KEY,
        mfa: {
          encryptionKey: VALID_ENCRYPTION_KEY,
          issuer: 'TestApp',
          totpWindow: 1
          // recoveryCodeCount intentionally absent — exercises the ?? DEFAULT_RECOVERY_CODE_COUNT branch
        }
      }
      const module = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithoutCount },
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

      const svc = module.get(MfaService)
      // mockPasswordService.hash is already configured to return '$scrypt$hashed'
      const result = await svc.setup('user-1')

      // The default count is 8 — verify the service produces the default number of codes
      expect(result.recoveryCodes).toHaveLength(8)
    })

    // Verifies the fast-path idempotency: when an existing setup payload is found by
    // the initial GET, the service returns it WITHOUT generating a new TOTP secret or
    // running scrypt on recovery codes (CPU-amplification defence).
    it('should fast-path-return existing setup data without re-running scrypt', async () => {
      const existingSecret = 'EXISTINGSECRETFROMREDIS32CHARS=='
      const existingCodes = ['1111-2222-3333', '4444-5555-6666']

      const { encrypt } = await import('../crypto/aes-gcm')
      const setupData = {
        encryptedSecret: encrypt(existingSecret, VALID_ENCRYPTION_KEY),
        hashedCodes: ['hash1', 'hash2'],
        encryptedPlainCodes: encrypt(JSON.stringify(existingCodes), VALID_ENCRYPTION_KEY)
      }

      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockPasswordService.hash.mockClear()

      const result = await service.setup('user-1')

      expect(result.recoveryCodes).toEqual(existingCodes)
      expect(result.secret).toBe(existingSecret)
      // Critical assertion: no scrypt work performed on the fast path.
      expect(mockPasswordService.hash).not.toHaveBeenCalled()
      // Critical assertion: setIfAbsent was NOT called — the fast path returned earlier.
      expect(mockRedis.setIfAbsent).not.toHaveBeenCalled()
    })

    // Verifies that a corrupted Redis payload on the fast path surfaces opaquely as
    // MFA_SETUP_REQUIRED rather than leaking SyntaxError. Anti-tampering defence.
    it('should throw MFA_SETUP_REQUIRED when fast-path Redis payload is corrupted JSON', async () => {
      mockRedis.get.mockResolvedValue('{not-valid-json')

      await expect(service.setup('user-1')).rejects.toThrow(AuthException)
      try {
        await service.setup('user-1')
      } catch (err) {
        expect(err).toBeInstanceOf(AuthException)
        const code = (err as AuthException).getResponse() as { error: { code: string } }
        expect(code.error.code).toBe(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
      }
    })

    // Verifies that a corrupted decrypted recovery-code payload surfaces opaquely as
    // MFA_SETUP_REQUIRED — defence against tampering on the encrypted blob in Redis.
    it('should throw MFA_SETUP_REQUIRED when decrypted recovery codes are not valid JSON', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const setupData = {
        encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
        hashedCodes: ['hash1'],
        // Encrypt a non-JSON payload so the decrypt succeeds but JSON.parse fails.
        encryptedPlainCodes: encrypt('not-json', VALID_ENCRYPTION_KEY)
      }

      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))

      await expect(service.setup('user-1')).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // verifyAndEnable
  // ---------------------------------------------------------------------------

  describe('verifyAndEnable', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that verifyAndEnable throws TOKEN_INVALID when the user is not found.
    it('should throw TOKEN_INVALID when user is not found in verifyAndEnable', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.verifyAndEnable('unknown', '123456', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that verifyAndEnable throws MFA_ALREADY_ENABLED when MFA is already active on the account.
    it('should throw MFA_ALREADY_ENABLED when MFA is already enabled', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: true })

      try {
        await service.verifyAndEnable('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_ALREADY_ENABLED })
        })
      }
    })

    // Verifies that verifyAndEnable throws MFA_SETUP_REQUIRED when no pending setup exists.
    it('should throw MFA_SETUP_REQUIRED when no setup data is in Redis', async () => {
      expect.assertions(1)
      mockRedis.get.mockResolvedValue(null)

      try {
        await service.verifyAndEnable('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_SETUP_REQUIRED })
        })
      }
    })

    // Verifies that verifyAndEnable surfaces a corrupted Redis payload opaquely as
    // MFA_SETUP_REQUIRED — preventing an attacker with Redis write access from
    // crashing the route handler with an unhandled SyntaxError.
    it('should throw MFA_SETUP_REQUIRED when Redis setup payload is corrupted JSON', async () => {
      expect.assertions(1)
      mockRedis.get.mockResolvedValue('{not-json-at-all')

      try {
        await service.verifyAndEnable('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_SETUP_REQUIRED })
        })
      }
    })

    // Verifies that verifyAndEnable throws MFA_INVALID_CODE for an incorrect TOTP code.
    it('should throw MFA_INVALID_CODE for an incorrect TOTP code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      // Anti-replay: SETNX returns true (new key) — but code won't match clock anyway
      mockRedis.setnx.mockResolvedValue(true)

      await expect(
        service.verifyAndEnable('user-1', '000000', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that verifyAndEnable calls userRepo.updateMfa and invalidateUserSessions on success.
    it('should update MFA in the DB and invalidate sessions on a valid code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const currentStep = Math.floor(Date.now() / 1000 / 30)
      const validCode = generateHotp(base32, currentStep)

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true) // anti-replay: new code
      mockRedis.getdel.mockResolvedValue(JSON.stringify(setupData)) // completion gate wins

      await service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({ mfaEnabled: true })
      )
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1')
    })

    // Defends against the verify-enable race: two concurrent valid submissions
    // must not both persist MFA state. The completion gate (GETDEL) returns a
    // non-null value to the first caller only; the loser observes null and must
    // throw MFA_SETUP_REQUIRED without touching the database.
    it('should throw MFA_SETUP_REQUIRED when the setup key was consumed by a concurrent request', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      // The racing caller already consumed the setup key — GETDEL returns null.
      mockRedis.getdel.mockResolvedValue(null)

      await expect(
        service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
    })

    // Verifies that the email notification is sent after enabling MFA.
    it('should send an MFA enabled email notification', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)

      await service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')

      expect(mockEmailProvider.sendMfaEnabledNotification).toHaveBeenCalledWith(
        AUTH_USER_MFA_DISABLED.email
      )
    })

    // Verifies that errors thrown by afterMfaEnabled hook are silently suppressed (fire-and-forget).
    it('should complete successfully even when afterMfaEnabled hook rejects', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterMfaEnabled.mockImplementation(() => Promise.reject(new Error('hook failure')))

      // Should resolve without throwing — hook errors must not propagate
      await expect(
        service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeUndefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies that anti-replay applies in verifyAndEnable: a replayed code is rejected.
    it('should throw MFA_INVALID_CODE when a valid code is replayed (setnx returns false)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(false) // key already exists = replayed code

      await expect(
        service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // challenge
  // ---------------------------------------------------------------------------

  describe('challenge', () => {
    // Static fixture values — rawRefreshToken is just an opaque string from the service perspective.
    const MOCK_AUTH_RESULT = {
      user: SAFE_USER,
      accessToken: 'access.jwt',
      rawRefreshToken: 'mock-refresh-token-dashboard'
    }

    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard'
      })
      mockTokenManager.issueTokens.mockResolvedValue(MOCK_AUTH_RESULT)
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that TOKEN_INVALID is thrown when the dashboard user cannot be found in the repository.
    it('should throw TOKEN_INVALID when dashboard user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that TOKEN_INVALID is thrown when the platform admin cannot be found in the repository.
    it('should throw TOKEN_INVALID when platform admin is not found', async () => {
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform'
      })
      mockPlatformUserRepo.findById.mockResolvedValue(null)

      await expect(service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that challenge throws MFA_INVALID_CODE when mfaRecoveryCodes is undefined,
    // exercising the ?? [] fallback on the recovery code path.
    it('should throw MFA_INVALID_CODE when mfaRecoveryCodes is undefined (empty fallback)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: undefined // undefined → ?? [] fallback at line 442
      })

      // Non-6-digit code routes through the recovery path; empty list → no match → INVALID_CODE
      await expect(
        service.challenge('mfa.temp', 'not-a-totp-code', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that challenge throws ACCOUNT_LOCKED when brute-force threshold is reached.
    it('should throw ACCOUNT_LOCKED when the user is locked out', async () => {
      expect.assertions(1)
      mockBruteForce.isLockedOut.mockResolvedValue(true)

      try {
        await service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
    })

    // Verifies that challenge throws MFA_INVALID_CODE for a wrong TOTP code.
    it('should throw MFA_INVALID_CODE and record a brute-force failure for a wrong code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(service.challenge('mfa.temp', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      // Brute-force identifier is an HMAC — verify it is hash-shaped (not the raw user ID).
      expect(mockBruteForce.recordFailure).toHaveBeenCalledWith(
        expect.stringMatching(/^[a-f0-9]{64}$/)
      )
    })

    // Verifies that a valid TOTP code resets the brute-force counter and issues tokens.
    it('should reset brute-force counter and issue tokens for a valid TOTP code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true) // anti-replay: new code

      const result = await service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')

      expect(mockBruteForce.resetFailures).toHaveBeenCalled()
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.any(Object),
        '1.2.3.4',
        'Browser',
        { mfaVerified: true }
      )
      expect(result).toBe(MOCK_AUTH_RESULT)
    })

    // Verifies that a valid recovery code is accepted and the used code is removed.
    it('should accept a recovery code and remove it from the stored list', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const hashedCodes = ['$scrypt$hash1', '$scrypt$hash2']

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })
      // passwordService.compare: first code doesn't match, second does
      mockPasswordService.compare
        .mockResolvedValueOnce(false) // first hash
        .mockResolvedValueOnce(true) // second hash

      const result = await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', {
        mfaEnabled: true,
        mfaSecret: expect.any(String),
        mfaRecoveryCodes: ['$scrypt$hash1'] // second code removed; mfaSecret preserved
      })
      expect(result).toBe(MOCK_AUTH_RESULT)
    })

    // Verifies that challenge stops iterating recovery codes after the first match
    // (early exit). Position-timing leakage is not exploitable here — the matched
    // code is consumed immediately afterwards (its position is no longer secret) —
    // and avoiding the remaining scrypt hashes prevents an O(N) CPU-amplification
    // window an attacker could otherwise force on every challenge attempt.
    it('should early-exit recovery code iteration after the first match', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const hashedCodes = ['$scrypt$hash1', '$scrypt$hash2', '$scrypt$hash3']

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })
      // '1234-5678-9012' does not match /^\d{6}$/ so the recovery code path is used (not TOTP).
      // First code matches — service should NOT continue past it.
      mockPasswordService.compare
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false)
        .mockResolvedValueOnce(false)

      await service.challenge('mfa.temp', '1234-5678-9012', '1.2.3.4', 'Browser')

      expect(mockPasswordService.compare).toHaveBeenCalledTimes(1)
      // Verify the first code (index 0) was the one removed.
      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({
          mfaRecoveryCodes: ['$scrypt$hash2', '$scrypt$hash3']
        })
      )
    })

    // Verifies that no match across all stored recovery codes still iterates every entry
    // before returning -1, so attackers cannot infer "no match found before code N" via timing.
    it('should iterate every recovery code when none match (full scan on miss)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const hashedCodes = ['$scrypt$hash1', '$scrypt$hash2', '$scrypt$hash3']

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })
      mockPasswordService.compare
        .mockResolvedValueOnce(false)
        .mockResolvedValueOnce(false)
        .mockResolvedValueOnce(false)

      await expect(
        service.challenge('mfa.temp', '1234-5678-9012', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      expect(mockPasswordService.compare).toHaveBeenCalledTimes(3)
    })

    // Verifies that TOTP anti-replay prevents a code from being used twice.
    it('should reject a replayed TOTP code (setnx returns false = already used)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(false) // key already exists = replayed

      await expect(service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      // Anti-replay call: key must be 'tu:' + 64-char HMAC hex; TTL must be 90 seconds.
      expect(mockRedis.setnx).toHaveBeenCalledWith(expect.stringMatching(/^tu:[a-f0-9]{64}$/), 90)
      // Replayed codes count as failed attempts to prevent lockout bypass via known valid codes.
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies that malformed recovery codes (non-6-digit strings with invalid format) are still
    // routed through passwordService.compare but produce no match, consistent with constant-time behavior.
    it('should route any non-6-digit code through recovery code comparison', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: ['$scrypt$hash1', '$scrypt$hash2']
      })
      // All comparisons return false — malformed code never matches
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(service.challenge('mfa.temp', '', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      // The service should still call compare for all stored codes (constant-time)
      expect(mockPasswordService.compare).toHaveBeenCalledTimes(2)
    })

    // Verifies that TOKEN_INVALID is thrown when the stored mfaSecret is corrupted (decrypt fails).
    it('should throw TOKEN_INVALID when mfaSecret cannot be decrypted', async () => {
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        // Wire format is iv:authTag:ciphertext — this corrupted value forces decrypt() to throw
        mfaSecret: 'aW52YWxpZA==:aW52YWxpZA==:aW52YWxpZA=='
      })

      await expect(service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that MFA_NOT_ENABLED is thrown when the user record shows mfaEnabled: false.
    it('should throw MFA_NOT_ENABLED when user does not have MFA active in challenge', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: false })

      try {
        await service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that errors thrown by the afterLogin hook (dashboard) are silently suppressed.
    it('should complete successfully even when afterLogin hook rejects (dashboard)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterLogin.mockImplementation(() => Promise.reject(new Error('hook failure')))

      await expect(
        service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeDefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies that a recovery code is removed via platformUserRepo when context is 'platform'.
    it('should remove the used recovery code via platformUserRepo for platform context', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const hashedCodes = ['$scrypt$hash1', '$scrypt$hash2']

      const PLATFORM_AUTH_RESULT = {
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'mock-refresh-token-platform-recovery'
      }

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })
      mockTokenManager.issuePlatformTokens.mockResolvedValue(PLATFORM_AUTH_RESULT)
      // First code doesn't match, second does
      mockPasswordService.compare
        .mockResolvedValueOnce(false)
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false)

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith(
        'admin-1',
        expect.objectContaining({ mfaRecoveryCodes: ['$scrypt$hash1'] })
      )
    })

    // Verifies that errors thrown by the afterLogin hook (platform) are silently suppressed.
    it('should complete successfully even when afterLogin hook rejects (platform)', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform'
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
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterLogin.mockImplementation(() => Promise.reject(new Error('hook failure')))

      await expect(
        service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeDefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies TOKEN_INVALID when context='platform' but platformUserRepo is not injected.
    it('should throw TOKEN_INVALID when platform context is used without platformUserRepo', async () => {
      // Create a service instance WITHOUT the platform user repo
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          // BYMAX_AUTH_PLATFORM_USER_REPOSITORY intentionally omitted
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()

      const serviceWithoutRepo = moduleWithoutRepo.get(MfaService)
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform'
      })

      await expect(
        serviceWithoutRepo.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that platform context challenges use issuePlatformTokens and the platform repo.
    it('should use issuePlatformTokens and platformUserRepo for platform context', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const PLATFORM_AUTH_RESULT = {
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'mock-refresh-token-platform'
      }

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockTokenManager.issuePlatformTokens.mockResolvedValue(PLATFORM_AUTH_RESULT)
      mockRedis.setnx.mockResolvedValue(true)

      const result = await service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')

      expect(mockPlatformUserRepo.findById).toHaveBeenCalledWith('admin-1')
      expect(mockTokenManager.issuePlatformTokens).toHaveBeenCalledWith(
        expect.any(Object),
        '1.2.3.4',
        'Browser',
        { mfaVerified: true }
      )
      expect(result).toBe(PLATFORM_AUTH_RESULT)
    })

    // Verifies that challenge calls sessionService.createSession when sessions.enabled is true.
    it('should call sessionService.createSession when sessions.enabled is true', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const sessionOptions = {
        ...mockOptions,
        sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
      }
      const sessionModule = await Test.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: sessionOptions },
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
      const sessionEnabledService = sessionModule.get(MfaService)

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: SAFE_USER.id,
        context: 'dashboard'
      })
      mockTokenManager.issueTokens.mockResolvedValue(MOCK_AUTH_RESULT)
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockSessionService.createSession.mockResolvedValue('session-hash')

      await sessionEnabledService.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')

      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        SAFE_USER.id,
        MOCK_AUTH_RESULT.rawRefreshToken,
        '1.2.3.4',
        'Browser'
      )
    })
  })

  // ---------------------------------------------------------------------------
  // disable
  // ---------------------------------------------------------------------------

  describe('disable', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that disable throws TOKEN_INVALID when the user is not found.
    it('should throw TOKEN_INVALID when user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.disable('unknown', '123456', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that disable throws MFA_NOT_ENABLED when MFA is not active on the account.
    it('should throw MFA_NOT_ENABLED when MFA is not active', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: false })

      try {
        await service.disable('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that disable throws TOKEN_INVALID when mfaEnabled is true but mfaSecret is null
    // (database inconsistency — should never happen in normal operation but must be handled safely).
    it('should throw TOKEN_INVALID when mfaEnabled is true but mfaSecret is null', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_ENABLED, mfaSecret: null })

      try {
        await service.disable('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
        })
      }
    })

    // Verifies that disable throws ACCOUNT_LOCKED when the brute-force threshold is reached.
    it('should throw ACCOUNT_LOCKED when user is locked out', async () => {
      expect.assertions(1)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockBruteForce.isLockedOut.mockResolvedValue(true)

      try {
        await service.disable('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
    })

    // Verifies that a valid TOTP code disables MFA, clears the DB fields, and invalidates sessions.
    it('should clear MFA fields in DB and invalidate sessions on a valid code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await service.disable('user-1', validCode, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: null
      })
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1')
    })

    // Verifies that the MFA disabled email notification is sent after a successful disable.
    it('should send an MFA disabled email notification', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await service.disable('user-1', validCode, '1.2.3.4', 'Browser')

      expect(mockEmailProvider.sendMfaDisabledNotification).toHaveBeenCalledWith(
        AUTH_USER_MFA_DISABLED.email
      )
    })

    // Verifies that disable throws MFA_INVALID_CODE and records a brute-force failure for a wrong code.
    it('should throw MFA_INVALID_CODE and record brute-force failure for a wrong code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(service.disable('user-1', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies that disable with context='platform' uses platformUserRepo.updateMfa instead of userRepo.updateMfa.
    it('should use platformUserRepo.updateMfa when context is platform', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)

      await service.disable('admin-1', validCode, '1.2.3.4', 'Browser', 'platform')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith('admin-1', {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: null
      })
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
    })

    // Verifies that errors thrown by the afterMfaDisabled hook are silently suppressed (fire-and-forget).
    it('should complete successfully even when afterMfaDisabled hook rejects', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterMfaDisabled.mockImplementation(() => Promise.reject(new Error('hook failure')))

      // Should resolve without throwing — hook errors must not propagate
      await expect(
        service.disable('user-1', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeUndefined()
      // Drain microtasks so the .catch callback executes (for coverage).
      // Two hops needed: one to resolve the internal Promise.resolve(rejected), one to run .catch.
      // Using Promise.resolve() instead of setTimeout(0) so fake timers don't block execution.
      await Promise.resolve()
      await Promise.resolve()
    })
  })
})
