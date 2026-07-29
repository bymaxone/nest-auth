/**
 * @fileoverview Tests for MfaService — TOTP setup, verify-enable, challenge, and disable flows.
 *
 * All external dependencies (Redis, repositories, email, brute-force) are mocked.
 * The AES-256-GCM encrypt/decrypt functions are exercised with a real key to avoid
 * mocking crypto internals, consistent with the project's testing guidelines.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256 } from '../crypto/secure-token'
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
  afterMfaRecoveryCodesRegenerated: jest.fn(),
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

  /**
   * Build a second service over the same doubles with `mockOptions` overridden.
   *
   * Used by the rotation cases, which need a different `previousHmacKeys` than the suite-wide
   * fixture without disturbing every other test in the file.
   */
  async function buildService(overrides: Record<string, unknown>): Promise<MfaService> {
    const module = await Test.createTestingModule({
      providers: [
        MfaService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: { ...mockOptions, ...overrides } },
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
    return module.get(MfaService)
  }

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

    // Scenario: first-time setup. Expected: each recovery code is 6 groups of 4 UPPERCASE hex
    // chars joined by '-' (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX). Why: a single canonical-format check
    // kills the groups=[] prefill (line 240), the slice loop bound/body mutants (line 241),
    // the slice argument mutants (line 242), the '-' join separator (line 244:32) and the
    // toUpperCase->toLowerCase mutant (line 244:20) — all break the canonical format.
    it('should format every recovery code as 6 groups of 4 uppercase hex chars', async () => {
      const result = await service.setup('user-1')
      for (const code of result.recoveryCodes) {
        expect(code).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){5}$/)
      }
    })

    // Scenario: first-time setup with recoveryCodeCount=2. Expected: the stored payload carries
    // exactly 2 hashedCodes. Why: kills the hashedCodes=["Stryker"] prefill (line 232), which
    // would persist 3 hashes instead of 2.
    it('should persist exactly recoveryCodeCount hashed codes in the setup payload', async () => {
      await service.setup('user-1')
      const payload = mockRedis.setIfAbsent.mock.calls[0]?.[1] as string
      const parsed = JSON.parse(payload) as { hashedCodes: string[] }
      expect(parsed.hashedCodes).toHaveLength(2)
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

    // Scenario: setIfAbsent wins the race (returns true, the default). Expected: redis.set is NOT
    // called and an info log carries the userId. Why: kills the `if (!wasSet)` -> `if (true)`
    // mutant (line 366), which would re-store via set even on the happy path, and pins the
    // setup log template (line 385).
    it('should not call redis.set and should log when setIfAbsent succeeds', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.setup('user-1')
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(logSpy).toHaveBeenCalledWith(
        'setup: MFA setup initiated userId=user-1 context=dashboard'
      )
      logSpy.mockRestore()
    })

    // Scenario: setup for a known user. Expected: the Redis setup key is exactly
    // 'mfa_setup:' + HMAC(userId). Why: pins the key template so a blanked key would diverge.
    it('should claim the mfa_setup key derived from the HMAC of the userId', async () => {
      await service.setup('user-1')
      const expectedKey = `mfa_setup:${hmacSha256('user-1', HMAC_KEY)}`
      expect(mockRedis.setIfAbsent).toHaveBeenCalledWith(expectedKey, expect.any(String), 600)
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
        previousHmacKeys: [],
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

    // Scenario: a pending-setup record that parses but carries no `hashedCodes`. Expected:
    // refused. Why: it used to be cast, not checked, so the field arrived as `undefined` and
    // the account could finish enrolling with no recovery codes at all — a lockout the user
    // discovers only when they have already lost their authenticator. `rust-auth`
    // deserializes into a struct with every field required and refuses the same record.
    it('should refuse a pending-setup record with no hashed recovery codes', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')

      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
          encryptedPlainCodes: encrypt('["a"]', VALID_ENCRYPTION_KEY)
        })
      )

      await expect(service.setup('user-1')).rejects.toThrow(AuthException)
    })

    // Scenario: a stored pending-setup value that parses to something that is not an object —
    // a bare `null` or a number. Expected: refused before any field read.
    it.each(['null', '42'])(
      'should refuse a pending-setup value that is not an object (%s)',
      async (raw) => {
        mockRedis.get.mockResolvedValue(raw)

        await expect(service.setup('user-1')).rejects.toThrow(AuthException)
      }
    )

    // Scenario: the same record with `hashedCodes` present but holding a non-string.
    // Expected: refused. Why: the array is written back to the repository verbatim on enable,
    // so a non-string member becomes a stored digest that no comparison can ever match.
    it('should refuse a pending-setup record whose hashed codes are not all strings', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')

      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
          hashedCodes: ['hash1', 42],
          encryptedPlainCodes: encrypt('["a"]', VALID_ENCRYPTION_KEY)
        })
      )

      await expect(service.setup('user-1')).rejects.toThrow(AuthException)
    })

    // Scenario: the decrypted plain-code payload is valid JSON but not an array of strings.
    // Expected: refused. Why: it is returned to the caller as the codes to write down; a
    // shape that is not a string array renders as `[object Object]` in the user's hands.
    it('should refuse decrypted recovery codes that are not an array of strings', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')

      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          encryptedSecret: encrypt('SECRETBASE32ABCDEFGHIJKLMNOPQR12', VALID_ENCRYPTION_KEY),
          hashedCodes: ['hash1'],
          encryptedPlainCodes: encrypt('[{"not":"a string"}]', VALID_ENCRYPTION_KEY)
        })
      )

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
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.verifyAndEnable('user-1', '000000', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      // Pin the invalid-code warn template (line 432) so blanking it to '' is caught.
      expect(warnSpy).toHaveBeenCalledWith('verifyAndEnable: invalid TOTP code userId=user-1')
      warnSpy.mockRestore()
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

      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({ mfaEnabled: true })
      )
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1', 'dashboard')
      // The setup key (read + getdel) must be 'mfa_setup:' + HMAC(userId): kills line 420 blanking.
      expect(mockRedis.get).toHaveBeenCalledWith(`mfa_setup:${hmacSha256('user-1', HMAC_KEY)}`)
      // The anti-replay key must be 'tu:' + HMAC('{userId}:{code}') with a 90s TTL: kills the
      // empty hmac input on the replay key (line 730).
      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `tu:${hmacSha256(`user-1:${validCode}`, HMAC_KEY)}`,
        90
      )
      // The afterMfaEnabled hook must be invoked (kills the BlockStatement emptying at line 461)
      // and the success log must carry the userId (kills line 457).
      expect(mockHooks.afterMfaEnabled).toHaveBeenCalledTimes(1)
      // With the dashboard projection, not the platform one: the platform shape blanks the
      // tenant (there is no tenant on that plane), so a hook that received it for a dashboard
      // user would lose the very field a multi-tenant consumer routes on.
      const dashboardHookUser = mockHooks.afterMfaEnabled.mock.calls[0]?.[0] as {
        tenantId: string
      }
      expect(dashboardHookUser.tenantId).toBe('tenant-1')
      expect(logSpy).toHaveBeenCalledWith(
        'verifyAndEnable: MFA enabled userId=user-1 context=dashboard'
      )
      logSpy.mockRestore()
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
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
      // Pin the concurrent-consumption warn template (line 443).
      expect(warnSpy).toHaveBeenCalledWith(
        'verifyAndEnable: setup key consumed by concurrent request userId=user-1'
      )
      warnSpy.mockRestore()
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
        context: 'dashboard',
        jti: 'jti-test-1'
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
        context: 'platform',
        jti: 'jti-test-platform-1'
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
        mfaRecoveryCodes: undefined // undefined → ?? [] fallback at line 530
      })
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Non-6-digit code routes through the recovery path; empty list → no match → INVALID_CODE
      await expect(
        service.challenge('mfa.temp', 'not-a-totp-code', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      // The ?? [] fallback must yield an EMPTY array, so no recovery comparison runs. Kills the
      // `?? []` -> `?? ["Stryker"]` ArrayDeclaration mutant (line 530), which would compare once.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      // Pin the invalid-code warn template including the context (line 537).
      expect(warnSpy).toHaveBeenCalledWith(
        'challenge: invalid MFA code userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies that challenge throws ACCOUNT_LOCKED when brute-force threshold is reached.
    it('should throw ACCOUNT_LOCKED when the user is locked out', async () => {
      expect.assertions(2)
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
      // Pin the account-locked warn template (line 509).
      expect(warnSpy).toHaveBeenCalledWith('challenge: account locked userId=user-1')
      warnSpy.mockRestore()
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

    // Scenario: the loop an attacker who holds the password runs — log in, burn the MFA
    // guess budget, log in again to get a fresh temp token, keep guessing. Expected: the
    // failure counter keeps climbing across logins, so the lockout engages. Why: issuing a
    // temp token used to clear this counter, which made the per-account lockout unreachable
    // and left only the per-IP limit (defeated by distributing). The counter is cleared by
    // exactly one event — a successful challenge — and this test pins that: the identifier
    // recorded across two separate login cycles is the SAME key, so the count accumulates.
    it('should keep accumulating MFA failures across separate logins', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      // Two challenge attempts, each following its own login (the service re-reads the
      // identifier from the token's userId every time, so a fresh temp token changes nothing).
      await expect(service.challenge('mfa.temp', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      await expect(
        service.challenge('mfa.temp.fresh', '111111', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      const identifiers = mockBruteForce.recordFailure.mock.calls.map((call) => call[0] as string)
      expect(identifiers).toHaveLength(2)
      // Same counter both times — nothing in the login path reset it in between.
      expect(identifiers[0]).toBe(identifiers[1])
      expect(mockBruteForce.resetFailures).not.toHaveBeenCalled()
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
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      const result = await service.challenge('mfa.temp', validCode, '1.2.3.4', 'Browser')

      expect(mockBruteForce.resetFailures).toHaveBeenCalled()
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.any(Object),
        '1.2.3.4',
        'Browser',
        { mfaVerified: true }
      )
      expect(result).toBe(MOCK_AUTH_RESULT)
      // A TOTP success must NOT touch the recovery-code list: usedRecoveryIndex stays -1, so the
      // `if (usedRecoveryIndex >= 0)` block is skipped. Kills the `-1` -> `+1` UnaryOperator
      // (line 525) and the `if (usedRecoveryIndex >= 0)` -> `if (true)` mutant (line 544), both
      // of which would (wrongly) call updateMfa.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      // sessions disabled (default options) -> createSession must NOT run. Kills the
      // `if (this.options.sessions.enabled)` -> `if (true)` mutant (line 575).
      expect(mockSessionService.createSession).not.toHaveBeenCalled()
      // The afterLogin hook must be invoked (kills the dashboard BlockStatement emptying line 579)
      // and the success log must carry userId/context (kills line 565).
      expect(mockHooks.afterLogin).toHaveBeenCalledTimes(1)
      expect(logSpy).toHaveBeenCalledWith(
        'challenge: MFA challenge passed userId=user-1 context=dashboard'
      )
      logSpy.mockRestore()
    })

    // Verifies that a valid recovery code is accepted and the used code is removed.
    it('should accept a recovery code and remove it from the stored list', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const otherDigest = 'a'.repeat(64)
      const hashedCodes = [otherDigest, hmacSha256(plainRecovery, HMAC_KEY)]

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })

      const result = await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', {
        mfaEnabled: true,
        mfaSecret: expect.any(String),
        mfaRecoveryCodes: [otherDigest] // matched code consumed; mfaSecret preserved
      })
      // The keyed MAC replaces the KDF entirely on this path.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      expect(result).toBe(MOCK_AUTH_RESULT)
    })

    // Scenario: a recovery code whose digest was written under a secret since retired, with the
    // rotation configured. Expected: accepted and consumed. Why: the digest is keyed by an HMAC
    // derived from `jwt.secret`, so a rotation without this invalidates every code a user
    // printed and filed — and they discover it at the moment they most need it, locked out of
    // an account they cannot reach any other way.
    it('should accept a recovery code digested under a retired secret', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const retiredKey = 'f'.repeat(64)
      const plainRecovery = '1234-5678-9012'
      const otherDigest = 'a'.repeat(64)
      // Written under the OLD key: nothing in the stored set matches the current one.
      const hashedCodes = [otherDigest, hmacSha256(plainRecovery, retiredKey)]

      const rotated = await buildService({ previousHmacKeys: [retiredKey] })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })

      const result = await rotated.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', {
        mfaEnabled: true,
        mfaSecret: expect.any(String),
        mfaRecoveryCodes: [otherDigest]
      })
      expect(result).toBe(MOCK_AUTH_RESULT)
    })

    // Scenario: the same code, but the rotation NOT configured. Expected: refused. Why: this is
    // the failure the test above prevents, and it has to be shown to be real — otherwise the
    // dual read could be doing nothing and both tests would still pass.
    it('should refuse a code digested under a secret that was not listed', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const hashedCodes = ['a'.repeat(64), hmacSha256(plainRecovery, 'f'.repeat(64))]

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })

      await expect(
        service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')
      ).rejects.toThrow()
    })

    // Scenario: the matching digest sits in the MIDDLE of the set. Expected: that entry is the
    // one consumed. Why: the MAC branch deliberately scans to completion instead of returning
    // early, so it has to remember the first match rather than the last one — recording every
    // comparison would consume whichever code happened to be stored last.
    it('should consume the matching code, not the last one scanned', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const before = 'a'.repeat(64)
      const after = 'b'.repeat(64)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [before, hmacSha256(plainRecovery, HMAC_KEY), after]
      })

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({ mfaRecoveryCodes: [before, after] })
      )
    })

    // Scenario: the same digest stored twice. Expected: the FIRST occurrence is consumed and
    // the duplicate survives. Why: the scan keeps the earliest match, so exactly one code is
    // spent per use — recording later matches too would consume the wrong entry and leave the
    // user's remaining count wrong.
    it('should consume only the first of two identical recovery digests', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const digest = hmacSha256(plainRecovery, HMAC_KEY)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: [digest, digest]
      })

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({ mfaRecoveryCodes: [digest] })
      )
    })

    // Scenario: a stored digest in the pre-MAC `scrypt:` shape. Expected: refused, and no key
    // derivation spent on it. Why: the format is gone, not deprecated. Keeping a reader for it
    // meant one scrypt derivation per stored entry on every wrong submission — an amplifier
    // anyone holding a temp token could reach — and the libraries are new, so there is no
    // corpus of such digests to keep readable.
    it('should refuse a digest in the removed scrypt format without spending a derivation', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: ['scrypt:0011223344556677:8899aabbccddeeff']
      })

      await expect(
        service.challenge('mfa.temp', '1234-5678-9012', '1.2.3.4', 'Browser')
      ).rejects.toThrow()
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // Verifies a wrong code costs no key derivation at all once the codes are in the MAC
    // format. This is the security property of the change: previously one wrong submission
    // forced one scrypt derivation per stored code, an amplifier reachable by anyone holding
    // a temp token.
    it('should spend no key derivation when a wrong code is scanned against MAC digests', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]
      })

      await expect(
        service.challenge('mfa.temp', '1234-5678-9012', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      expect(mockPasswordService.compare).not.toHaveBeenCalled()
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
        // The digest of the empty string under the identifier key. If the branch routes to
        // recovery, this matches and the challenge succeeds — which is the observation, since
        // the MAC comparison spends no service call to watch.
        mfaRecoveryCodes: [hmacSha256('', HMAC_KEY)]
      })

      await expect(service.challenge('mfa.temp', '', '1.2.3.4', 'Browser')).resolves.toBe(
        MOCK_AUTH_RESULT
      )
      // …and no key derivation was spent getting there.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
    })

    // Scenario: a 6-digit prefix followed by a non-digit suffix ('123456X'). The canonical
    // /^\d{6}$/ rejects it (the $ anchor requires the string to END after 6 digits), so it must
    // route through the RECOVERY path (passwordService.compare runs). Why: kills the
    // /^\d{6}$/ -> /^\d{6}/ Regex mutant (line 522), which drops the $ anchor and would
    // (wrongly) treat '123456X' as a TOTP code, skipping the recovery comparison.
    it('should route a 6-digit-prefixed code with a trailing char through the recovery path', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        // Legacy-format digests, so the recovery branch is observable through the KDF call
        // the MAC format no longer needs.
        mfaRecoveryCodes: [hmacSha256('123456X', HMAC_KEY)]
      })

      // Routing to recovery is what lets this match; the TOTP path would reject it outright.
      await expect(service.challenge('mfa.temp', '123456X', '1.2.3.4', 'Browser')).resolves.toBe(
        MOCK_AUTH_RESULT
      )
    })

    // Scenario: a non-digit prefix followed by 6 digits ('X123456'). The canonical /^\d{6}$/
    // rejects it (the ^ anchor requires digits to START the string), so it must route through
    // the RECOVERY path. Why: kills the /^\d{6}$/ -> /\d{6}$/ Regex mutant (line 522), which
    // drops the ^ anchor and would (wrongly) treat 'X123456' as a TOTP code.
    it('should route a code with a non-digit prefix and 6 trailing digits through the recovery path', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        // Legacy-format digests, so the recovery branch is observable through the KDF call
        // the MAC format no longer needs.
        mfaRecoveryCodes: [hmacSha256('X123456', HMAC_KEY)]
      })

      await expect(service.challenge('mfa.temp', 'X123456', '1.2.3.4', 'Browser')).resolves.toBe(
        MOCK_AUTH_RESULT
      )
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

    // Verifies the challenge re-checks account status. Login gated it before minting the
    // temp token, but that token stays valid for its whole TTL: an account suspended in the
    // meantime must not be able to finish the second factor and walk away with a full
    // session. Revoking access cannot depend on how far through login the holder had got.
    it('should reject the challenge when the account was blocked after the temp token was issued', async () => {
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        status: 'SUSPENDED'
      })

      let caught: AuthException | undefined
      try {
        await service.challenge('mfa.temp', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }

      expect(caught).toBeInstanceOf(AuthException)
      expect(caught!.getStatus()).toBe(403)
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    // Verifies the status gate runs before the code is verified: the recovery-code path
    // costs one scrypt derivation per stored code, so a blocked account must never reach it.
    it('should reject a blocked account without verifying the submitted code', async () => {
      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        status: 'BANNED'
      })

      await expect(
        service.challenge('mfa.temp', 'some-recovery-code', '1.2.3.4', 'Browser')
      ).rejects.toBeInstanceOf(AuthException)

      expect(mockPasswordService.compare).not.toHaveBeenCalled()
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
      // MAC digests: the first is another code's, the second is the one being presented, so
      // the assertion below proves the MATCHED entry is the one spliced out.
      const hashedCodes = [
        hmacSha256('0000-0000-0000', HMAC_KEY),
        hmacSha256(plainRecovery, HMAC_KEY)
      ]

      const PLATFORM_AUTH_RESULT = {
        admin: SAFE_ADMIN,
        accessToken: 'platform.jwt',
        rawRefreshToken: 'mock-refresh-token-platform-recovery'
      }

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-test-platform-1'
      })
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: hashedCodes
      })
      mockTokenManager.issuePlatformTokens
        .mockResolvedValue(PLATFORM_AUTH_RESULT)
        // First code doesn't match, second does
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false)

      await service.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith(
        'admin-1',
        expect.objectContaining({ mfaRecoveryCodes: [hmacSha256('0000-0000-0000', HMAC_KEY)] })
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
        context: 'platform',
        jti: 'jti-test-platform-1'
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
        context: 'platform',
        jti: 'jti-test-platform-1'
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
        context: 'platform',
        jti: 'jti-test-platform-1'
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
      // The platform afterLogin hook must be invoked (kills the platform BlockStatement emptying
      // at line 598) with a SafeAuthUser-compatible projection whose platform-sentinel fields are
      // tenantId='' (kills line 301) and emailVerified=true (kills line 302).
      expect(mockHooks.afterLogin).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterLogin.mock.calls[0]?.[0] as {
        tenantId: string
        emailVerified: boolean
      }
      expect(hookUser.tenantId).toBe('')
      expect(hookUser.emailVerified).toBe(true)
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
        context: 'dashboard',
        jti: 'jti-test-safe-user-1'
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

  /**
   * The same misconfiguration guard as `setup`/`verifyAndEnable`, on the third
   * entry point. Without it a platform regenerate falls through to the dashboard
   * repository, which is how one admin's recovery codes end up written onto a
   * dashboard user with the same id.
   */
  describe('regenerateRecoveryCodes — platform misconfiguration', () => {
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
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

      await expect(
        serviceWithoutRepo.regenerateRecoveryCodes(
          'admin-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'platform'
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
      expect(mockUserRepo.findById).not.toHaveBeenCalled()
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()

      // And only the platform context is a misconfiguration here — a dashboard regenerate on
      // the same platform-less service is an ordinary call and must not be refused by it.
      mockUserRepo.findById.mockResolvedValue(null)
      await expect(
        serviceWithoutRepo.regenerateRecoveryCodes('user-1', '123456', '1.2.3.4', 'Browser')
      ).rejects.not.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
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
      expect.assertions(2)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await service.disable('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
      // Pin the disable account-locked warn template including the context (line 655).
      expect(warnSpy).toHaveBeenCalledWith(
        'disable: account locked userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
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
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.disable('user-1', validCode, '1.2.3.4', 'Browser')

      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: null
      })
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1', 'dashboard')
      // The disable brute-force identifier must be HMAC('disable:{userId}') — kills line 653.
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(
        hmacSha256('disable:user-1', HMAC_KEY)
      )
      // Pin the success log including the context (line 686).
      expect(logSpy).toHaveBeenCalledWith('disable: MFA disabled userId=user-1 context=dashboard')
      // The afterMfaDisabled hook must be invoked (kills the BlockStatement emptying at line 694)
      // with the DASHBOARD projection that retains the real tenantId. The dashboard branch of the
      // `context === 'platform' ? ... : toSafeUser(...)` ternary (line 690) must be taken — kills
      // the `true` and `!==` mutants which would force the platform projection (tenantId='').
      expect(mockHooks.afterMfaDisabled).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaDisabled.mock.calls[0]?.[0] as { tenantId: string }
      expect(hookUser.tenantId).toBe('tenant-1')
      logSpy.mockRestore()
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
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(service.disable('user-1', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
      // Pin the disable invalid-code warn template including the context (line 670).
      expect(warnSpy).toHaveBeenCalledWith(
        'disable: invalid MFA code userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
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
      // Revocation is scoped to the PLATFORM plane, sessions and epoch alike: the two id
      // spaces come from different repositories and may collide, so the dashboard variants
      // here would log out — and un-revoke — the wrong account.
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')
      // The afterMfaDisabled hook must receive the PLATFORM projection: the
      // `context === 'platform' ? platformUserAsSafeUser(...) : ...` ternary (line 690) takes the
      // platform branch, so tenantId is the '' sentinel. Kills the `false` and `!==` mutants on
      // line 690 (which would use toSafeUser and drop the sentinel), plus line 301 (tenantId='').
      const hookUser = mockHooks.afterMfaDisabled.mock.calls[0]?.[0] as {
        tenantId: string
        emailVerified: boolean
      }
      expect(hookUser.tenantId).toBe('')
      expect(hookUser.emailVerified).toBe(true)
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

    // Scenario: disable succeeds but the consumer registered no afterMfaDisabled hook. Expected:
    // disable completes without throwing. Why: covers the false branch of
    // `if (this.hooks.afterMfaDisabled)` (line 695) where the hook is absent.
    it('should complete disable when no afterMfaDisabled hook is registered', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

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
          // Hooks object without afterMfaDisabled — the `if` guard must short-circuit.
          { provide: BYMAX_AUTH_HOOKS, useValue: {} }
        ]
      }).compile()
      const noHookService = module.get(MfaService)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(
        noHookService.disable('user-1', validCode, '1.2.3.4', 'Browser')
      ).resolves.toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // setup — platform context
  // ---------------------------------------------------------------------------

  describe('setup — platform context', () => {
    // Verifies that setup with context='platform' resolves the user via
    // platformUserRepo and never touches the dashboard userRepo. Without this,
    // a platform admin's MFA enrolment would silently target a tenant user row.
    it('should resolve user via platformUserRepo when context is platform', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })

      const result = await service.setup('admin-1', 'platform')

      expect(mockPlatformUserRepo.findById).toHaveBeenCalledWith('admin-1')
      expect(mockUserRepo.findById).not.toHaveBeenCalled()
      expect(result.secret).toMatch(/^[A-Z2-7]+$/)
      expect(result.recoveryCodes).toHaveLength(2)
    })

    // Verifies that setup throws MFA_NOT_ENABLED when context='platform' but the
    // platform repository was not configured at module registration — surfacing
    // the misconfiguration at the first request instead of silently falling back
    // to the dashboard repo (which would persist on the wrong table).
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
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

      expect.assertions(1)
      try {
        await serviceWithoutRepo.setup('admin-1', 'platform')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that setup logs the resolved context so platform vs dashboard
    // operations can be distinguished in observability streams.
    it('should log the context on a successful platform setup', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.setup('admin-1', 'platform')

      expect(logSpy).toHaveBeenCalledWith(
        'setup: MFA setup initiated userId=admin-1 context=platform'
      )
      logSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // verifyAndEnable — platform context
  // ---------------------------------------------------------------------------

  describe('verifyAndEnable — platform context', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that verifyAndEnable persists MFA state via platformUserRepo when
    // context='platform' — never via userRepo. Catches the most dangerous bug
    // class for this feature (silent cross-repo write).
    it('should persist MFA state via platformUserRepo and fire the platform projection hook', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })
      const setupData = {
        encryptedSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        hashedCodes: [],
        encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
      }
      mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
      mockRedis.setnx.mockResolvedValue(true)
      mockRedis.getdel.mockResolvedValue(JSON.stringify(setupData))

      await service.verifyAndEnable('admin-1', validCode, '1.2.3.4', 'Browser', 'platform')

      // Revocation scoped to the platform plane — see the disable counterpart for why.
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1', 'platform')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('admin-1', 'platform')

      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith(
        'admin-1',
        expect.objectContaining({ mfaEnabled: true })
      )
      // The dashboard repo must NOT have received the write — pins the
      // `if (context === 'platform' && this.platformUserRepo)` branch and kills
      // mutants that would route both contexts to the same repo.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      // The afterMfaEnabled hook must be invoked with the platform projection
      // (tenantId='' sentinel) — kills mutants that would force the dashboard
      // projection (which would carry a real tenantId).
      expect(mockHooks.afterMfaEnabled).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaEnabled.mock.calls[0]?.[0] as { tenantId: string }
      expect(hookUser.tenantId).toBe('')
    })

    // Verifies that verifyAndEnable throws MFA_NOT_ENABLED when the platform
    // repository is not configured. Without this, a platform-context enable
    // request would silently fall back to the dashboard repo at line 478.
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
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

      // The specific code matters: any other AuthException here would mean the guard let the
      // request through and something downstream refused it instead — which is the bug this
      // test exists for, since downstream would be the *dashboard* repository.
      await expect(
        serviceWithoutRepo.verifyAndEnable('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
      // Refused before any read: the dashboard repository is never consulted for a platform
      // request, not even to fail.
      expect(mockUserRepo.findById).not.toHaveBeenCalled()

      // And the guard is about the platform context specifically — a dashboard enable on the
      // same (platform-less) service is not a misconfiguration and must run its normal course.
      mockUserRepo.findById.mockResolvedValue({
        ...SAFE_USER,
        passwordHash: 'hash',
        mfaEnabled: false,
        mfaRecoveryCodes: []
      })
      mockRedis.get.mockResolvedValue(null)
      await expect(
        serviceWithoutRepo.verifyAndEnable('user-1', '123456', '1.2.3.4', 'Browser')
      ).rejects.not.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })
    })
  })

  // ---------------------------------------------------------------------------
  // regenerateRecoveryCodes
  // ---------------------------------------------------------------------------

  describe('regenerateRecoveryCodes', () => {
    beforeEach(() => {
      jest.useFakeTimers()
      jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    })

    afterEach(() => {
      jest.useRealTimers()
    })

    // Verifies that regenerate throws TOKEN_INVALID when the user is not found —
    // mirrors the disable() guard so an unknown user never reaches scrypt.
    it('should throw TOKEN_INVALID when user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.regenerateRecoveryCodes('unknown', '123456', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that regenerate throws MFA_NOT_ENABLED when MFA is not active —
    // the action is meaningless without an existing TOTP secret to rotate against.
    it('should throw MFA_NOT_ENABLED when MFA is not active', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_DISABLED, mfaEnabled: false })

      try {
        await service.regenerateRecoveryCodes('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_NOT_ENABLED })
        })
      }
    })

    // Verifies that regenerate throws TOKEN_INVALID when mfaEnabled is true but
    // mfaSecret is null — database inconsistency must surface, not crash.
    it('should throw TOKEN_INVALID when mfaEnabled is true but mfaSecret is null', async () => {
      expect.assertions(1)
      mockUserRepo.findById.mockResolvedValue({ ...AUTH_USER_MFA_ENABLED, mfaSecret: null })

      try {
        await service.regenerateRecoveryCodes('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
        })
      }
    })

    // Verifies that regenerate throws ACCOUNT_LOCKED when the brute-force
    // threshold has been reached. Reuses the disable counter namespace so a
    // pre-auth attacker cannot exhaust it via the public challenge endpoint.
    it('should throw ACCOUNT_LOCKED when user is locked out', async () => {
      expect.assertions(2)
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await service.regenerateRecoveryCodes('user-1', '123456', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
        })
      }
      expect(warnSpy).toHaveBeenCalledWith(
        'regenerateRecoveryCodes: account locked userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies that regenerate throws MFA_INVALID_CODE for a wrong TOTP and
    // records a brute-force failure (same counter as disable — kills mutants
    // that would target the challenge counter instead).
    it('should throw MFA_INVALID_CODE and record brute-force failure for a wrong code', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.regenerateRecoveryCodes('user-1', '000000', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      expect(mockBruteForce.recordFailure).toHaveBeenCalledWith(
        hmacSha256('disable:user-1', HMAC_KEY)
      )
      expect(warnSpy).toHaveBeenCalledWith(
        'regenerateRecoveryCodes: invalid MFA code userId=user-1 context=dashboard'
      )
      warnSpy.mockRestore()
    })

    // Verifies the happy path: a valid TOTP returns fresh plain-text codes,
    // persists new hashes via userRepo, resets the brute-force counter, and
    // preserves the existing TOTP secret (only recovery codes change).
    it('should return fresh recovery codes and persist new hashes on a valid TOTP', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
      const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encryptedSecret,
        mfaRecoveryCodes: ['$scrypt$old1', '$scrypt$old2']
      })
      mockRedis.setnx.mockResolvedValue(true)
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      const result = await service.regenerateRecoveryCodes(
        'user-1',
        validCode,
        '1.2.3.4',
        'Browser'
      )

      // recoveryCodeCount=2 in mockOptions
      expect(result.recoveryCodes).toHaveLength(2)
      for (const code of result.recoveryCodes) {
        expect(code).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){5}$/)
      }
      expect(mockUserRepo.updateMfa).toHaveBeenCalledWith('user-1', {
        mfaEnabled: true,
        mfaSecret: encryptedSecret, // unchanged — only recovery codes rotate
        mfaRecoveryCodes: expect.any(Array)
      })
      // The stored hashes must NOT be the same as the old ones — pins that
      // the new codes are actually fresh.
      const persisted = mockUserRepo.updateMfa.mock.calls[0]?.[1] as {
        mfaRecoveryCodes: string[]
      }
      expect(persisted.mfaRecoveryCodes).not.toEqual(['$scrypt$old1', '$scrypt$old2'])
      expect(mockBruteForce.resetFailures).toHaveBeenCalled()
      expect(logSpy).toHaveBeenCalledWith(
        'regenerateRecoveryCodes: recovery codes regenerated userId=user-1 context=dashboard'
      )
      // The afterMfaRecoveryCodesRegenerated hook must be invoked with the
      // dashboard projection (real tenantId).
      expect(mockHooks.afterMfaRecoveryCodesRegenerated).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaRecoveryCodesRegenerated.mock.calls[0]?.[0] as {
        tenantId: string
      }
      expect(hookUser.tenantId).toBe('tenant-1')
      logSpy.mockRestore()
    })

    // Verifies that the platform context routes the write through
    // platformUserRepo and fires the hook with the platform projection. This is
    // the strongest test against silent cross-repo writes.
    it('should persist via platformUserRepo and fire the platform hook projection for platform context', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY),
        mfaRecoveryCodes: ['$scrypt$old1']
      })
      mockRedis.setnx.mockResolvedValue(true)

      const result = await service.regenerateRecoveryCodes(
        'admin-1',
        validCode,
        '1.2.3.4',
        'Browser',
        'platform'
      )

      expect(result.recoveryCodes).toHaveLength(2)
      expect(mockPlatformUserRepo.updateMfa).toHaveBeenCalledWith(
        'admin-1',
        expect.objectContaining({ mfaEnabled: true })
      )
      // The dashboard repo must NOT receive the write.
      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      // The hook must receive the platform projection (tenantId='' sentinel).
      expect(mockHooks.afterMfaRecoveryCodesRegenerated).toHaveBeenCalledTimes(1)
      const hookUser = mockHooks.afterMfaRecoveryCodesRegenerated.mock.calls[0]?.[0] as {
        tenantId: string
        emailVerified: boolean
      }
      expect(hookUser.tenantId).toBe('')
      expect(hookUser.emailVerified).toBe(true)
    })

    // Verifies that regenerate throws MFA_NOT_ENABLED when the platform user
    // repository was not configured — caller misconfiguration must fail closed,
    // never silently fall back to the dashboard repo (data corruption risk).
    it('should throw MFA_NOT_ENABLED when platform context is used without platformUserRepo', async () => {
      const { Test: NestTest } = await import('@nestjs/testing')
      const moduleWithoutRepo = await NestTest.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
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

      await expect(
        serviceWithoutRepo.regenerateRecoveryCodes(
          'admin-1',
          '123456',
          '1.2.3.4',
          'Browser',
          'platform'
        )
      ).rejects.toThrow(AuthException)
    })

    // Verifies that errors thrown by the hook are silently suppressed — a
    // failing audit-log integration must not propagate after a successful
    // rotation. Mirrors the disable() suppression contract.
    it('should complete successfully even when afterMfaRecoveryCodesRegenerated hook rejects', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockHooks.afterMfaRecoveryCodesRegenerated.mockImplementation(() =>
        Promise.reject(new Error('hook failure'))
      )

      await expect(
        service.regenerateRecoveryCodes('user-1', validCode, '1.2.3.4', 'Browser')
      ).resolves.toEqual(expect.objectContaining({ recoveryCodes: expect.any(Array) }))
      // Drain microtasks so the .catch callback executes (for coverage).
      await Promise.resolve()
      await Promise.resolve()
    })

    // Verifies that regenerate completes without the hook registered — covers
    // the false branch of `if (this.hooks.afterMfaRecoveryCodesRegenerated)`.
    it('should complete regenerate when no afterMfaRecoveryCodesRegenerated hook is registered', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

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
          // Hooks object without afterMfaRecoveryCodesRegenerated — the `if` guard must short-circuit.
          { provide: BYMAX_AUTH_HOOKS, useValue: {} }
        ]
      }).compile()
      const noHookService = module.get(MfaService)

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(
        noHookService.regenerateRecoveryCodes('user-1', validCode, '1.2.3.4', 'Browser')
      ).resolves.toEqual(expect.objectContaining({ recoveryCodes: expect.any(Array) }))
    })

    // Verifies that the default DEFAULT_RECOVERY_CODE_COUNT (8) is used when
    // recoveryCodeCount is absent from the mfa options — exercises the
    // `?? DEFAULT_RECOVERY_CODE_COUNT` branch at the regenerate path.
    it('should use DEFAULT_RECOVERY_CODE_COUNT when recoveryCodeCount is not configured', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateHotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

      const { Test: NestTest } = await import('@nestjs/testing')
      const optionsWithoutCount = {
        jwt: { secret: JWT_SECRET },
        hmacKey: HMAC_KEY,
        previousHmacKeys: [],
        mfa: {
          encryptionKey: VALID_ENCRYPTION_KEY,
          issuer: 'TestApp',
          totpWindow: 1
          // recoveryCodeCount intentionally absent
        },
        sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
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

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, VALID_ENCRYPTION_KEY)
      })
      mockRedis.setnx.mockResolvedValue(true)

      const result = await svc.regenerateRecoveryCodes('user-1', validCode, '1.2.3.4', 'Browser')

      expect(result.recoveryCodes).toHaveLength(8)
    })
  })

  // ---------------------------------------------------------------------------
  // Misconfiguration: platform context without a platform repository
  // ---------------------------------------------------------------------------

  describe('platform context with no platform repository wired', () => {
    let unwired: MfaService

    beforeEach(async () => {
      // The same module, minus the platform repository. A host can enable MFA without ever
      // wiring the platform plane, and every platform-context entry point has to fail closed
      // rather than fall through to the tenant repository — writing a platform admin's MFA
      // secret onto a tenant user row would be a cross-plane credential leak.
      const module = await Test.createTestingModule({
        providers: [
          MfaService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: null },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
        ]
      }).compile()

      unwired = module.get(MfaService)
    })

    // Verifies setup refuses rather than provisioning against the wrong repository, with the
    // misconfiguration code specifically. Asserting merely "some AuthException" would not
    // distinguish this guard from a later failure on the fall-through path.
    it('should refuse setup for the platform context', async () => {
      await expect(unwired.setup('admin-1', 'platform')).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })

      expect(mockUserRepo.findById).not.toHaveBeenCalled()
    })

    // Verifies verifyAndEnable refuses before it can persist a secret anywhere.
    it('should refuse verifyAndEnable for the platform context', async () => {
      await expect(
        unwired.verifyAndEnable('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ).rejects.toBeInstanceOf(AuthException)

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
    })

    // Verifies regenerateRecoveryCodes refuses, so a caller cannot mint platform recovery
    // codes that would be written to a tenant row.
    it('should refuse regenerateRecoveryCodes for the platform context', async () => {
      await expect(
        unwired.regenerateRecoveryCodes('admin-1', '123456', '1.2.3.4', 'Browser', 'platform')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_NOT_ENABLED } }
      })

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      expect(mockBruteForce.isLockedOut).not.toHaveBeenCalled()
    })

    // Verifies the dashboard context is unaffected: the guard must key on the context, not
    // simply refuse whenever the platform repository is absent.
    it('should still serve the dashboard context', async () => {
      mockUserRepo.findById.mockResolvedValue(AUTH_USER_MFA_DISABLED)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.setIfAbsent.mockResolvedValue(true)

      await expect(unwired.setup('user-1', 'dashboard')).resolves.toMatchObject({
        secret: expect.any(String)
      })
    })
  })

  // ---------------------------------------------------------------------------
  // Rotating the MFA encryption key
  // ---------------------------------------------------------------------------

  describe('encryption key rotation', () => {
    const RETIRED_KEY = Buffer.alloc(32, 3).toString('base64')
    const ROTATION_AUTH_RESULT = { accessToken: 'at', rawRefreshToken: 'rt', user: {} }

    beforeEach(() => {
      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'user-1',
        context: 'dashboard',
        jti: 'jti-rotation'
      })
      mockTokenManager.issueTokens.mockResolvedValue(ROTATION_AUTH_RESULT)
      mockBruteForce.isLockedOut.mockResolvedValue(false)
    })

    // Scenario: a TOTP secret encrypted under a key since retired, with the rotation
    // configured. Expected: the challenge succeeds. Why: the ciphertext records no key
    // identifier, so without the retired key every stored secret becomes undecryptable the
    // moment `mfa.encryptionKey` changes — every enrolled user's authenticator stops matching
    // at once, with no way back.
    it('should decrypt a secret stored under a retired key', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        // Written under the OLD key: the current one cannot open it.
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)

      await expect(
        rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      ).resolves.toBe(ROTATION_AUTH_RESULT)
    })

    // Scenario: the same secret, rotation NOT configured. Expected: refused. Why: this is the
    // failure the test above prevents, and it has to be shown to be real — otherwise the
    // fallback could be doing nothing and both tests would still pass.
    it('should refuse a secret whose key was not listed', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })

      await expect(
        service.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Scenario: a successful challenge against a secret under a retired key. Expected: the
    // secret is rewritten under the current one. Why: without it the rotation never drains and
    // the retired key has to stay configured forever — a key that still opens every secret.
    it('should re-encrypt the secret under the current key after a successful challenge', async () => {
      const { encrypt, decrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      await new Promise((resolve) => setImmediate(resolve))

      const [, update] = mockUserRepo.updateMfa.mock.calls[0] as [string, { mfaSecret: string }]
      // Readable under the CURRENT key, and the plaintext is unchanged.
      expect(decrypt(update.mfaSecret, VALID_ENCRYPTION_KEY)).toBe(base32)
    })

    // Scenario: the re-encryption write fails. Expected: the challenge still succeeded. Why:
    // the retired key still opens the secret, so a failed migration costs nothing but the
    // migration — failing the login over it would turn housekeeping into an outage.
    it('should not fail the challenge when the re-encryption write fails', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.updateMfa.mockRejectedValue(new Error('write failed'))

      await expect(
        rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      ).resolves.toBe(ROTATION_AUTH_RESULT)
      await new Promise((resolve) => setImmediate(resolve))

      expect(errorSpy).toHaveBeenCalledWith(
        're-encryption under the current MFA key failed',
        expect.any(Error)
      )
      errorSpy.mockRestore()
    })

    // Scenario: the same rotation, but the account lives on the platform plane. Expected: the
    // rewrite goes to the platform repository. Why: the two planes are separate stores, and a
    // rewrite routed to the wrong one leaves the platform secret under the retired key forever
    // while the log says the migration ran.
    it('should re-encrypt a platform secret through the platform repository', async () => {
      const { encrypt, decrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockTokenManager.verifyMfaTempToken.mockResolvedValue({
        userId: 'admin-1',
        context: 'platform',
        jti: 'jti-rotation-platform'
      })
      mockTokenManager.issuePlatformTokens.mockResolvedValue(ROTATION_AUTH_RESULT)
      mockPlatformUserRepo.findById.mockResolvedValue({
        ...SAFE_ADMIN,
        passwordHash: 'hash',
        mfaEnabled: true,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: []
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockPlatformUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
      const [, update] = mockPlatformUserRepo.updateMfa.mock.calls[0] as [
        string,
        { mfaSecret: string }
      ]
      expect(decrypt(update.mfaSecret, VALID_ENCRYPTION_KEY)).toBe(base32)
    })

    // Scenario: a RECOVERY-code challenge against a secret under a retired key. Expected: the
    // splice write carries the re-encrypted secret. Why: that path already writes the record,
    // so a separate write would be a second round trip — but it also means the re-encryption
    // rides on a value that is easy to leave untouched, and then only recovery-code users never
    // migrate.
    it('should re-encrypt on the recovery-code path, in the write it already makes', async () => {
      const { encrypt, decrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const plainRecovery = '1234-5678-9012'
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: [hmacSha256(plainRecovery, HMAC_KEY)]
      })
      mockUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', plainRecovery, '1.2.3.4', 'Browser')

      const [, update] = mockUserRepo.updateMfa.mock.calls[0] as [
        string,
        { mfaSecret: string; mfaRecoveryCodes: string[] }
      ]
      expect(decrypt(update.mfaSecret, VALID_ENCRYPTION_KEY)).toBe(base32)
      // …and the code that was used is still gone: the re-encryption rides along, it does not
      // replace the write's own job.
      expect(update.mfaRecoveryCodes).toEqual([])
    })

    // Scenario: a TOTP re-encryption for a record whose recovery-code list is absent, not
    // empty. Expected: the rewrite still happens and stores an empty list. Why: a repository
    // that returns `undefined` for a user who never generated codes would otherwise crash the
    // migration — or, worse, write `undefined` over the column.
    it('should re-encrypt a record that carries no recovery-code list', async () => {
      const { encrypt } = await import('../crypto/aes-gcm')
      const { generateTotpSecret, generateTotp } = await import('../crypto/totp')
      const { base32 } = generateTotpSecret()
      const rotated = await buildService({
        mfa: { ...mockOptions.mfa, previousEncryptionKeys: [RETIRED_KEY] }
      })

      mockUserRepo.findById.mockResolvedValue({
        ...AUTH_USER_MFA_ENABLED,
        mfaSecret: encrypt(base32, RETIRED_KEY),
        mfaRecoveryCodes: undefined
      })
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.updateMfa.mockResolvedValue(undefined)

      await rotated.challenge('mfa.temp', generateTotp(base32), '1.2.3.4', 'Browser')
      await new Promise((resolve) => setImmediate(resolve))

      const [, update] = mockUserRepo.updateMfa.mock.calls[0] as [
        string,
        { mfaRecoveryCodes: string[] }
      ]
      expect(update.mfaRecoveryCodes).toEqual([])
    })
  })
})
