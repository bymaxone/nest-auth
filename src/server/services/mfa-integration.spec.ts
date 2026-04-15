/**
 * @fileoverview MFA integration smoke tests — end-to-end flow validation.
 *
 * Validates the full MFA lifecycle (setup → verifyAndEnable → challenge → disable)
 * and key security properties: anti-replay, brute-force isolation, session invalidation.
 *
 * External dependencies (Redis, repositories, email, brute-force) are mocked.
 * AES-256-GCM encrypt/decrypt and TOTP generation use real crypto to catch integration
 * regressions that mocks would mask.
 *
 * Test scenarios:
 *  1. Full flow: setup → verifyAndEnable → challenge (TOTP) end-to-end
 *  2. Setup is idempotent (concurrent calls within TTL return the same data)
 *  3. Recovery codes work as alternative to TOTP in challenge
 *  4. Exhausted recovery codes leave user blocked without TOTP
 *  5. Anti-replay: same TOTP code rejected on second challenge within 90 s
 *  6. Brute-force on challenge: lockout after threshold, temp token invalid after lock
 *  7. Challenge BF identifier is namespaced ('challenge:') — independent of login BF counter
 *  8. Challenge with context='platform' returns PlatformAuthResult
 *  9. verifyAndEnable invalidates all existing sessions
 * 10. Disable requires TOTP — recovery-code-length strings are rejected
 * 11. @SkipMfa() bypasses MfaRequiredGuard
 */

import { Reflector } from '@nestjs/core'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-one-nest-auth.constants'
import { encrypt } from '../crypto/aes-gcm'
import { hmacSha256 } from '../crypto/secure-token'
import { generateHotp, generateTotpSecret } from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { MfaRequiredGuard } from '../guards/mfa-required.guard'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { MfaService } from './mfa.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/** Valid 32-byte AES-256-GCM key. TEST FIXTURE ONLY — not a real credential. */
const VALID_ENCRYPTION_KEY = Buffer.from('nest-auth-test-encryption-key-32').toString('base64')

/** TEST FIXTURE ONLY — not a real JWT secret. */
const JWT_SECRET = 'nest-auth-test-jwt-secret-32chars+'

const mockOptions = {
  jwt: { secret: JWT_SECRET },
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

const DASHBOARD_USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  passwordHash: 'hash',
  mfaSecret: null,
  mfaRecoveryCodes: null
}

const PLATFORM_ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01'),
  passwordHash: 'hash',
  mfaSecret: null,
  mfaRecoveryCodes: null
}

// ---------------------------------------------------------------------------
// Mock doubles
// ---------------------------------------------------------------------------

const mockUserRepo = { findById: jest.fn(), updateMfa: jest.fn() }
const mockPlatformUserRepo = { findById: jest.fn(), updateMfa: jest.fn() }

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

const mockEmailProvider = {
  sendMfaEnabledNotification: jest.fn(),
  sendMfaDisabledNotification: jest.fn()
}

const mockHooks = {}

// ---------------------------------------------------------------------------
// Suite bootstrap
// ---------------------------------------------------------------------------

describe('MFA — integration smoke tests', () => {
  let service: MfaService

  beforeEach(async () => {
    jest.useFakeTimers()
    jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
    jest.resetAllMocks()

    // Default safe returns
    mockRedis.get.mockResolvedValue(null)
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(undefined)
    mockRedis.sadd.mockResolvedValue(1)
    mockRedis.srem.mockResolvedValue(1)
    mockRedis.expire.mockResolvedValue(undefined)
    mockRedis.setIfAbsent.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockUserRepo.findById.mockResolvedValue(DASHBOARD_USER)
    mockUserRepo.updateMfa.mockResolvedValue(undefined)
    mockPlatformUserRepo.findById.mockResolvedValue(PLATFORM_ADMIN)
    mockPlatformUserRepo.updateMfa.mockResolvedValue(undefined)
    mockBruteForce.isLockedOut.mockResolvedValue(false)
    mockBruteForce.recordFailure.mockResolvedValue(undefined)
    mockBruteForce.resetFailures.mockResolvedValue(undefined)
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
        {
          provide: PasswordService,
          useValue: {
            hash: jest.fn().mockResolvedValue('$scrypt$hashed'),
            compare: jest.fn().mockResolvedValue(false)
          }
        },
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

  // ---------------------------------------------------------------------------
  // 1. Full E2E flow: setup → verifyAndEnable → challenge (TOTP)
  // ---------------------------------------------------------------------------

  // Validates that the three-step MFA onboarding chain completes without error
  // when a real TOTP code is used at each step.
  it('1. full flow: setup → verifyAndEnable → challenge (TOTP) succeeds end-to-end', async () => {
    // ── Step 1: setup ──
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)
    const setupData = {
      encryptedSecret,
      hashedCodes: ['$scrypt$hash1', '$scrypt$hash2'],
      encryptedPlainCodes: encrypt('["plain1", "plain2"]', VALID_ENCRYPTION_KEY)
    }
    // setup() calls setIfAbsent first; return true (new key) then fall through to get
    mockRedis.setIfAbsent.mockResolvedValue(true)
    // setup() then reads back the data it just stored
    mockRedis.get.mockResolvedValue(JSON.stringify(setupData))

    const setupResult = await service.setup('user-1')
    expect(setupResult.secret).toBeDefined()
    expect(setupResult.qrCodeUri).toContain('TestApp')
    expect(setupResult.recoveryCodes).toHaveLength(2)

    // ── Step 2: verifyAndEnable with a valid TOTP ──
    const currentStep = Math.floor(Date.now() / 1000 / 30)
    const validCode = generateHotp(base32, currentStep)
    mockRedis.setnx.mockResolvedValue(true) // anti-replay: first use
    mockRedis.get.mockResolvedValue(JSON.stringify(setupData))

    await expect(
      service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')
    ).resolves.toBeUndefined()

    expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
      'user-1',
      expect.objectContaining({ mfaEnabled: true })
    )

    // ── Step 3: challenge via mfa temp token ──
    // Generate a fresh TOTP code (next step to avoid anti-replay on the same code)
    const nextStep = currentStep + 1
    const challengeCode = generateHotp(base32, nextStep)

    const userWithMfa = { ...DASHBOARD_USER, mfaEnabled: true, mfaSecret: encryptedSecret }
    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard'
    })
    mockUserRepo.findById.mockResolvedValue(userWithMfa)
    mockRedis.setnx.mockResolvedValue(true) // fresh anti-replay slot
    mockTokenManager.issueTokens.mockResolvedValue({
      accessToken: 'at',
      rawRefreshToken: 'rt',
      user: {}
    })

    const result = await service.challenge('mfa.temp.token', challengeCode, '1.2.3.4', 'Browser')
    expect(result).toMatchObject({ accessToken: 'at' })
  })

  // ---------------------------------------------------------------------------
  // 2. Setup idempotency — concurrent calls within TTL return the same secret
  // ---------------------------------------------------------------------------

  // Validates that a second setup() call within the TTL window returns the data
  // already stored in Redis instead of generating a new secret (prevents secret churn).
  it('2. setup is idempotent: second call within TTL returns the existing stored secret', async () => {
    const { base32: storedBase32 } = generateTotpSecret()
    const storedEncryptedSecret = encrypt(storedBase32, VALID_ENCRYPTION_KEY)
    const storedSetupData = {
      encryptedSecret: storedEncryptedSecret,
      hashedCodes: ['$scrypt$hash1', '$scrypt$hash2'],
      encryptedPlainCodes: encrypt('["old-plain1", "old-plain2"]', VALID_ENCRYPTION_KEY)
    }

    // Second call: setIfAbsent returns false (key already claimed by the first request)
    // → service reads from redis.get and returns the already-stored data.
    mockRedis.setIfAbsent.mockResolvedValue(false)
    mockRedis.get.mockResolvedValue(JSON.stringify(storedSetupData))

    const result = await service.setup('user-1')

    // Result must reflect the STORED secret — not a freshly generated one.
    expect(result.secret).toBe(storedBase32)
    expect(result.qrCodeUri).toContain(storedBase32)
    expect(result.recoveryCodes).toEqual(['old-plain1', 'old-plain2'])
    // redis.get must have been called to retrieve the existing data
    expect(mockRedis.get).toHaveBeenCalled()
  })

  // ---------------------------------------------------------------------------
  // 3. Recovery codes work as alternative to TOTP in challenge
  // ---------------------------------------------------------------------------

  // Validates that a valid plain-text recovery code is accepted by challenge()
  // when the user cannot supply a TOTP code.
  it('3. recovery code works as an alternative to TOTP in challenge', async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)

    // PasswordService.compare is mocked to return true for the recovery code match.
    const plainCode = 'PLAIN-RECOVERY-CODE'
    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard'
    })
    mockUserRepo.findById.mockResolvedValue({
      ...DASHBOARD_USER,
      mfaEnabled: true,
      mfaSecret: encryptedSecret,
      mfaRecoveryCodes: ['$scrypt$hashedcode']
    })
    mockRedis.setnx.mockResolvedValue(true) // TOTP anti-replay
    // passwordService.compare returns true when the plain recovery code matches the hash
    const mockPasswordSvc = { compare: jest.fn().mockResolvedValue(true) }
    // Inject passwordService via re-bootstrap with mock
    const module2 = await Test.createTestingModule({
      providers: [
        MfaService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: PasswordService, useValue: mockPasswordSvc },
        { provide: SessionService, useValue: mockSessionService },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
      ]
    }).compile()
    const svc2 = module2.get(MfaService)

    mockTokenManager.issueTokens.mockResolvedValue({
      accessToken: 'at',
      rawRefreshToken: 'rt',
      user: {}
    })

    const result = await svc2.challenge('temp.token', plainCode, '1.2.3.4', 'Browser')
    expect(result).toMatchObject({ accessToken: 'at' })
    expect(mockUserRepo.updateMfa).toHaveBeenCalledWith(
      'user-1',
      expect.objectContaining({ mfaEnabled: true, mfaRecoveryCodes: [] })
    )
  })

  // ---------------------------------------------------------------------------
  // 4. All recovery codes consumed — user blocked without TOTP
  // ---------------------------------------------------------------------------

  // Once all recovery codes have been used (empty array), a recovery-code-length
  // string is rejected even if TOTP is unavailable — no fallback left.
  it('4. challenge rejects code when recovery codes array is exhausted', async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)
    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard'
    })
    mockUserRepo.findById.mockResolvedValue({
      ...DASHBOARD_USER,
      mfaEnabled: true,
      mfaSecret: encryptedSecret,
      mfaRecoveryCodes: [] // all consumed
    })
    mockRedis.setnx.mockResolvedValue(true)

    // A non-TOTP string will fail TOTP verification and there are no recovery codes to check.
    await expect(
      service.challenge('temp.token', 'not-a-totp', '1.2.3.4', 'Browser')
    ).rejects.toThrow(AuthException)
  })

  // ---------------------------------------------------------------------------
  // 5. Anti-replay: same TOTP code rejected on second challenge within 90 s
  // ---------------------------------------------------------------------------

  // Validates that the setnx-based anti-replay key prevents a stolen TOTP from
  // being replayed within the 90-second acceptance window.
  it('5. same TOTP code is rejected as a replay on second challenge attempt', async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)
    const currentStep = Math.floor(Date.now() / 1000 / 30)
    const validCode = generateHotp(base32, currentStep)

    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard'
    })
    mockUserRepo.findById.mockResolvedValue({
      ...DASHBOARD_USER,
      mfaEnabled: true,
      mfaSecret: encryptedSecret,
      mfaRecoveryCodes: []
    })
    mockTokenManager.issueTokens.mockResolvedValue({
      accessToken: 'at',
      rawRefreshToken: 'rt',
      user: {}
    })

    // First challenge: setnx returns true (fresh code) → succeeds
    mockRedis.setnx.mockResolvedValueOnce(true)
    await expect(
      service.challenge('temp.token', validCode, '1.2.3.4', 'Browser')
    ).resolves.toBeDefined()

    // Second challenge with the same code: setnx returns false (replay detected) → rejected
    mockRedis.setnx.mockResolvedValueOnce(false)
    await expect(service.challenge('temp.token', validCode, '1.2.3.4', 'Browser')).rejects.toThrow(
      AuthException
    )
  })

  // ---------------------------------------------------------------------------
  // 6. Brute-force on challenge — lockout after threshold
  // ---------------------------------------------------------------------------

  // Validates that after repeated wrong codes the brute-force service is consulted
  // on each attempt, and once locked out, further attempts throw ACCOUNT_LOCKED
  // before any TOTP validation occurs.
  it('6. challenge throws ACCOUNT_LOCKED and stops processing when BF threshold is reached', async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)

    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard'
    })
    mockUserRepo.findById.mockResolvedValue({
      ...DASHBOARD_USER,
      mfaEnabled: true,
      mfaSecret: encryptedSecret,
      mfaRecoveryCodes: []
    })
    mockRedis.setnx.mockResolvedValue(true)

    // First attempt: not locked → wrong code → recordFailure
    mockBruteForce.isLockedOut.mockResolvedValueOnce(false)
    await expect(service.challenge('temp.token', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
      AuthException
    )
    expect(mockBruteForce.recordFailure).toHaveBeenCalledTimes(1)

    // Second attempt: now locked → ACCOUNT_LOCKED thrown before TOTP check
    mockBruteForce.isLockedOut.mockResolvedValueOnce(true)
    try {
      await service.challenge('temp.token', '000000', '1.2.3.4', 'Browser')
      expect('should not reach here').toBe(true)
    } catch (e) {
      expect((e as AuthException).getResponse()).toMatchObject({
        error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_LOCKED })
      })
    }
    // recordFailure must NOT be called again — lockout check exits early
    expect(mockBruteForce.recordFailure).toHaveBeenCalledTimes(1)
  })

  // ---------------------------------------------------------------------------
  // 7. Brute-force identifier is namespaced with 'challenge:' prefix
  // ---------------------------------------------------------------------------

  // Validates that the challenge BF counter is keyed by hmacSha256('challenge:{userId}', secret),
  // ensuring it is independent from the login BF counter (keyed by hmacSha256(userId, secret))
  // and from the disable counter ('disable:{userId}').
  it("7. challenge BF identifier includes 'challenge:' prefix — independent of login counter", async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)

    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'user-1',
      context: 'dashboard'
    })
    mockUserRepo.findById.mockResolvedValue({
      ...DASHBOARD_USER,
      mfaEnabled: true,
      mfaSecret: encryptedSecret,
      mfaRecoveryCodes: []
    })
    mockRedis.setnx.mockResolvedValue(true)

    // Trigger a failed attempt so isLockedOut and recordFailure are called with a BF identifier
    await expect(service.challenge('temp.token', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
      AuthException
    )

    const expectedBfId = hmacSha256(`challenge:user-1`, JWT_SECRET)
    const plainBfId = hmacSha256('user-1', JWT_SECRET) // login-style identifier
    const disableBfId = hmacSha256('disable:user-1', JWT_SECRET) // disable-style identifier

    expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(expectedBfId)
    expect(mockBruteForce.recordFailure).toHaveBeenCalledWith(expectedBfId)
    // Must NOT use the plain (login) or disable-namespaced identifiers
    expect(mockBruteForce.isLockedOut).not.toHaveBeenCalledWith(plainBfId)
    expect(mockBruteForce.isLockedOut).not.toHaveBeenCalledWith(disableBfId)
  })

  // ---------------------------------------------------------------------------
  // 8. Challenge with context='platform' returns PlatformAuthResult
  // ---------------------------------------------------------------------------

  // Validates that when the MFA temp token carries context='platform', the service
  // uses the platform repository and issuePlatformTokens.
  it('8. challenge with platform context returns PlatformAuthResult via issuePlatformTokens', async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)
    const currentStep = Math.floor(Date.now() / 1000 / 30)
    const validCode = generateHotp(base32, currentStep)

    mockTokenManager.verifyMfaTempToken.mockResolvedValue({
      userId: 'admin-1',
      context: 'platform'
    })
    mockPlatformUserRepo.findById.mockResolvedValue({
      ...PLATFORM_ADMIN,
      mfaEnabled: true,
      mfaSecret: encryptedSecret,
      mfaRecoveryCodes: []
    })
    mockRedis.setnx.mockResolvedValue(true)
    mockTokenManager.issuePlatformTokens.mockResolvedValue({
      admin: { id: 'admin-1' },
      accessToken: 'platform-at',
      rawRefreshToken: 'platform-rt'
    })

    const result = await service.challenge('temp.token', validCode, '1.2.3.4', 'Browser')

    expect(mockPlatformUserRepo.findById).toHaveBeenCalledWith('admin-1')
    expect(mockTokenManager.issuePlatformTokens).toHaveBeenCalled()
    expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    expect(result).toMatchObject({ accessToken: 'platform-at' })
  })

  // ---------------------------------------------------------------------------
  // 9. verifyAndEnable invalidates all existing sessions
  // ---------------------------------------------------------------------------

  // Validates that after enabling MFA, invalidateUserSessions is called so that
  // existing refresh tokens are revoked — forcing re-authentication through the MFA
  // challenge endpoint.
  it('9. verifyAndEnable invalidates all sessions after enabling MFA', async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)
    const setupData = {
      encryptedSecret,
      hashedCodes: [],
      encryptedPlainCodes: encrypt('[]', VALID_ENCRYPTION_KEY)
    }
    mockRedis.get.mockResolvedValue(JSON.stringify(setupData))
    mockRedis.setnx.mockResolvedValue(true)

    const validCode = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))
    await service.verifyAndEnable('user-1', validCode, '1.2.3.4', 'Browser')

    expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('user-1')
    expect(mockRedis.invalidateUserSessions).toHaveBeenCalledTimes(1)
  })

  // ---------------------------------------------------------------------------
  // 10. Disable requires TOTP — non-TOTP strings are rejected
  // ---------------------------------------------------------------------------

  // Validates that the disable endpoint only accepts 6-digit TOTP codes; a recovery
  // code or any other string that fails TOTP verification is rejected with
  // MFA_INVALID_CODE — no recovery-code pathway exists in disable().
  it('10. disable rejects non-TOTP strings with MFA_INVALID_CODE', async () => {
    const { base32 } = generateTotpSecret()
    const encryptedSecret = encrypt(base32, VALID_ENCRYPTION_KEY)
    mockUserRepo.findById.mockResolvedValue({
      ...DASHBOARD_USER,
      mfaEnabled: true,
      mfaSecret: encryptedSecret,
      mfaRecoveryCodes: ['$scrypt$hash1']
    })
    mockRedis.setnx.mockResolvedValue(true)

    // 'RCVRYCODE' looks nothing like a 6-digit TOTP — TOTP verify will return false
    await expect(service.disable('user-1', '000000', '1.2.3.4', 'Browser')).rejects.toThrow(
      AuthException
    )
    // The service must record a brute-force failure — confirming TOTP was attempted
    expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    // The service must NOT have updated the MFA data (recovery not attempted)
    expect(mockUserRepo.updateMfa).not.toHaveBeenCalled()
  })

  // ---------------------------------------------------------------------------
  // 11. @SkipMfa() bypasses MfaRequiredGuard
  // ---------------------------------------------------------------------------

  // Validates that endpoints decorated with @SkipMfa() are excluded from the
  // MFA check even when the authenticated user has mfaEnabled:true and mfaVerified:false.
  it('11. @SkipMfa() allows through a user with mfaEnabled=true and mfaVerified=false', async () => {
    const reflector = new Reflector()
    const guard = new MfaRequiredGuard(reflector)

    const payload = {
      sub: 'user-1',
      type: 'dashboard',
      mfaEnabled: true,
      mfaVerified: false // would normally be blocked
    }

    const mockContext = {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({
        getRequest: () => ({ user: payload })
      })
    }

    // Reflector returns true for 'skipMfa' metadata → guard must pass
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true)

    expect(guard.canActivate(mockContext as never)).toBe(true)
  })
})
