/**
 * PlatformAuthService — unit tests
 *
 * Tests the full authentication lifecycle for platform administrators:
 * login (with/without MFA, brute-force, credential errors), logout (JTI revocation,
 * grace-pointer cleanup), refresh (delegation), getMe (safe projection), and
 * revokeAllPlatformSessions (atomic delegation).
 *
 * Mocking strategy: all collaborators are plain jest mock objects. No real Redis,
 * no real JWT, no real password hash. The test module is rebuilt in beforeEach
 * so mocks are cleanly reset between every test.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY
} from '../bymax-one-nest-auth.constants'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { PlatformAuthService } from './platform-auth.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test doubles — platform admin records
// ---------------------------------------------------------------------------

const PLATFORM_ADMIN = {
  id: 'admin-1',
  email: 'admin@example.com',
  name: 'Super Admin',
  passwordHash: 'scrypt:salt:hash',
  role: 'super_admin',
  status: 'active',
  mfaEnabled: false,
  mfaSecret: undefined,
  mfaRecoveryCodes: undefined,
  lastLoginAt: null,
  updatedAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01')
}

const PLATFORM_ADMIN_MFA = {
  ...PLATFORM_ADMIN,
  mfaEnabled: true,
  mfaSecret: 'encrypted-totp-secret',
  mfaRecoveryCodes: ['hash1', 'hash2']
}

// Safe view used for result comparison (no credential fields).
const SAFE_ADMIN = {
  id: 'admin-1',
  email: 'admin@example.com',
  name: 'Super Admin',
  role: 'super_admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  updatedAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01')
}

const PLATFORM_AUTH_RESULT = {
  admin: SAFE_ADMIN,
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh-uuid'
}

const ROTATED_TOKEN_RESULT = {
  session: { userId: 'admin-1', tenantId: '', role: 'super_admin' },
  accessToken: 'new-access.jwt',
  rawRefreshToken: 'new-raw-refresh'
}

// JWT secret used in mockOptions — must be ≥32 chars for hmacSha256 key material.
const JWT_SECRET = 'test-jwt-secret-32bytes-exact-here!!'

// ---------------------------------------------------------------------------
// Mock collaborators
// ---------------------------------------------------------------------------

const mockPlatformUserRepo = {
  findByEmail: jest.fn(),
  findById: jest.fn(),
  updateLastLogin: jest.fn(),
  updateMfa: jest.fn(),
  updatePassword: jest.fn(),
  updateStatus: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn(),
  compare: jest.fn()
}

const mockTokenManager = {
  issuePlatformTokens: jest.fn(),
  issueMfaTempToken: jest.fn(),
  reissuePlatformTokens: jest.fn()
}

const mockBruteForce = {
  isLockedOut: jest.fn(),
  recordFailure: jest.fn(),
  resetFailures: jest.fn(),
  getRemainingLockoutSeconds: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  del: jest.fn(),
  srem: jest.fn(),
  invalidateUserSessions: jest.fn()
}

const mockOptions = {
  jwt: { secret: JWT_SECRET }
}

// ---------------------------------------------------------------------------
// Suite — PlatformAuthService
// ---------------------------------------------------------------------------

describe('PlatformAuthService', () => {
  let service: PlatformAuthService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        PlatformAuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: AuthRedisService, useValue: mockRedis }
      ]
    }).compile()

    service = module.get(PlatformAuthService)
  })

  // ---------------------------------------------------------------------------
  // login
  // ---------------------------------------------------------------------------

  describe('login', () => {
    const dto = { email: 'admin@example.com', password: 'SecureAdminPass123' }
    const ip = '1.2.3.4'
    const userAgent = 'TestBrowser/1.0'

    beforeEach(() => {
      // Default: not locked, admin found, password matches, no MFA, tokens issued
      mockBruteForce.isLockedOut.mockResolvedValue(false)
      mockBruteForce.recordFailure.mockResolvedValue(undefined)
      mockBruteForce.resetFailures.mockResolvedValue(undefined)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(120)
      mockPlatformUserRepo.findByEmail.mockResolvedValue(PLATFORM_ADMIN)
      mockPasswordService.compare.mockResolvedValue(true)
      mockTokenManager.issuePlatformTokens.mockResolvedValue(PLATFORM_AUTH_RESULT)
      mockPlatformUserRepo.updateLastLogin.mockResolvedValue(undefined)
    })

    // Verifies the complete happy path: valid credentials with no MFA → auth result + updateLastLogin side effect.
    it('should return PlatformAuthResult and call updateLastLogin on success', async () => {
      const result = await service.login(dto, ip, userAgent)
      expect(result).toBe(PLATFORM_AUTH_RESULT)
      // Fire-and-forget: drain the microtask queue so the updateLastLogin call completes.
      await Promise.resolve()
      expect(mockPlatformUserRepo.updateLastLogin).toHaveBeenCalledWith(PLATFORM_ADMIN.id)
    })

    // Verifies that the brute-force identifier is computed as hmacSha256('platform:' + email, secret)
    // so the stored Redis key cannot be reversed via dictionary lookup to reveal the admin email.
    it('should build the brute-force identifier as hmacSha256("platform:email", jwt.secret)', async () => {
      await service.login(dto, ip, userAgent)
      const expectedId = hmacSha256('platform:' + dto.email, JWT_SECRET)
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(expectedId)
      expect(mockBruteForce.resetFailures).toHaveBeenCalledWith(expectedId)
    })

    // Verifies that issuePlatformTokens receives the safe admin (no passwordHash/mfaSecret/mfaRecoveryCodes).
    it('should strip credential fields from admin before calling issuePlatformTokens', async () => {
      await service.login(dto, ip, userAgent)
      const adminArg = (mockTokenManager.issuePlatformTokens.mock.calls[0] as [unknown])[0]
      expect(adminArg).not.toHaveProperty('passwordHash')
      expect(adminArg).not.toHaveProperty('mfaSecret')
      expect(adminArg).not.toHaveProperty('mfaRecoveryCodes')
    })

    // Verifies ACCOUNT_LOCKED is thrown when bruteForce.isLockedOut returns true,
    // with the retryAfterSeconds from getRemainingLockoutSeconds attached.
    it('should throw ACCOUNT_LOCKED (429) when the account is locked', async () => {
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(300)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as {
        error: { code: string; retryAfterSeconds: number }
      }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
      expect(caught!.getStatus()).toBe(429)
    })

    // Verifies that retryAfterSeconds from getRemainingLockoutSeconds is included in the error.
    it('should include retryAfterSeconds from getRemainingLockoutSeconds in ACCOUNT_LOCKED', async () => {
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(77)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      const response = caught!.getResponse() as {
        error: { details: { retryAfterSeconds: number } }
      }
      expect(response.error.details.retryAfterSeconds).toBe(77)
    })

    // Verifies INVALID_CREDENTIALS when the email is not found and recordFailure is called.
    it('should record failure and throw INVALID_CREDENTIALS when email is not found', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue(null)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies INVALID_CREDENTIALS when the password does not match and recordFailure is called.
    it('should record failure and throw INVALID_CREDENTIALS when password is wrong', async () => {
      mockPasswordService.compare.mockResolvedValue(false)

      let caught: AuthException | undefined
      try {
        await service.login(dto, ip, userAgent)
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies the MFA path: when admin.mfaEnabled is true, issueMfaTempToken is called
    // and a MfaChallengeResult is returned instead of a full PlatformAuthResult.
    it('should return MfaChallengeResult when admin has MFA enabled', async () => {
      mockPlatformUserRepo.findByEmail.mockResolvedValue(PLATFORM_ADMIN_MFA)
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.token')

      const result = await service.login(dto, ip, userAgent)
      expect(result).toEqual({ mfaRequired: true, mfaTempToken: 'mfa.temp.token' })
      expect(mockTokenManager.issueMfaTempToken).toHaveBeenCalledWith(
        PLATFORM_ADMIN_MFA.id,
        'platform'
      )
      // Tokens should NOT be issued on the MFA path.
      expect(mockTokenManager.issuePlatformTokens).not.toHaveBeenCalled()
    })

    // Verifies that when updateLastLogin rejects, the error is swallowed and logged
    // but the auth result is still returned to the caller (fire-and-forget guarantee).
    it('should swallow updateLastLogin errors and still return the auth result', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockPlatformUserRepo.updateLastLogin.mockRejectedValue(new Error('DB timeout'))

      const result = await service.login(dto, ip, userAgent)
      expect(result).toBe(PLATFORM_AUTH_RESULT)
      // Drain microtask queue so the fire-and-forget rejection handler runs.
      await Promise.resolve()
      expect(loggerSpy).toHaveBeenCalledWith('updateLastLogin failed', expect.any(Error))
      loggerSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // logout
  // ---------------------------------------------------------------------------

  describe('logout', () => {
    const userId = 'admin-1'
    const jti = 'a1b2c3d4-1234-4abc-8def-a1b2c3d4e5f6'
    const rawRefreshToken = 'some-opaque-refresh-token'
    const tokenHash = sha256(rawRefreshToken)

    beforeEach(() => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.srem.mockResolvedValue(1)
    })

    // Verifies that when the access token still has remaining TTL, the JTI is
    // blacklisted in Redis (rv:{jti}) to prevent it being used after logout.
    it('should blacklist the JTI in Redis when the token is not yet expired', async () => {
      const futureExp = Math.floor(Date.now() / 1000) + 3600
      await service.logout(userId, jti, futureExp, rawRefreshToken)
      expect(mockRedis.set).toHaveBeenCalledWith('rv:' + jti, '1', expect.any(Number))
      const ttl = (mockRedis.set.mock.calls[0] as [string, string, number])[2]
      expect(ttl).toBeGreaterThan(0)
    })

    // Verifies that when the token is already expired (exp <= now), no revocation entry
    // is written — there is nothing to blacklist since the token cannot be reused anyway.
    it('should NOT set rv:{jti} when the token has already expired', async () => {
      const pastExp = Math.floor(Date.now() / 1000) - 1
      await service.logout(userId, jti, pastExp, rawRefreshToken)
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Verifies that the primary platform refresh token key (prt:{hash}) is deleted from Redis.
    it('should delete prt:{sha256(rawRefreshToken)} from Redis', async () => {
      await service.logout(userId, jti, Math.floor(Date.now() / 1000) + 3600, rawRefreshToken)
      expect(mockRedis.del).toHaveBeenCalledWith('prt:' + tokenHash)
    })

    // Verifies that the grace-pointer key (prp:{hash}) is also deleted during logout
    // so a partially-rotated session cannot be reused after the admin logs out.
    it('should delete prp:{sha256(rawRefreshToken)} from Redis', async () => {
      await service.logout(userId, jti, Math.floor(Date.now() / 1000) + 3600, rawRefreshToken)
      expect(mockRedis.del).toHaveBeenCalledWith('prp:' + tokenHash)
    })

    // Verifies that prt:{hash} is removed from the per-user sess: SET so that
    // a future revokeAllPlatformSessions call does not try to delete an already-gone key.
    it('should srem prt:{hash} from sess:{userId}', async () => {
      await service.logout(userId, jti, Math.floor(Date.now() / 1000) + 3600, rawRefreshToken)
      expect(mockRedis.srem).toHaveBeenCalledWith('sess:' + userId, 'prt:' + tokenHash)
    })

    // Verifies that prp:{hash} is also removed from the per-user sess: SET.
    it('should srem prp:{hash} from sess:{userId}', async () => {
      await service.logout(userId, jti, Math.floor(Date.now() / 1000) + 3600, rawRefreshToken)
      expect(mockRedis.srem).toHaveBeenCalledWith('sess:' + userId, 'prp:' + tokenHash)
    })
  })

  // ---------------------------------------------------------------------------
  // refresh
  // ---------------------------------------------------------------------------

  describe('refresh', () => {
    // Verifies that refresh is a thin delegation to TokenManagerService.reissuePlatformTokens —
    // the caller only needs to pass the raw token; complex rotation logic lives in the manager.
    it('should delegate to tokenManager.reissuePlatformTokens and return its result', async () => {
      mockTokenManager.reissuePlatformTokens.mockResolvedValue(ROTATED_TOKEN_RESULT)

      const result = await service.refresh('raw-refresh', '1.2.3.4', 'Browser/1')
      expect(result).toBe(ROTATED_TOKEN_RESULT)
      expect(mockTokenManager.reissuePlatformTokens).toHaveBeenCalledWith(
        'raw-refresh',
        '1.2.3.4',
        'Browser/1'
      )
    })

    // Verifies that errors thrown by reissuePlatformTokens propagate without wrapping —
    // the REFRESH_TOKEN_INVALID AuthException must surface unchanged to the controller.
    it('should propagate errors from reissuePlatformTokens', async () => {
      mockTokenManager.reissuePlatformTokens.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
      )
      await expect(service.refresh('invalid-token', '1.2.3.4', 'Browser/1')).rejects.toThrow(
        AuthException
      )
    })
  })

  // ---------------------------------------------------------------------------
  // getMe
  // ---------------------------------------------------------------------------

  describe('getMe', () => {
    // Verifies the happy path: admin exists → safe projection returned (no credentials).
    it('should return SafeAuthPlatformUser when admin is found', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue(PLATFORM_ADMIN)
      const result = await service.getMe('admin-1')
      expect(result).not.toHaveProperty('passwordHash')
      expect(result).not.toHaveProperty('mfaSecret')
      expect(result).not.toHaveProperty('mfaRecoveryCodes')
      expect(result.id).toBe('admin-1')
      expect(result.email).toBe('admin@example.com')
    })

    // Verifies that when the admin record cannot be found (deleted/suspended after login),
    // TOKEN_INVALID is thrown so the guard invalidates the session.
    it('should throw TOKEN_INVALID when the admin no longer exists', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue(null)

      let caught: AuthException | undefined
      try {
        await service.getMe('admin-1')
      } catch (e) {
        caught = e instanceof AuthException ? e : undefined
      }
      expect(caught).toBeInstanceOf(AuthException)
      const response = caught!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // Verifies that an admin with mfaSecret and mfaRecoveryCodes set also has those
    // stripped in the safe projection, even when they are non-undefined values.
    it('should strip mfaSecret and mfaRecoveryCodes even when they are set', async () => {
      mockPlatformUserRepo.findById.mockResolvedValue(PLATFORM_ADMIN_MFA)
      const result = await service.getMe('admin-1')
      expect(result).not.toHaveProperty('passwordHash')
      expect(result).not.toHaveProperty('mfaSecret')
      expect(result).not.toHaveProperty('mfaRecoveryCodes')
      expect((result as { mfaEnabled: boolean }).mfaEnabled).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // revokeAllPlatformSessions
  // ---------------------------------------------------------------------------

  describe('revokeAllPlatformSessions', () => {
    // Verifies that revokeAllPlatformSessions delegates entirely to the atomic Lua helper
    // invalidateUserSessions — no SMEMBERS+loop which would have a TOCTOU race.
    it('should delegate to redis.invalidateUserSessions with the userId', async () => {
      mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
      await service.revokeAllPlatformSessions('admin-1')
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('admin-1')
    })

    // Verifies that errors from invalidateUserSessions propagate so the caller can handle them.
    it('should propagate errors from redis.invalidateUserSessions', async () => {
      mockRedis.invalidateUserSessions.mockRejectedValue(new Error('Redis timeout'))
      await expect(service.revokeAllPlatformSessions('admin-1')).rejects.toThrow('Redis timeout')
    })
  })
})
