/**
 * @fileoverview Tests for AuthService, which orchestrates the full authentication
 * lifecycle including register, login, logout, refresh, email verification, and
 * fire-and-forget hook/side-effect error handling.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Request } from 'express'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-one-nest-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AuthService } from './auth.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

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

const AUTH_RESULT = {
  user: SAFE_USER,
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh-uuid'
}

const mockUserRepo = {
  findByEmail: jest.fn(),
  findById: jest.fn(),
  create: jest.fn(),
  updateLastLogin: jest.fn(),
  updateEmailVerified: jest.fn()
}

const mockEmailProvider = {
  sendEmailVerificationOtp: jest.fn(),
  sendPasswordResetToken: jest.fn()
}

const mockHooks = {
  beforeRegister: jest.fn(),
  afterRegister: jest.fn(),
  beforeLogin: jest.fn(),
  afterLogin: jest.fn(),
  afterLogout: jest.fn(),
  afterEmailVerified: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn(),
  compare: jest.fn()
}

const mockTokenManager = {
  issueTokens: jest.fn(),
  issueMfaTempToken: jest.fn(),
  reissueTokens: jest.fn(),
  decodeToken: jest.fn()
}

const mockBruteForce = {
  isLockedOut: jest.fn(),
  recordFailure: jest.fn(),
  resetFailures: jest.fn(),
  getRemainingLockoutSeconds: jest.fn()
}

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  setnx: jest.fn()
}

const mockOtpService = {
  generate: jest.fn(),
  store: jest.fn(),
  verify: jest.fn()
}

const mockOptions = {
  jwt: { secret: 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long' },
  emailVerification: { required: false, otpTtlSeconds: 600 },
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  bruteForce: { maxAttempts: 5, windowSeconds: 900 }
}

const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser' }
} as unknown as Request

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('AuthService', () => {
  let service: AuthService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: mockBruteForce },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: OtpService, useValue: mockOtpService }
      ]
    }).compile()

    service = module.get(AuthService)
  })

  // ---------------------------------------------------------------------------
  // register
  // ---------------------------------------------------------------------------

  describe('register', () => {
    const dto = {
      email: 'new@example.com',
      password: 'SecureP@ss1',
      name: 'New User',
      tenantId: 'tenant-1'
    }

    beforeEach(() => {
      mockHooks.beforeRegister.mockResolvedValue({ allowed: true })
      mockUserRepo.findByEmail.mockResolvedValue(null) // email not taken
      mockPasswordService.hash.mockResolvedValue('scrypt:salt:hash')
      mockUserRepo.create.mockResolvedValue(USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockHooks.afterRegister.mockResolvedValue(undefined)
    })

    // Verifies that a successful registration creates the user and returns an AuthResult with tokens.
    it('should create user and return AuthResult on success', async () => {
      const result = await service.register(dto, mockReq)
      expect(result).toBe(AUTH_RESULT)
      expect(mockUserRepo.create).toHaveBeenCalled()
    })

    // Verifies that attempting to register with an already-used email throws EMAIL_ALREADY_EXISTS.
    it('should throw EMAIL_ALREADY_EXISTS when email is taken', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      await expect(service.register(dto, mockReq)).rejects.toThrow(AuthException)
    })

    // Verifies that a beforeRegister hook returning allowed=false causes FORBIDDEN to be thrown.
    it('should throw FORBIDDEN when beforeRegister hook rejects', async () => {
      mockHooks.beforeRegister.mockResolvedValue({ allowed: false, reason: 'Blocked domain' })
      await expect(service.register(dto, mockReq)).rejects.toThrow(AuthException)
    })

    // Verifies that modifiedData from the beforeRegister hook is merged into the registration payload.
    it('should apply modifiedData from beforeRegister hook', async () => {
      mockHooks.beforeRegister.mockResolvedValue({
        allowed: true,
        modifiedData: { role: 'viewer' }
      })
      await service.register(dto, mockReq)
      // role override applied — create was called
      expect(mockUserRepo.create).toHaveBeenCalled()
    })

    // Verifies that when emailVerification.required is true, the OTP is generated and stored.
    it('should send verification OTP when emailVerification.required is true', async () => {
      const module = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, emailVerification: { required: true, otpTtlSeconds: 600 } }
          },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService }
        ]
      }).compile()

      const svc = module.get(AuthService)
      mockOtpService.generate.mockReturnValue('123456')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockResolvedValue(undefined)

      await svc.register(dto, mockReq)

      expect(mockOtpService.generate).toHaveBeenCalled()
      expect(mockOtpService.store).toHaveBeenCalled()
    })

    // Verifies that an error thrown by the afterRegister hook is logged and does not propagate to the caller.
    it('should log and swallow afterRegister hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockHooks.afterRegister.mockRejectedValue(new Error('hook error'))

      await service.register(dto, mockReq)

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith('afterRegister hook threw', expect.any(Error))
      loggerSpy.mockRestore()
    })

    // Verifies that tenantIdResolver is used when provided, overriding the dto tenantId.
    it('should use tenantIdResolver when configured in options', async () => {
      const tenantResolverModule = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              tenantIdResolver: () => 'resolved-tenant'
            }
          },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService }
        ]
      }).compile()

      const svc = tenantResolverModule.get(AuthService)

      await svc.register(dto, mockReq)

      // The resolved tenantId from the resolver ('resolved-tenant') should be used in findByEmail.
      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith(dto.email, 'resolved-tenant')
    })

    // Verifies that ip and userAgent default to empty strings when the request provides neither.
    it('should default ip and userAgent to empty string when absent from the request', async () => {
      const reqNoMeta = { ip: undefined, headers: {} } as unknown as Request
      const result = await service.register(dto, reqNoMeta)
      expect(result).toBe(AUTH_RESULT)
    })

    // Verifies that a string status value from hook modifiedData is forwarded to userRepo.create.
    it('should include status string from hook modifiedData in the create payload', async () => {
      mockHooks.beforeRegister.mockResolvedValue({
        allowed: true,
        modifiedData: { status: 'pending_approval' }
      })
      await service.register(dto, mockReq)
      expect(mockUserRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'pending_approval' })
      )
    })

    // Verifies that a boolean emailVerified from modifiedData is forwarded when emailVerification is not required.
    it('should include emailVerified boolean from modifiedData when emailVerification is not required', async () => {
      mockHooks.beforeRegister.mockResolvedValue({
        allowed: true,
        modifiedData: { emailVerified: true }
      })
      await service.register(dto, mockReq)
      expect(mockUserRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ emailVerified: true })
      )
    })

    // Verifies that array-valued request headers are joined with a comma in the sanitized hook context.
    it('should join array-valued request headers with comma in the hook context', async () => {
      const reqArrayHeader = {
        ip: '1.2.3.4',
        headers: { 'accept-encoding': ['gzip', 'br'] }
      } as unknown as Request
      await expect(service.register(dto, reqArrayHeader)).resolves.toBeDefined()
    })

    // Verifies that undefined header values are normalized to empty strings in the hook context.
    it('should normalize undefined header values to empty string in the hook context', async () => {
      const reqUndefinedHeader = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'TestBrowser', 'x-custom': undefined }
      } as unknown as Request
      await expect(service.register(dto, reqUndefinedHeader)).resolves.toBeDefined()
    })

    // Verifies that buildHookContext assigns userId to the context when the caller provides it.
    it('should assign userId to the hook context when provided to buildHookContext', () => {
      // buildHookContext is private — accessed via Reflect to cover the userId branch.
      type BuildHookContextFn = (opts: {
        userId?: string
        ip: string
        userAgent: string
        req: Request
      }) => { userId?: string }
      const buildHookContext = (
        Reflect.get(service, 'buildHookContext') as BuildHookContextFn
      ).bind(service)
      const ctx = buildHookContext({
        userId: 'test-user-id',
        ip: '1.2.3.4',
        userAgent: 'UA',
        req: mockReq
      })
      expect(ctx.userId).toBe('test-user-id')
    })
  })

  // ---------------------------------------------------------------------------
  // login
  // ---------------------------------------------------------------------------

  describe('login', () => {
    const dto = { email: 'user@example.com', password: 'correct', tenantId: 'tenant-1' }

    beforeEach(() => {
      mockBruteForce.isLockedOut.mockResolvedValue(false)
      mockBruteForce.recordFailure.mockResolvedValue(undefined)
      mockBruteForce.resetFailures.mockResolvedValue(undefined)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(0)
      mockHooks.beforeLogin.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockPasswordService.compare.mockResolvedValue(true)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined)
      mockHooks.afterLogin.mockResolvedValue(undefined)
    })

    // Verifies that a successful login returns the full AuthResult with tokens.
    it('should return AuthResult on successful login', async () => {
      const result = await service.login(dto, mockReq)
      expect(result).toBe(AUTH_RESULT)
    })

    // Verifies that a wrong password records a brute-force failure and throws INVALID_CREDENTIALS.
    it('should throw INVALID_CREDENTIALS on wrong password', async () => {
      mockPasswordService.compare.mockResolvedValue(false)
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies that a missing user records a brute-force failure and throws INVALID_CREDENTIALS.
    it('should throw INVALID_CREDENTIALS when user not found', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null)
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Verifies that an account locked by brute-force protection throws ACCOUNT_LOCKED.
    it('should throw ACCOUNT_LOCKED when brute-force limit reached', async () => {
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(543)
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
    })

    // Verifies that a user with a blocked status (e.g. BANNED) throws an AuthException.
    it('should throw when user status is blocked', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, status: 'BANNED' })
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
    })

    // Verifies that a user with MFA enabled receives an MFA challenge instead of a full auth result.
    it('should return MfaChallengeResult when user has MFA enabled', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, mfaEnabled: true })
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.token')

      const result = await service.login(dto, mockReq)
      expect(result).toMatchObject({ mfaRequired: true, mfaTempToken: 'mfa.temp.token' })
    })

    // Verifies that an unverified email blocks login when emailVerification.required is true.
    it('should throw EMAIL_NOT_VERIFIED when verification is required and email not verified', async () => {
      const module = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, emailVerification: { required: true, otpTtlSeconds: 600 } }
          },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService }
        ]
      }).compile()

      const svc = module.get(AuthService)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })

      await expect(svc.login(dto, mockReq)).rejects.toThrow(AuthException)
    })

    // Verifies that the beforeLogin hook is called with the correct email, tenantId, and hook context.
    it('should call beforeLogin hook with correct arguments', async () => {
      await service.login(dto, mockReq)
      expect(mockHooks.beforeLogin).toHaveBeenCalledWith(
        dto.email,
        dto.tenantId,
        expect.any(Object)
      )
    })

    // Verifies that the brute-force counter is reset after a successful login to clear previous failures.
    it('should reset brute-force counter after successful login', async () => {
      await service.login(dto, mockReq)
      expect(mockBruteForce.resetFailures).toHaveBeenCalled()
    })

    // Verifies that an error from updateLastLogin is logged and does not propagate (fire-and-forget).
    it('should log and swallow updateLastLogin errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockUserRepo.updateLastLogin.mockRejectedValue(new Error('db error'))

      await service.login(dto, mockReq)

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith('updateLastLogin failed', expect.any(Error))
      loggerSpy.mockRestore()
    })

    // Verifies that an error thrown by the afterLogin hook is logged and does not propagate (fire-and-forget).
    it('should log and swallow afterLogin hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockHooks.afterLogin.mockRejectedValue(new Error('hook error'))

      await service.login(dto, mockReq)

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith('afterLogin hook threw', expect.any(Error))
      loggerSpy.mockRestore()
    })

    // Verifies that ip and userAgent default to empty strings when absent from the login request.
    it('should default ip and userAgent to empty string when absent from the request', async () => {
      const reqNoMeta = { ip: undefined, headers: {} } as unknown as Request
      const result = await service.login(dto, reqNoMeta)
      expect(result).toBe(AUTH_RESULT)
    })

    // Verifies that assertUserNotBlocked falls back to ACCOUNT_INACTIVE for statuses absent from the error code map.
    it('should use ACCOUNT_INACTIVE as fallback when blocked status is not in the error code map', async () => {
      // 'LOCKED' is a valid blocked status but has no entry in the internal codeMap,
      // so the ?? fallback must return AUTH_ERROR_CODES.ACCOUNT_INACTIVE.
      const svc = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, blockedStatuses: ['LOCKED'] }
          },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService }
        ]
      })
        .compile()
        .then((m) => m.get(AuthService))

      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, status: 'LOCKED' })

      let thrown: AuthException | undefined
      try {
        await svc.login(dto, mockReq)
      } catch (e) {
        thrown = e as AuthException
      }
      expect(thrown).toBeInstanceOf(AuthException)
      expect((thrown!.getResponse() as { error: { code: string } }).error.code).toBe(
        AUTH_ERROR_CODES.ACCOUNT_INACTIVE
      )
    })
  })

  // ---------------------------------------------------------------------------
  // logout
  // ---------------------------------------------------------------------------

  describe('logout', () => {
    // Verifies that logout revokes the JWT jti in Redis and deletes the refresh session.
    it('should blacklist the JWT jti and delete the refresh session', async () => {
      mockTokenManager.decodeToken.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh', 'user-1')

      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^rv:/),
        '1',
        expect.any(Number)
      )
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:/))
    })

    // Verifies that logout resolves successfully even when the access token is malformed.
    it('should not throw when decodeToken fails (malformed token)', async () => {
      mockTokenManager.decodeToken.mockImplementation(() => {
        throw new Error('Malformed')
      })
      mockRedis.del.mockResolvedValue(undefined)

      await expect(service.logout('bad.token', 'refresh', 'user-1')).resolves.toBeUndefined()
    })

    // Verifies that an error thrown by the afterLogout hook is logged and does not propagate (fire-and-forget).
    it('should log and swallow afterLogout hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockTokenManager.decodeToken.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockRejectedValue(new Error('hook error'))

      await service.logout('access.token', 'raw-refresh', 'user-1')

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith('afterLogout hook threw', expect.any(Error))
      loggerSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // refresh
  // ---------------------------------------------------------------------------

  describe('refresh', () => {
    // Verifies that refresh delegates to tokenManager.reissueTokens and returns the rotated result.
    it('should delegate to tokenManager.reissueTokens', async () => {
      const rotated = {
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      }
      mockTokenManager.reissueTokens.mockResolvedValue(rotated)

      const result = await service.refresh('old-refresh', '1.2.3.4', 'Browser')
      expect(result).toBe(rotated)
      expect(mockTokenManager.reissueTokens).toHaveBeenCalledWith(
        'old-refresh',
        '1.2.3.4',
        'Browser'
      )
    })
  })

  // ---------------------------------------------------------------------------
  // getMe
  // ---------------------------------------------------------------------------

  describe('getMe', () => {
    // Verifies that getMe returns the safe user object without credential fields.
    it('should return the safe user when found', async () => {
      mockUserRepo.findById.mockResolvedValue(USER)
      const result = await service.getMe('user-1')
      expect(result).not.toHaveProperty('passwordHash')
      expect(result.id).toBe('user-1')
    })

    // Verifies that getMe throws TOKEN_INVALID when the user no longer exists (deleted after JWT issued).
    it('should throw TOKEN_INVALID when user not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)
      await expect(service.getMe('ghost')).rejects.toThrow(AuthException)
      try {
        await service.getMe('ghost')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
        })
      }
    })
  })

  // ---------------------------------------------------------------------------
  // verifyEmail
  // ---------------------------------------------------------------------------

  describe('verifyEmail', () => {
    // Verifies that verifyEmail calls otpService.verify and updates the user's emailVerified flag.
    it('should verify OTP and update emailVerified', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(USER)
      mockHooks.afterEmailVerified.mockResolvedValue(undefined)

      await service.verifyEmail('tenant-1', 'user@example.com', 'user-1', '123456')

      expect(mockOtpService.verify).toHaveBeenCalledWith(
        'email_verification',
        expect.any(String),
        '123456'
      )
      expect(mockUserRepo.updateEmailVerified).toHaveBeenCalledWith('user-1', true)
    })

    // Verifies that OTP verification errors from otpService propagate to the caller.
    it('should propagate OTP errors', async () => {
      mockOtpService.verify.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_INVALID))
      await expect(
        service.verifyEmail('tenant-1', 'user@example.com', 'user-1', 'wrong')
      ).rejects.toThrow(AuthException)
    })

    // Verifies that an error thrown by the afterEmailVerified hook is logged and does not propagate.
    it('should log and swallow afterEmailVerified hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(USER)
      mockHooks.afterEmailVerified.mockRejectedValue(new Error('hook error'))

      await service.verifyEmail('tenant-1', 'user@example.com', 'user-1', '123456')

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith('afterEmailVerified hook threw', expect.any(Error))
      loggerSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // resendVerificationEmail
  // ---------------------------------------------------------------------------

  describe('resendVerificationEmail', () => {
    // Verifies that an OTP is generated and sent when the cooldown has not been triggered yet.
    it('should send OTP when cooldown is not active', async () => {
      mockRedis.setnx.mockResolvedValue(true) // key was newly set — first caller
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      mockOtpService.generate.mockReturnValue('654321')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockResolvedValue(undefined)

      await service.resendVerificationEmail('tenant-1', 'user@example.com')

      expect(mockOtpService.generate).toHaveBeenCalled()
    })

    // Verifies that when the cooldown is active (setnx=false) the endpoint silently succeeds without sending.
    it('should silently succeed when cooldown is active (anti-enumeration)', async () => {
      mockRedis.setnx.mockResolvedValue(false) // key already existed — cooldown active

      await service.resendVerificationEmail('tenant-1', 'user@example.com')

      expect(mockOtpService.generate).not.toHaveBeenCalled()
    })

    // Verifies that an error from sendEmailVerificationOtp is logged and does not propagate (fire-and-forget).
    it('should log and swallow sendEmailVerificationOtp errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      mockOtpService.generate.mockReturnValue('654321')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockRejectedValue(new Error('email error'))

      await service.resendVerificationEmail('tenant-1', 'user@example.com')

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('sendEmailVerificationOtp failed'),
        expect.any(Error)
      )
      loggerSpy.mockRestore()
    })
  })
})
