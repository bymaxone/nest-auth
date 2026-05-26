/**
 * @fileoverview Tests for AuthService, which orchestrates the full authentication
 * lifecycle including register, login, logout, refresh, email verification, and
 * fire-and-forget hook/side-effect error handling.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Request } from 'express'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { sleep } from '../utils/sleep'
import { AuthService } from './auth.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

// Mock the anti-enumeration sleep so timing-normalization delays are observable and instant.
jest.mock('../utils/sleep', () => ({ sleep: jest.fn().mockResolvedValue(undefined) }))

const mockSleep = sleep as jest.MockedFunction<typeof sleep>

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

const mockSessionService = {
  createSession: jest.fn(),
  revokeSession: jest.fn(),
  rotateSession: jest.fn()
}

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  emailVerification: { required: false, otpTtlSeconds: 600 },
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  bruteForce: { maxAttempts: 5, windowSeconds: 900 },
  sessions: { enabled: false, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
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
        { provide: OtpService, useValue: mockOtpService },
        { provide: SessionService, useValue: mockSessionService }
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

    // Scenario: register with a populated request. Expected: issueTokens receives the request's
    // ip and the 'user-agent' header value. Why: pins the 'user-agent' header name (line 91:42),
    // the ?? coalescing (line 91:30) and the ip pass-through so swaps to '' / wrong header die.
    it('should pass the request ip and user-agent header through to issueTokens', async () => {
      await service.register(dto, mockReq)
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.objectContaining({ id: USER.id }),
        '1.2.3.4',
        'TestBrowser'
      )
    })

    // Scenario: register with sessions.enabled=false (default). Expected: createSession is NOT
    // called. Why: kills the `if (this.options.sessions.enabled)` -> `if (true)` mutant (line 142).
    it('should NOT create a session when sessions are disabled', async () => {
      await service.register(dto, mockReq)
      expect(mockSessionService.createSession).not.toHaveBeenCalled()
    })

    // Scenario: successful register. Expected: an info log carrying the new userId and tenantId.
    // Why: pins the log template (line 146) so blanking it to '' is caught.
    it('should log the registered userId and tenantId on success', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.register(dto, mockReq)
      expect(logSpy).toHaveBeenCalledWith(
        `register: user registered userId=${USER.id} tenantId=tenant-1`
      )
      logSpy.mockRestore()
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
      // role override applied — assert it reached the create payload, killing the
      // `&& { role: augmented['role'] }` -> `&& {}` ObjectLiteral mutant at line 124.
      expect(mockUserRepo.create).toHaveBeenCalledWith(expect.objectContaining({ role: 'viewer' }))
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
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
        ]
      }).compile()

      const svc = module.get(AuthService)
      mockOtpService.generate.mockReturnValue('123456')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockResolvedValue(undefined)

      await svc.register(dto, mockReq)

      expect(mockOtpService.generate).toHaveBeenCalled()
      expect(mockOtpService.store).toHaveBeenCalled()
      // The create payload must force emailVerified=false when verification is required —
      // kills the `? { emailVerified: false }` -> `? {}` (line 127:11) and the
      // `false` -> `true` BooleanLiteral (line 127:28) mutants.
      expect(mockUserRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ emailVerified: false })
      )
      // OTP is stored under the 'email_verification' purpose with the tenant/email HMAC
      // identifier and the configured TTL — kills the store('') (line 516:33), the empty
      // hmac input (line 512:35) and verifies the OTP value is the generated one.
      const expectedIdentifier = hmacSha256(`tenant-1:${dto.email}`, HMAC_KEY)
      expect(mockOtpService.store).toHaveBeenCalledWith(
        'email_verification',
        expectedIdentifier,
        '123456',
        600
      )
    })

    // Verifies that when emailProvider is null, sendVerificationOtp logs a warning and does not attempt to send.
    it('should log warn and skip OTP send when emailProvider is null', async () => {
      const noEmailModule = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, emailVerification: { required: true, otpTtlSeconds: 600 } }
          },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: null },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
        ]
      }).compile()

      const svc = noEmailModule.get(AuthService)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await svc.register(
        {
          email: 'new@example.com',
          password: 'SecureP@ss1',
          name: 'New User',
          tenantId: 'tenant-1'
        },
        mockReq
      )

      expect(warnSpy).toHaveBeenCalledWith(
        'sendVerificationOtp: no email provider configured — OTP not sent'
      )
      expect(mockOtpService.generate).not.toHaveBeenCalled()
      warnSpy.mockRestore()
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
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
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
      // ip and user-agent absent -> both coalesce to '' -> forwarded to issueTokens. This pins
      // the `?? ''` fallbacks (lines 90:26 ip and 91:59 user-agent) so a non-empty replacement dies.
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.objectContaining({ id: USER.id }),
        '',
        ''
      )
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
      // The beforeRegister hook receives the sanitized headers as the 2nd arg. Pin the array
      // join separator to ', ' (line 470:79) and the [k, v] tuple shape (line 470:49): the
      // header must survive as a single comma-joined string, not 'gzipbr' or a dropped key.
      const ctx = mockHooks.beforeRegister.mock.calls[0]?.[1] as {
        sanitizedHeaders: Record<string, string | string[] | undefined>
      }
      expect(ctx.sanitizedHeaders['accept-encoding']).toBe('gzip, br')
    })

    // Verifies that a defined single-value header is preserved verbatim in the hook context.
    it('should preserve a defined single-value header in the hook context', async () => {
      const reqHeader = {
        ip: '1.2.3.4',
        headers: { 'content-type': 'application/json' }
      } as unknown as Request
      await service.register(dto, reqHeader)
      // Kills the `v ?? ''` -> `v && ''` LogicalOperator mutant (line 470:88): a defined string
      // value must pass through unchanged, not collapse to '' via short-circuit.
      const ctx = mockHooks.beforeRegister.mock.calls[0]?.[1] as {
        sanitizedHeaders: Record<string, string | string[] | undefined>
      }
      expect(ctx.sanitizedHeaders['content-type']).toBe('application/json')
    })

    // Verifies that undefined header values are normalized to empty strings in the hook context.
    it('should normalize undefined header values to empty string in the hook context', async () => {
      const reqUndefinedHeader = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'TestBrowser', 'x-custom': undefined }
      } as unknown as Request
      await expect(service.register(dto, reqUndefinedHeader)).resolves.toBeDefined()
      // An undefined header value must coalesce to '' (not "Stryker..."): kills line 470:93.
      const ctx = mockHooks.beforeRegister.mock.calls[0]?.[1] as {
        sanitizedHeaders: Record<string, string | string[] | undefined>
      }
      expect(ctx.sanitizedHeaders['x-custom']).toBe('')
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

    // Scenario: successful login with a populated request. Expected: issueTokens receives the
    // request ip and the 'user-agent' header value, an info log carries userId/tenantId, and
    // createSession is NOT called (sessions disabled). Why: kills the 'user-agent' header name
    // (line 180:42), the ?? coalescing (line 180:30), the success log (line 249) and the
    // `if (sessions.enabled)` -> `if (true)` mutant (line 245).
    it('should forward ip/user-agent to issueTokens, log success, and skip session creation', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.login(dto, mockReq)
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.objectContaining({ id: USER.id }),
        '1.2.3.4',
        'TestBrowser'
      )
      expect(logSpy).toHaveBeenCalledWith(`login: success userId=${USER.id} tenantId=tenant-1`)
      expect(mockSessionService.createSession).not.toHaveBeenCalled()
      logSpy.mockRestore()
    })

    // Scenario: brute-force identifier derivation. Expected: isLockedOut receives the HMAC of
    // '{tenantId}:{email}'. Why: pins the hmac input template (line 185:37) so blanking it dies.
    it('should compute the brute-force identifier from the tenant and email HMAC', async () => {
      await service.login(dto, mockReq)
      const expectedIdentifier = hmacSha256(`tenant-1:${dto.email}`, HMAC_KEY)
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(expectedIdentifier)
    })

    // Verifies that a wrong password records a brute-force failure and throws INVALID_CREDENTIALS.
    it('should throw INVALID_CREDENTIALS on wrong password', async () => {
      mockPasswordService.compare.mockResolvedValue(false)
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      expect(mockBruteForce.recordFailure).toHaveBeenCalled()
    })

    // Scenario: wrong password. Expected: the thrown code is exactly INVALID_CREDENTIALS and a
    // warn log carries the masked email and tenantId. Why: pins the code and the warn template
    // (line 226) so a blanked log message is caught.
    it('should throw exactly INVALID_CREDENTIALS and warn-log the masked email on wrong password', async () => {
      expect.assertions(2)
      mockPasswordService.compare.mockResolvedValue(false)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      try {
        await service.login(dto, mockReq)
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.INVALID_CREDENTIALS })
        })
      }
      expect(warnSpy).toHaveBeenCalledWith(
        `login: invalid credentials email=u***@example.com tenantId=tenant-1`
      )
      warnSpy.mockRestore()
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

    // Scenario: locked account. Expected: thrown AuthException carries
    // details.retryAfterSeconds=543 and a warn log naming the masked email/tenant. Why: kills
    // the `{ retryAfterSeconds: remainingSeconds }` -> `{}` ObjectLiteral mutant (line 191:69)
    // and pins the warn log template (line 189).
    it('should include retryAfterSeconds in the ACCOUNT_LOCKED details and warn-log it', async () => {
      expect.assertions(2)
      mockBruteForce.isLockedOut.mockResolvedValue(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(543)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      try {
        await service.login(dto, mockReq)
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({
            code: AUTH_ERROR_CODES.ACCOUNT_LOCKED,
            details: { retryAfterSeconds: 543 }
          })
        })
      }
      expect(warnSpy).toHaveBeenCalledWith(
        `login: account locked email=u***@example.com tenantId=tenant-1`
      )
      warnSpy.mockRestore()
    })

    // Verifies that a user with a blocked status (e.g. BANNED) throws an AuthException.
    it('should throw when user status is blocked', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, status: 'BANNED' })
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
    })

    // Scenario: BANNED status (an exact codeMap key, lowercased). Expected: thrown code is
    // exactly ACCOUNT_BANNED, not the ACCOUNT_INACTIVE fallback. Why: kills the codeMap -> {}
    // emptying (line 488) and the `.toLowerCase()` -> `.toUpperCase()` lookup mutant (line 497),
    // both of which would force the fallback ACCOUNT_INACTIVE.
    it('should map a BANNED status to exactly ACCOUNT_BANNED via the lowercase codeMap', async () => {
      expect.assertions(1)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, status: 'BANNED' })
      try {
        await service.login(dto, mockReq)
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_BANNED })
        })
      }
    })

    // Verifies that a user with MFA enabled receives an MFA challenge instead of a full auth result.
    it('should return MfaChallengeResult when user has MFA enabled', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, mfaEnabled: true })
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.token')

      const result = await service.login(dto, mockReq)
      expect(result).toMatchObject({ mfaRequired: true, mfaTempToken: 'mfa.temp.token' })
    })

    // Scenario: MFA-enabled user logs in. Expected: an info log carries the userId and tenantId
    // of the issued MFA challenge. Why: pins the log template (line 237) so blanking it is caught.
    it('should log the issued MFA challenge with userId and tenantId', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, mfaEnabled: true })
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.token')
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.login(dto, mockReq)

      expect(logSpy).toHaveBeenCalledWith(
        `login: MFA challenge issued userId=${USER.id} tenantId=tenant-1`
      )
      logSpy.mockRestore()
    })

    // Scenario: emailVerification.required is false (default) but the user is unverified.
    // Expected: login succeeds (no EMAIL_NOT_VERIFIED). Why: kills the `required && !verified`
    // -> `required || !verified` LogicalOperator mutant (line 218); the OR form would throw here.
    it('should allow login for an unverified user when email verification is not required', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      const result = await service.login(dto, mockReq)
      expect(result).toBe(AUTH_RESULT)
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
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
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
      // ip and user-agent absent -> both coalesce to '' -> forwarded to issueTokens. Pins the
      // `?? ''` fallbacks (lines 179:26 ip and 180:59 user-agent) so a non-empty replacement dies.
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.objectContaining({ id: USER.id }),
        '',
        ''
      )
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
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
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
    // Verifies that logout revokes the JWT jti in Redis with the correct key and a positive TTL.
    it('should blacklist the JWT jti and delete the refresh session', async () => {
      const jti = 'some-jti'
      const exp = Math.floor(Date.now() / 1000) + 900
      mockTokenManager.decodeToken.mockReturnValue({ jti, sub: 'user-1', exp })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh', 'user-1')

      expect(mockRedis.set).toHaveBeenCalledWith(`rv:${jti}`, '1', expect.any(Number))
      const ttl = (mockRedis.set.mock.calls[0] as [string, string, number])[2]
      expect(ttl).toBeGreaterThan(800)
      expect(ttl).toBeLessThanOrEqual(900)
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:/))
    })

    // Verifies that redis.set is NOT called when the access token is already expired at logout time.
    it('should skip the revocation redis.set when the token is already expired', async () => {
      mockTokenManager.decodeToken.mockReturnValue({
        jti: 'expired-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) - 10 // expired 10 s ago
      })
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh', 'user-1')

      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:/))
    })

    // Scenario: token whose exp equals "now" exactly, so remainingTtl === 0. Expected: redis.set
    // is NOT called. Why: kills the `remainingTtl > 0` -> `remainingTtl >= 0` EqualityOperator
    // mutant (line 282) — `>= 0` would (wrongly) write a revocation entry with a zero TTL.
    it('should NOT write a revocation entry when remainingTtl is exactly zero', async () => {
      const fixedNowMs = 1_700_000_000_000
      const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(fixedNowMs)
      mockTokenManager.decodeToken.mockReturnValue({
        jti: 'edge-jti',
        sub: 'user-1',
        exp: Math.floor(fixedNowMs / 1000) // remainingTtl = exp - now = 0
      })
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh', 'user-1')

      expect(mockRedis.set).not.toHaveBeenCalled()
      nowSpy.mockRestore()
    })

    // Scenario: any logout. Expected: an info log carrying the userId. Why: pins the log
    // template (line 276) so blanking it to '' is caught.
    it('should log the userId on logout', async () => {
      mockTokenManager.decodeToken.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.logout('access.token', 'raw-refresh', 'user-1')

      expect(logSpy).toHaveBeenCalledWith('logout: userId=user-1')
      logSpy.mockRestore()
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
  // issueTokensForUserId (workspace switch / password-less token issuance)
  // ---------------------------------------------------------------------------

  describe('issueTokensForUserId', () => {
    /*
     * Scenario: target user exists, is ACTIVE, emailVerified, MFA off.
     * Expected: returns AuthResult from TokenManagerService.issueTokens.
     * Protects: the happy path of the v1.0.10 password-less token path used
     * by consumer apps to implement silent workspace switch.
     */
    it('should issue tokens for an active verified user without MFA', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: false })
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockSessionService.createSession.mockResolvedValue(undefined)

      const result = await service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')

      expect(result).toBe(AUTH_RESULT)
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'user-1' }),
        '1.2.3.4',
        'Browser'
      )
    })

    /*
     * Scenario: target userId does not exist.
     * Expected: throws AuthException(TOKEN_INVALID) — same code as getMe to
     * avoid leaking whether the userId is a valid handle or a typo.
     * Protects: user-not-found branch.
     */
    it('should throw TOKEN_INVALID when target user does not exist', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.issueTokensForUserId('ghost', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    /*
     * Scenario: target user is SUSPENDED. The same `assertUserNotBlocked`
     * guard the password-login path uses must fire — otherwise the
     * password-less path becomes a back-door around account holds.
     * Protects: status branch with surfaced ACCOUNT_SUSPENDED.
     */
    it('should throw ACCOUNT_SUSPENDED when target user is suspended', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, status: 'suspended' })

      await expect(service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      try {
        await service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.ACCOUNT_SUSPENDED })
        })
      }
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    /*
     * Scenario: target user has not verified their email AND verification
     * is required globally. The password-login path enforces this gate so
     * the password-less path must mirror it.
     * Protects: EMAIL_NOT_VERIFIED branch.
     */
    it('should throw EMAIL_NOT_VERIFIED when verification is required and user is unverified', async () => {
      // Build a separate service instance with emailVerification.required=true.
      // The default mockOptions has it disabled, so a freshly-issued switch
      // for an unverified user would succeed under defaults — but ANY app
      // that turns verification on must see the gate fire.
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
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
        ]
      }).compile()
      const svc = module.get(AuthService)
      mockUserRepo.findById.mockResolvedValue({ ...USER, emailVerified: false })

      await expect(svc.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      try {
        await svc.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED })
        })
      }
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    /*
     * Scenario: target user has MFA enabled.
     * Expected: throws AuthException(MFA_REQUIRED). The consumer is expected
     * to route through the MFA challenge flow for that user — issuing a
     * full session with `mfaVerified: false` would let the dashboard's
     * MfaRequiredGuard lock the user out on every subsequent request.
     * Protects: MFA branch.
     */
    it('should throw MFA_REQUIRED when target user has MFA enabled', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: true })

      await expect(service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      try {
        await service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')
      } catch (e) {
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_REQUIRED })
        })
      }
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    /*
     * Scenario: sessions are enabled in the resolved options.
     * Expected: a refresh session is tracked via SessionService so the
     * concurrent-session limit applies to switched sessions identically.
     * Protects: the sessions.enabled branch.
     */
    it('should create a tracked session when sessions are enabled', async () => {
      // Default mockOptions has sessions.enabled=false; override so the
      // session-tracking branch fires under test.
      const module = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              ...mockOptions,
              sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
            }
          },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
        ]
      }).compile()
      const svc = module.get(AuthService)
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: false })
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockSessionService.createSession.mockResolvedValue(undefined)

      await svc.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')

      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        'user-1',
        AUTH_RESULT.rawRefreshToken,
        '1.2.3.4',
        'Browser'
      )
    })

    /*
     * Scenario: the configured `afterLogin` hook is invoked on success.
     * Expected: hook fires (fire-and-forget) with the safe user + a minimal
     * HookContext. Mirrors `login()` so consumers cannot tell whether a
     * session was created via password or via switch when wiring audit logs.
     * Protects: hook side-effect branch.
     */
    it('should fire afterLogin hook with the switched safe user', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: false })
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      await service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')
      // Hooks are fire-and-forget — flush microtasks before asserting.
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockHooks.afterLogin).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'user-1' }),
        expect.objectContaining({ userId: 'user-1', ip: '1.2.3.4', userAgent: 'Browser' })
      )
    })

    /*
     * Scenario: `updateLastLogin` rejects (e.g. DB hiccup during switch).
     * Expected: error is caught and logged via the service Logger; the
     * switch caller does NOT see the rejection because the side-effect
     * is fire-and-forget. Mirrors the same guard `login()` ships.
     * Protects: the `.catch()` arm on the updateLastLogin promise.
     */
    it('should log and swallow updateLastLogin errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: false })
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockUserRepo.updateLastLogin.mockRejectedValue(new Error('db error'))

      await service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')
      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith('updateLastLogin failed', expect.any(Error))
      loggerSpy.mockRestore()
    })

    /*
     * Scenario: the `afterLogin` hook rejects.
     * Expected: error is caught + logged; the switch caller does NOT see
     * the rejection. Mirrors the same guard `login()` ships so consumers
     * cannot tell from caller-side whether the session was issued via
     * password or via switch when their hooks fail.
     * Protects: the `.catch()` arm on the afterLogin promise.
     */
    it('should log and swallow afterLogin hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: false })
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockHooks.afterLogin.mockRejectedValue(new Error('hook error'))

      await service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')
      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith('afterLogin hook threw', expect.any(Error))
      loggerSpy.mockRestore()
    })

    /*
     * Scenario: the consumer passed no IAuthHooks implementation (or one
     * without `afterLogin`). The switch path must NOT call any hook and
     * must NOT throw an "afterLogin is not a function" reference error.
     * Protects: the false branch of `if (this.hooks?.afterLogin)` at line
     * 461 of auth.service.ts — exercises both `hooks === null` and the
     * `?.` optional-chain on `afterLogin`.
     */
    it('should skip the afterLogin hook when hooks are unconfigured', async () => {
      // Build a service with hooks === null to hit the false branch.
      const module = await Test.createTestingModule({
        providers: [
          AuthService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
        ]
      }).compile()
      const svc = module.get(AuthService)
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: false })
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      await expect(svc.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')).resolves.toBe(
        AUTH_RESULT
      )
      // Hook mock from the outer scope must not have been called by this
      // freshly-built service (which uses `null` hooks).
      expect(mockHooks.afterLogin).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // verifyEmail
  // ---------------------------------------------------------------------------

  describe('verifyEmail', () => {
    // Verifies that verifyEmail resolves the user from (tenantId, email) and updates the flag.
    it('should verify OTP and update emailVerified for the resolved user', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)
      mockHooks.afterEmailVerified.mockResolvedValue(undefined)

      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.verifyEmail('tenant-1', 'user@example.com', '123456')

      // The OTP identifier must be the exact HMAC of '{tenant}:{email}' — kills the empty
      // hmac input mutant (line 397:35).
      const expectedIdentifier = hmacSha256('tenant-1:user@example.com', HMAC_KEY)
      expect(mockOtpService.verify).toHaveBeenCalledWith(
        'email_verification',
        expectedIdentifier,
        '123456'
      )
      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith('user@example.com', 'tenant-1')
      expect(mockUserRepo.updateEmailVerified).toHaveBeenCalledWith(USER.id, true)
      // Pin the success log template (line 408) so blanking it to '' is caught.
      expect(logSpy).toHaveBeenCalledWith(
        `verifyEmail: email verified userId=${USER.id} tenantId=tenant-1`
      )
      logSpy.mockRestore()
    })

    // Verifies that OTP verification errors from otpService propagate to the caller.
    it('should propagate OTP errors', async () => {
      mockOtpService.verify.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_INVALID))
      await expect(service.verifyEmail('tenant-1', 'user@example.com', 'wrong')).rejects.toThrow(
        AuthException
      )
    })

    // Defends against the ownership-bypass path: valid OTP but user not found → OTP_INVALID.
    it('should throw OTP_INVALID when user does not exist after OTP succeeds', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await expect(service.verifyEmail('tenant-1', 'ghost@example.com', '123456')).rejects.toThrow(
        AuthException
      )
      expect(mockUserRepo.updateEmailVerified).not.toHaveBeenCalled()
    })

    // Verifies that an error thrown by the afterEmailVerified hook is logged and does not propagate.
    it('should log and swallow afterEmailVerified hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)
      mockHooks.afterEmailVerified.mockRejectedValue(new Error('hook error'))

      await service.verifyEmail('tenant-1', 'user@example.com', '123456')

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
      // The cooldown SET NX key must be 'resend:email_verification:' + HMAC('{tenant}:{email}').
      // Kills the whole-key blanking (line 431:25) and the empty hmac input (line 431:65).
      const expectedCooldownKey = `resend:email_verification:${hmacSha256('tenant-1:user@example.com', HMAC_KEY)}`
      expect(mockRedis.setnx).toHaveBeenCalledWith(expectedCooldownKey, 60)
      // The OTP is stored under the 'email_verification' purpose with the matching HMAC identifier
      // (kills the store('') line 516:33 and the empty hmac input line 512:35 on the resend path).
      const expectedIdentifier = hmacSha256('tenant-1:user@example.com', HMAC_KEY)
      expect(mockOtpService.store).toHaveBeenCalledWith(
        'email_verification',
        expectedIdentifier,
        '654321',
        600
      )
    })

    // Verifies that when the cooldown is active (setnx=false) the endpoint silently succeeds without sending.
    it('should silently succeed when cooldown is active (anti-enumeration)', async () => {
      mockRedis.setnx.mockResolvedValue(false) // key already existed — cooldown active

      await service.resendVerificationEmail('tenant-1', 'user@example.com')

      expect(mockOtpService.generate).not.toHaveBeenCalled()
      // The early `return` inside `if (!wasSet)` must short-circuit BEFORE the user lookup —
      // kills the BlockStatement mutant (line 435) that empties the block and would fall through
      // to findByEmail and a potential send.
      expect(mockUserRepo.findByEmail).not.toHaveBeenCalled()
    })

    // ---------------------------------------------------------------------------
    // resendVerificationEmail — anti-enumeration timing normalization
    // ---------------------------------------------------------------------------

    describe('anti-enumeration sleep argument', () => {
      let nowSpy: jest.SpyInstance

      beforeEach(() => {
        // Pin Date.now: the FIRST call is `start`, every later call is 50 ms after (elapsed=50,
        // < 300 ms ANTI_ENUM_MIN_MS). Original Math.max(0, 300 - 50) = 250; Math.min(0, 250) = 0;
        // (300 + 50) = 350; (300 - (now + start)) -> huge-negative -> 0. Asserting exactly 250
        // kills every Math.min/-/+ mutant on both sleep call sites (lines 436 and 445).
        // mockReturnValueOnce pins only `start`; extra Date.now calls stay at start+50.
        nowSpy = jest.spyOn(Date, 'now')
        nowSpy.mockReturnValue(1_000_050)
        nowSpy.mockReturnValueOnce(1_000_000)
      })

      afterEach(() => {
        nowSpy.mockRestore()
      })

      // Scenario: cooldown active path. Expected: sleep(250). Why: pins the normalization delay
      // on the early-return branch (line 436).
      it('should sleep the remaining anti-enumeration delay when cooldown is active', async () => {
        mockRedis.setnx.mockResolvedValue(false)
        await service.resendVerificationEmail('tenant-1', 'user@example.com')
        expect(mockSleep).toHaveBeenCalledWith(250)
      })

      // Scenario: cooldown not active path. Expected: sleep(250). Why: pins the normalization
      // delay on the post-send branch (line 445).
      it('should sleep the remaining anti-enumeration delay after sending', async () => {
        mockRedis.setnx.mockResolvedValue(true)
        mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
        mockOtpService.generate.mockReturnValue('654321')
        mockOtpService.store.mockResolvedValue(undefined)
        mockEmailProvider.sendEmailVerificationOtp.mockResolvedValue(undefined)
        await service.resendVerificationEmail('tenant-1', 'user@example.com')
        expect(mockSleep).toHaveBeenCalledWith(250)
      })
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

  // ---------------------------------------------------------------------------
  // Session integration (sessions.enabled: true)
  // ---------------------------------------------------------------------------

  describe('session integration (sessions.enabled: true)', () => {
    let sessionEnabledService: AuthService

    const sessionOptions = {
      ...mockOptions,
      sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' as const }
    }

    beforeEach(async () => {
      const module = await Test.createTestingModule({
        providers: [
          AuthService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: sessionOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
        ]
      }).compile()

      sessionEnabledService = module.get(AuthService)
    })

    // Verifies that register calls sessionService.createSession with the user id and raw refresh token when sessions are enabled.
    it('register: calls sessionService.createSession after issuing tokens', async () => {
      // Arrange
      mockHooks.beforeRegister.mockResolvedValue({ allowed: true })
      mockUserRepo.findByEmail.mockResolvedValue(null)
      mockPasswordService.hash.mockResolvedValue('scrypt:salt:hash')
      mockUserRepo.create.mockResolvedValue(USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockHooks.afterRegister.mockResolvedValue(undefined)
      mockSessionService.createSession.mockResolvedValue(undefined)

      // Act
      await sessionEnabledService.register(
        { email: 'new@example.com', password: 'Pass1!', name: 'New', tenantId: 'tenant-1' },
        mockReq
      )

      // Assert
      expect(mockSessionService.createSession).toHaveBeenCalledTimes(1)
      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        USER.id,
        AUTH_RESULT.rawRefreshToken,
        expect.any(String),
        expect.any(String)
      )
    })

    // Verifies that login calls sessionService.createSession with the user id and raw refresh token when sessions are enabled.
    it('login: calls sessionService.createSession after issuing tokens', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockBruteForce.isLockedOut.mockResolvedValue(false)
      mockPasswordService.compare.mockResolvedValue(true)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockHooks.beforeLogin.mockResolvedValue({ allowed: true })
      mockHooks.afterLogin.mockResolvedValue(undefined)
      mockSessionService.createSession.mockResolvedValue(undefined)

      // Act
      await sessionEnabledService.login(
        { email: USER.email, password: 'Pass1!', tenantId: USER.tenantId },
        mockReq
      )

      // Assert
      expect(mockSessionService.createSession).toHaveBeenCalledTimes(1)
      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        USER.id,
        AUTH_RESULT.rawRefreshToken,
        expect.any(String),
        expect.any(String)
      )
    })

    // Verifies that logout calls sessionService.revokeSession with the user id and the sha256 hash of the refresh token.
    it('logout: calls sessionService.revokeSession for the session hash', async () => {
      // Arrange
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      mockTokenManager.decodeToken.mockReturnValue({ jti: 'jti1', exp: 9_999_999_999 })
      mockSessionService.revokeSession.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      // Act
      await sessionEnabledService.logout('access.jwt', 'raw-refresh-token', USER.id)

      // Assert
      expect(mockSessionService.revokeSession).toHaveBeenCalledTimes(1)
      expect(mockSessionService.revokeSession).toHaveBeenCalledWith(
        USER.id,
        expect.stringMatching(/^[a-f0-9]{64}$/)
      )
    })

    // Verifies that logout completes without throwing when revokeSession rejects with SESSION_NOT_FOUND.
    it('logout: swallows SESSION_NOT_FOUND from sessionService.revokeSession', async () => {
      // Arrange
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      mockTokenManager.decodeToken.mockReturnValue({ jti: 'jti2', exp: 9_999_999_999 })
      mockSessionService.revokeSession.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
      )
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Act & Assert
      await expect(
        sessionEnabledService.logout('access.jwt', 'raw-refresh-token', USER.id)
      ).resolves.not.toThrow()

      // SESSION_NOT_FOUND must be swallowed silently — the cleanup-failed warning must NOT fire.
      // Kills the `if (errCode !== SESSION_NOT_FOUND)` -> `if (true)` ConditionalExpression
      // mutant (line 305), which would warn for the SESSION_NOT_FOUND case too.
      expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('session cleanup failed'))
      warnSpy.mockRestore()
    })

    // Verifies that logout logs a warning when revokeSession rejects with any error code other than SESSION_NOT_FOUND.
    it('logout: logs warn for non-SESSION_NOT_FOUND errors from sessionService.revokeSession', async () => {
      // Arrange
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      mockTokenManager.decodeToken.mockReturnValue({ jti: 'jti3', exp: 9_999_999_999 })
      const otherError = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      mockSessionService.revokeSession.mockRejectedValue(otherError)
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Act
      await sessionEnabledService.logout('access.jwt', 'raw-refresh-token', USER.id)

      // Assert — warning is logged but logout still completes without throwing
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('session cleanup failed'))
      warnSpy.mockRestore()
    })

    // Verifies that a non-AuthException rejection from revokeSession triggers the warn path just like an unknown-code AuthException.
    it('logout: logs warn when revokeSession rejects with a non-AuthException error', async () => {
      // Arrange — plain Error covers the `err instanceof AuthException` false branch
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      mockTokenManager.decodeToken.mockReturnValue({ jti: 'jti4', exp: 9_999_999_999 })
      mockSessionService.revokeSession.mockRejectedValue(new Error('unexpected redis failure'))
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Act
      await sessionEnabledService.logout('access.jwt', 'raw-refresh-token', USER.id)

      // Assert — warning is logged for any non-SESSION_NOT_FOUND rejection
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('session cleanup failed'))
      warnSpy.mockRestore()
    })

    // Verifies that refresh calls sessionService.rotateSession with the sha256 hashes of the old and new tokens.
    it('refresh: calls sessionService.rotateSession as fire-and-forget', async () => {
      // Arrange
      const rotatedResult = {
        session: { userId: USER.id, tenantId: USER.tenantId, role: USER.role },
        accessToken: 'new.access.jwt',
        rawRefreshToken: 'new-raw-refresh'
      }
      mockTokenManager.reissueTokens.mockResolvedValue(rotatedResult)
      mockSessionService.rotateSession.mockResolvedValue(undefined)

      // Act
      await sessionEnabledService.refresh('old-raw-refresh', '1.2.3.4', 'TestBrowser')

      // Allow fire-and-forget to settle
      await new Promise((r) => setImmediate(r))

      // Assert
      expect(mockSessionService.rotateSession).toHaveBeenCalledTimes(1)
      expect(mockSessionService.rotateSession).toHaveBeenCalledWith(
        expect.stringMatching(/^[a-f0-9]{64}$/), // sha256 of old token
        expect.stringMatching(/^[a-f0-9]{64}$/), // sha256 of new token
        '1.2.3.4',
        'TestBrowser'
      )
    })

    // Verifies that refresh completes without throwing when rotateSession fails because session rotation is fire-and-forget.
    it('refresh: does NOT throw when rotateSession fails (fire-and-forget)', async () => {
      // Arrange
      const rotatedResult = {
        session: { userId: USER.id, tenantId: USER.tenantId, role: USER.role },
        accessToken: 'new.access.jwt',
        rawRefreshToken: 'new-raw-refresh'
      }
      mockTokenManager.reissueTokens.mockResolvedValue(rotatedResult)
      mockSessionService.rotateSession.mockRejectedValue(new Error('Redis timeout'))
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Act & Assert — refresh should not throw even if session rotation fails
      await expect(
        sessionEnabledService.refresh('old-raw-refresh', '1.2.3.4', 'TestBrowser')
      ).resolves.not.toThrow()

      await new Promise((r) => setImmediate(r))
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('session detail rotation failed')
      )
      warnSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // Null hooks (@Optional() BYMAX_AUTH_HOOKS resolves to null)
  // ---------------------------------------------------------------------------

  describe('with null hooks (BYMAX_AUTH_HOOKS absent)', () => {
    let noHooksService: AuthService

    beforeEach(async () => {
      jest.clearAllMocks()

      const module = await Test.createTestingModule({
        providers: [
          AuthService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: BruteForceService, useValue: mockBruteForce },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: OtpService, useValue: mockOtpService },
          { provide: SessionService, useValue: mockSessionService }
        ]
      }).compile()

      noHooksService = module.get(AuthService)
    })

    // Scenario: register when no hooks are registered. Expected: registration succeeds without
    // invoking any hook. Why: covers the `this.hooks?.beforeRegister` / `?.afterRegister`
    // optional-chaining short-circuit branches (lines 95 and 150) where `this.hooks` is null.
    it('should register without invoking before/after hooks when hooks is null', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null)
      mockPasswordService.hash.mockResolvedValue('scrypt:salt:hash')
      mockUserRepo.create.mockResolvedValue(USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      const result = await noHooksService.register(
        {
          email: 'new@example.com',
          password: 'SecureP@ss1',
          name: 'New User',
          tenantId: 'tenant-1'
        },
        mockReq
      )

      expect(result).toBe(AUTH_RESULT)
      expect(mockHooks.beforeRegister).not.toHaveBeenCalled()
      expect(mockHooks.afterRegister).not.toHaveBeenCalled()
    })

    // Scenario: login when no hooks are registered. Expected: login succeeds without invoking any
    // hook. Why: covers the `this.hooks?.beforeLogin` / `?.afterLogin` short-circuit branches
    // (lines 199 and 256) where `this.hooks` is null.
    it('should login without invoking before/after hooks when hooks is null', async () => {
      mockBruteForce.isLockedOut.mockResolvedValue(false)
      mockBruteForce.resetFailures.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockPasswordService.compare.mockResolvedValue(true)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined)

      const result = await noHooksService.login(
        { email: 'user@example.com', password: 'correct', tenantId: 'tenant-1' },
        mockReq
      )

      expect(result).toBe(AUTH_RESULT)
      expect(mockHooks.beforeLogin).not.toHaveBeenCalled()
      expect(mockHooks.afterLogin).not.toHaveBeenCalled()
    })

    // Scenario: logout when no hooks are registered. Expected: logout completes without invoking
    // the afterLogout hook. Why: covers the `this.hooks?.afterLogout` short-circuit branch
    // (line 312) where `this.hooks` is null.
    it('should logout without invoking the afterLogout hook when hooks is null', async () => {
      mockTokenManager.decodeToken.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await expect(
        noHooksService.logout('access.token', 'raw-refresh', 'user-1')
      ).resolves.toBeUndefined()
      expect(mockHooks.afterLogout).not.toHaveBeenCalled()
    })

    // Scenario: verifyEmail when no hooks are registered. Expected: verification completes without
    // invoking the afterEmailVerified hook. Why: covers the `this.hooks?.afterEmailVerified`
    // short-circuit branch (line 411) where `this.hooks` is null.
    it('should verify email without invoking the afterEmailVerified hook when hooks is null', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)

      await expect(
        noHooksService.verifyEmail('tenant-1', 'user@example.com', '123456')
      ).resolves.toBeUndefined()
      expect(mockHooks.afterEmailVerified).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // resendVerificationEmail — user-existence/verification branch (line 442)
  // ---------------------------------------------------------------------------

  describe('resendVerificationEmail user branch', () => {
    // Scenario: cooldown free but the email maps to no user. Expected: no OTP is sent. Why: covers
    // the left-operand-false branch of `if (user && !user.emailVerified)` (line 442) — a null user
    // must short-circuit before sendVerificationOtp.
    it('should not send an OTP when no user matches the email', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await service.resendVerificationEmail('tenant-1', 'ghost@example.com')

      expect(mockOtpService.generate).not.toHaveBeenCalled()
    })

    // Scenario: cooldown free and the user exists but is already verified. Expected: no OTP is
    // sent. Why: covers the right-operand-false branch of `if (user && !user.emailVerified)`
    // (line 442) — an already-verified user must not receive a new verification OTP.
    it('should not send an OTP when the user is already verified', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: true })

      await service.resendVerificationEmail('tenant-1', 'user@example.com')

      expect(mockOtpService.generate).not.toHaveBeenCalled()
    })
  })
})
