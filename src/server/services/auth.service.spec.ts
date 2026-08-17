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
import { hmacSha256, sha256 } from '../crypto/secure-token'
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
  updateEmailVerified: jest.fn(),
  updatePassword: jest.fn()
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
  afterEmailVerified: jest.fn(),
  onLoginFailed: jest.fn(),
  onLockout: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn(),
  compare: jest.fn(),
  compareDummy: jest.fn().mockResolvedValue(false),
  assertNotCompromised: jest.fn().mockResolvedValue(undefined),
  assertAcceptable: jest.fn().mockResolvedValue(undefined),
  assertLongEnough: jest.fn(),
  needsRehash: jest.fn().mockReturnValue(false)
}

const mockTokenManager = {
  issueTokens: jest.fn(),
  issueMfaTempToken: jest.fn(),
  reissueTokens: jest.fn(),
  verifyIgnoringExpiry: jest.fn(),
  issueAccess: jest.fn()
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
  setnx: jest.fn(),
  readSessionOwner: jest.fn(),
  invalidateUserSessions: jest.fn(),
  bumpUserTokenEpoch: jest.fn(),
  getUserTokenEpoch: jest.fn()
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
  previousHmacKeys: [],
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

/** The wire code carried by a thrown `AuthException`. */
function getErrorCode(err: unknown): string {
  if (!(err instanceof AuthException)) throw new Error(`not an AuthException: ${String(err)}`)
  return (err.getResponse() as { error: { code: string } }).error.code
}

describe('AuthService', () => {
  /**
   * An `AuthService` over the same collaborators but different resolved options, for the
   * cases where the behaviour under test IS the option.
   */
  async function buildServiceWith(options: unknown): Promise<AuthService> {
    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: options },
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
    return module.get(AuthService)
  }

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
      // The FIELD NAME, not just that the screen ran. It is what the policy failure names in
      // its `details`, so the whole reason the argument exists is to point the caller at the
      // input they actually sent — and registration sends `password`, not `newPassword`.
      // Without pinning it here, a call site could pass anything and the suite would agree.
      expect(mockPasswordService.assertAcceptable).toHaveBeenCalledWith(dto.password, 'password')
    })

    // Verifies the email is canonicalized at the service boundary (not only via the DTO
    // @Transform, which the non-transforming ValidationPipe discards): a mixed-case,
    // padded email is looked up and stored lowercased/trimmed, so the stored identity
    // matches every email-keyed control.
    it('should normalize the email before lookup and persistence', async () => {
      await service.register({ ...dto, email: '  New.USER@Example.COM  ' }, mockReq)
      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith('new.user@example.com', 'tenant-1')
      expect(mockUserRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ email: 'new.user@example.com' })
      )
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

    // Scenario: verification is not required and the hook returns no `emailVerified` at all.
    // Expected: the key is ABSENT from what reaches the repository — not present holding
    // `undefined`. Why: the spread is guarded on the value being a boolean precisely so a hook
    // that says nothing leaves the decision to the repository's own default. Sending the key with
    // `undefined` overrides that default in most persistence layers, writing NULL or false over
    // whatever the column was meant to be — and this is the account-creation path, so the account
    // starts life in a state nobody chose.
    it('omits emailVerified entirely when the hook does not decide it', async () => {
      mockHooks.beforeRegister.mockResolvedValue({ allowed: true })

      await service.register(dto, mockReq)

      const created = mockUserRepo.create.mock.calls[0]?.[0] as Record<string, unknown>
      expect(Object.hasOwn(created, 'emailVerified')).toBe(false)
    })

    // …and honours it when the hook does decide, so the guard is not just "always omit".
    it('carries emailVerified through when the hook decides it', async () => {
      mockHooks.beforeRegister.mockResolvedValue({
        allowed: true,
        modifiedData: { emailVerified: true }
      })

      await service.register(dto, mockReq)

      expect(mockUserRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ emailVerified: true })
      )
    })

    // A non-boolean is not a decision. The guard is a type check rather than a presence check
    // because `modifiedData` crosses an interface the host application implements, so the value
    // arrives as whatever that code put there — and a truthy string would otherwise be written
    // into a boolean column as the host's idea of "verified".
    it('ignores a non-boolean emailVerified from the hook', async () => {
      mockHooks.beforeRegister.mockResolvedValue({
        allowed: true,
        modifiedData: { emailVerified: 'yes' }
      })

      await service.register(dto, mockReq)

      const created = mockUserRepo.create.mock.calls[0]?.[0] as Record<string, unknown>
      expect(Object.hasOwn(created, 'emailVerified')).toBe(false)
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
      // `&& { role: hookOverrides.role }` -> `&& {}` ObjectLiteral mutant.
      expect(mockUserRepo.create).toHaveBeenCalledWith(expect.objectContaining({ role: 'viewer' }))
    })

    // The mirror image, and the one that is a privilege boundary rather than a feature: the
    // SAME fields arriving from the CALLER must not reach `create`.
    //
    // They used to. The hook's overrides were merged into `dto` and then read back off it, so a
    // `role` the hook chose and a `role` the caller sent were the same value by the time it was
    // read. Through the shipped controller that was unreachable — the validation pipe sets
    // `whitelist` and `forbidNonWhitelisted`, so an extra body field is a 400 — but `AuthService`
    // is exported precisely so a host can write its own registration route, and the moment one
    // calls `register(req.body, req)` the only thing between an unauthenticated caller and
    // `role: 'ADMIN'` was a decorator in a different file that the host is free not to use.
    it('should ignore role, status and emailVerified supplied by the caller', async () => {
      mockHooks.beforeRegister.mockResolvedValue({ allowed: true })

      await service.register(
        { ...dto, role: 'ADMIN', status: 'ACTIVE', emailVerified: true } as typeof dto,
        mockReq
      )

      const payload = mockUserRepo.create.mock.calls.at(-1)?.[0] as Record<string, unknown>
      expect(payload['role']).toBeUndefined()
      expect(payload['status']).toBeUndefined()
      expect(payload['emailVerified']).toBeUndefined()
    })

    // And the two must not be confusable in the other direction either: a hook that sets nothing
    // cannot have its silence filled in by the caller's body.
    it('should ignore a caller-supplied role even when the hook overrides a different field', async () => {
      mockHooks.beforeRegister.mockResolvedValue({
        allowed: true,
        modifiedData: { status: 'pending_approval' }
      })

      await service.register({ ...dto, role: 'ADMIN' } as typeof dto, mockReq)

      const payload = mockUserRepo.create.mock.calls.at(-1)?.[0] as Record<string, unknown>
      expect(payload['status']).toBe('pending_approval')
      expect(payload['role']).toBeUndefined()
    })

    // The mirror of the case below, and the one that pins the FLAG rather than the send. Without
    // it, a build that ignored `emailVerification.required` and always sent would pass every other
    // register test — the default fixture has it off, so nothing else looks at the negative side.
    // It used to die by accident instead: the send was `provider.send(...).catch(...)`, and a mock
    // returning a non-promise made `.catch` throw. Moving the call inside an async IIFE's `try`
    // made the code tolerant of that, which removed the accidental kill and left the rule
    // unasserted — so the rule needed asserting on purpose.
    it('sends no verification OTP when emailVerification.required is false', async () => {
      await service.register(dto, mockReq)
      await new Promise((r) => setImmediate(r))

      expect(mockEmailProvider.sendEmailVerificationOtp).not.toHaveBeenCalled()
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

      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('afterRegister hook threw: '))
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

      // The body must stay silent: naming a tenant under a configured resolver is refused, and
      // the assertion below is about which tenant scopes the lookup, not about that refusal.
      // The key is omitted rather than set to `undefined`, which `exactOptionalPropertyTypes`
      // refuses — and rightly, since "absent" and "present but undefined" are different requests.
      const { tenantId: _named, ...bodyWithoutTenant } = dto
      await svc.register(bodyWithoutTenant, mockReq)

      // The resolved tenantId from the resolver ('resolved-tenant') should be used in findByEmail.
      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith(dto.email, 'resolved-tenant')
    })

    // Verifies the refusal itself on the flow the audit found it on. A caller that named a tenant
    // which a configured resolver would not honour used to get `201`, with the account created
    // elsewhere — the caller's belief and the server's state diverging on the tenancy boundary,
    // silently.
    it('should refuse a body-named tenant on register when a resolver is configured', async () => {
      const tenantResolverModule = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, tenantIdResolver: () => 'resolved-tenant' }
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

      const svc = tenantResolverModule.get<AuthService>(AuthService)
      mockUserRepo.create.mockClear()

      await expect(svc.register(dto, mockReq)).rejects.toBeInstanceOf(AuthException)

      // Refused before the account exists, so the divergence the audit reported cannot occur.
      expect(mockUserRepo.create).not.toHaveBeenCalled()
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

    // The lookup passes `tenantId` and the repository contract says to scope by it — but the
    // repository is the host's and an interface can only ask. A single-tenant host writing
    // `findByEmail(email)` that ignores its second argument is the shape nobody notices, and
    // under one every distinct `tenantId` in the body resolves the same account while deriving
    // a DIFFERENT `lf:` counter. Rotating the field then hands the attacker an unlimited supply
    // of fresh five-attempt budgets and the lockout never engages. Refusing the mismatch is
    // also tenant isolation in its own right: an account in tenant A must not authenticate
    // through a request naming tenant B, whatever the repository returns.
    it('refuses an account the repository returned from another tenant', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, tenantId: 'someone-elses-tenant' })

      await expect(service.login(dto, mockReq)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })
      // Refused on the not-found path: same generic code, and the password is never compared,
      // so nothing distinguishes the three refusals to a caller.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
      expect(mockPasswordService.compareDummy).toHaveBeenCalled()
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    // The warning names a permanent property of the deployment — a repository ignoring its
    // `tenantId` argument — so every line after the first carries nothing new. Repeating it per
    // request would make the log a function of traffic and put a per-request side effect on one
    // of three branches whose whole purpose is to be indistinguishable from each other.
    it('reports the misconfigured repository once, not once per attempt', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, tenantId: 'someone-elses-tenant' })
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)

      const mismatchWarnings = warnSpy.mock.calls.filter(([line]) =>
        String(line).includes('outside the requested tenant')
      )
      expect(mismatchWarnings).toHaveLength(1)
      // The line has to name what is actually wrong, which is the repository's own contract — not
      // the request. The symptom is "logins fail for a valid password"; the cause is a
      // `findByEmail` that ignores the argument it was given. Without the second clause the
      // operator is told a tenant mismatch happened and left to guess where.
      expect(String(mismatchWarnings[0]?.[0])).toContain(
        'IUserRepository.findByEmail scopes by its tenantId argument'
      )
      warnSpy.mockRestore()
    })

    // Every other hook fires on a success path, which left the failure side of authentication
    // with no structured seam: the events that matter most to detection existed only as
    // English log lines whose wording is not a contract. ASVS v5 §16.3.1 expects the outcome
    // of every authentication operation to be logged, and §6.1.1 an *adaptive* response, which
    // needs a signal to adapt to.
    it('emits onLoginFailed for an unknown address, with no userId', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await Promise.resolve()

      expect(mockHooks.onLoginFailed).toHaveBeenCalledWith(
        // No `userId`: the account does not exist, which is exactly the credential-stuffing
        // signal a consumer wants — and the thing the uniform response deliberately hides
        // from the caller but not from the hook.
        expect.objectContaining({
          email: dto.email,
          tenantId: 'tenant-1',
          reason: 'invalid_credentials'
        }),
        expect.anything()
      )
      expect(mockHooks.onLoginFailed.mock.calls[0]?.[0]).not.toHaveProperty('userId')
    })

    // A wrong password against a real account carries the id, which is what separates "someone
    // is guessing at this account" from "someone is spraying addresses".
    it('emits onLoginFailed with the userId when the password is wrong', async () => {
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await Promise.resolve()

      expect(mockHooks.onLoginFailed).toHaveBeenCalledWith(
        expect.objectContaining({ userId: USER.id, reason: 'invalid_credentials' }),
        expect.anything()
      )
    })

    // The blocked and unverified refusals are distinct reasons: a consumer counting
    // credential-stuffing attempts must not have them inflated by an account that simply has
    // not finished onboarding.
    it('emits onLoginFailed with reason account_blocked', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, status: 'banned' })

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await Promise.resolve()

      expect(mockHooks.onLoginFailed).toHaveBeenCalledWith(
        expect.objectContaining({ reason: 'account_blocked', userId: USER.id }),
        expect.anything()
      )
    })

    it('emits onLoginFailed with reason email_not_verified', async () => {
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
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })

      await expect(module.get(AuthService).login(dto, mockReq)).rejects.toThrow(AuthException)
      await Promise.resolve()

      expect(mockHooks.onLoginFailed).toHaveBeenCalledWith(
        expect.objectContaining({ reason: 'email_not_verified', userId: USER.id }),
        expect.anything()
      )
    })

    // The lockout signal has to fire on the attempt that CROSSES the threshold, not on the next
    // one: an attacker who trips the lock and walks away would otherwise never produce the
    // event, and the account would sit locked with nothing having announced it.
    it('emits onLockout on the attempt that crosses the threshold', async () => {
      mockPasswordService.compare.mockResolvedValue(false)
      // Not locked on entry, locked once the failure is recorded.
      mockBruteForce.isLockedOut.mockResolvedValueOnce(false).mockResolvedValueOnce(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(900)

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await Promise.resolve()

      expect(mockHooks.onLockout).toHaveBeenCalledWith(
        expect.objectContaining({ email: dto.email, retryAfterSeconds: 900 }),
        expect.anything()
      )
    })

    // The enumeration oracle this ordering exists to close. A blocked or unverified account
    // must be indistinguishable from a non-existent one to anyone who does NOT hold the
    // password — same code, same status, and the failure counter advances so probing is
    // bounded by the lockout rather than only by the per-IP limit.
    it.each([
      ['blocked', { ...USER, status: 'suspended' }],
      ['unverified', { ...USER, emailVerified: false }]
    ])(
      'answers a wrong password on a %s account like any other wrong password',
      async (_label, account) => {
        const strict = await buildServiceWith({
          ...mockOptions,
          emailVerification: { required: true, otpTtlSeconds: 600 }
        })
        mockUserRepo.findByEmail.mockResolvedValue(account)
        mockPasswordService.compare.mockResolvedValue(false)

        const err = await strict.login(dto, mockReq).catch((e: unknown) => e)

        expect(err).toBeInstanceOf(AuthException)
        expect(getErrorCode(err)).toBe(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
        // …and the attempt counted, which is what stops unlimited probing of those states.
        expect(mockBruteForce.recordFailure).toHaveBeenCalled()
      }
    )

    // The other half: the holder of the credential IS told why, because the flow is useless
    // otherwise — a user whose address is unverified has to learn to check their inbox.
    it('tells the password holder that the address is unverified', async () => {
      const strict = await buildServiceWith({
        ...mockOptions,
        emailVerification: { required: true, otpTtlSeconds: 600 }
      })
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      mockPasswordService.compare.mockResolvedValue(true)

      const err = await strict.login(dto, mockReq).catch((e: unknown) => e)

      expect(getErrorCode(err)).toBe(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    })

    it('tells the password holder that the account is blocked', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, status: 'suspended' })
      mockPasswordService.compare.mockResolvedValue(true)

      const err = await service.login(dto, mockReq).catch((e: unknown) => e)

      expect(getErrorCode(err)).toBe(AUTH_ERROR_CODES.ACCOUNT_SUSPENDED)
    })

    // …and the other half of "on the attempt that crosses it": a failure that does NOT cross
    // the threshold announces nothing. Without this, a hook firing on every wrong password
    // reads exactly like one firing at the lockout, and a consumer paging on the event would
    // be paged by every typo.
    it('stays silent on a failure that does not cross the threshold', async () => {
      mockPasswordService.compare.mockResolvedValue(false)
      // Not locked on entry, and still not locked once the failure is recorded.
      mockBruteForce.isLockedOut.mockResolvedValue(false)

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await Promise.resolve()

      expect(mockHooks.onLockout).not.toHaveBeenCalled()
      // …while the failure itself is still reported, so the silence is about the lockout and
      // not about the attempt.
      expect(mockHooks.onLoginFailed).toHaveBeenCalled()
    })

    // The lockout hook is fire-and-forget in both failure shapes, like every other. The
    // synchronous throw is the one a consumer writing a non-async body produces.
    it.each([
      [
        'throws synchronously',
        () => {
          throw new Error('siem down')
        }
      ],
      ['rejects', () => Promise.reject(new Error('siem down'))]
    ])('still locks out when the onLockout hook %s', async (_label, impl) => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockPasswordService.compare.mockResolvedValue(false)
      mockBruteForce.isLockedOut.mockResolvedValueOnce(false).mockResolvedValueOnce(true)
      mockBruteForce.getRemainingLockoutSeconds.mockResolvedValue(900)
      mockHooks.onLockout.mockImplementation(impl)

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      await Promise.resolve()
      await Promise.resolve()

      // The hook name reaches the log, which is the only thing that tells an operator WHICH
      // hook is down when several are wired.
      expect(errorSpy.mock.calls.map((call) => String(call[0])).join(' ')).toContain('onLockout')
      errorSpy.mockRestore()
    })

    // The same for a hook that REJECTS rather than throwing. Both arms matter: a consumer
    // writing `async onLoginFailed()` produces the rejection, one writing a synchronous body
    // produces the throw, and neither may reach the caller.
    it('still refuses when the onLoginFailed hook rejects, and logs it', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)
      mockHooks.onLoginFailed.mockRejectedValue(new Error('siem unreachable'))

      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      // Let the rejection settle so the handler runs before the assertion.
      await Promise.resolve()
      await Promise.resolve()

      expect(errorSpy.mock.calls.map((call) => String(call[0])).join(' ')).toContain(
        'onLoginFailed hook threw'
      )
      errorSpy.mockRestore()
    })

    // A hook that throws must not change the answer the caller gets — the refusal is still a
    // refusal, and a consumer's SIEM being down is not an authentication decision.
    it('still refuses when the onLoginFailed hook throws', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null)
      mockHooks.onLoginFailed.mockImplementation(() => {
        throw new Error('siem down')
      })

      await expect(service.login(dto, mockReq)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_CREDENTIALS } }
      })
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
      const expectedIdentifier = hmacSha256(`dashboard:tenant-1:${dto.email}`, HMAC_KEY)
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(expectedIdentifier)
    })

    // Verifies the case-rotation lockout bypass is closed at the service layer: a
    // mixed-case, padded email yields the SAME brute-force HMAC and user lookup as the
    // canonical lowercase form, so an attacker cannot rotate casing to get a fresh
    // lockout bucket. This holds independently of the DTO @Transform (which the
    // non-transforming ValidationPipe discards).
    // The plane collision. A tenant whose id is literally `platform` used to produce a
    // byte-identical lockout identifier to the platform plane's own `platform:{email}`, so
    // five unauthenticated dashboard logins locked an operator out of the console — and a
    // successful one cleared their lockout mid-attack. `tenantId` comes from the request body
    // whenever no resolver is configured, which is the default, so it was attacker-chosen.
    it('never derives the platform plane key, even for a tenant named platform', async () => {
      const platformKey = hmacSha256(`platform:${dto.email}`, HMAC_KEY)
      mockPasswordService.compare.mockResolvedValue(false)

      await expect(service.login({ ...dto, tenantId: 'platform' }, mockReq)).rejects.toThrow(
        AuthException
      )

      const touched = [
        ...mockBruteForce.isLockedOut.mock.calls,
        ...mockBruteForce.recordFailure.mock.calls,
        ...mockBruteForce.resetFailures.mock.calls
      ].map((call) => call[0] as string)
      expect(touched.length).toBeGreaterThan(0)
      expect(touched).not.toContain(platformKey)
    })

    it('should derive the brute-force key and lookup from the normalized email', async () => {
      await service.login({ ...dto, email: '  USER@Example.COM  ' }, mockReq)
      const canonicalIdentifier = hmacSha256('dashboard:tenant-1:user@example.com', HMAC_KEY)
      expect(mockBruteForce.isLockedOut).toHaveBeenCalledWith(canonicalIdentifier)
      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith('user@example.com', 'tenant-1')
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

    // Verifies the timing-oracle defense: the "user not found" branch runs a decoy
    // scrypt derivation so an unknown e-mail takes the same time as a wrong password,
    // preventing account enumeration by response latency.
    it('should run a dummy password compare when user not found (timing defense)', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(null)
      await expect(service.login(dto, mockReq)).rejects.toThrow(AuthException)
      expect(mockPasswordService.compareDummy).toHaveBeenCalledWith(dto.password)
      // The real compare must NOT run — there is no stored hash to compare against.
      expect(mockPasswordService.compare).not.toHaveBeenCalled()
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

      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('updateLastLogin failed: '))
      loggerSpy.mockRestore()
    })

    // The redaction list on that line is the only reason it names a value, so something has to
    // prove it removes one. A repository quoting the parameter it failed on is the ordinary shape
    // — an ORM error routinely carries the failing query's arguments — and `user.id` is the single
    // value this call passed it, which is what makes naming it a claim this site can honestly
    // make. Without this the list was unobservable: emptying it changed no assertion.
    it('removes the id it handed the repository from an error that quotes it', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockUserRepo.updateLastLogin.mockRejectedValue(
        new Error(`UPDATE users SET last_login WHERE id = '${USER.id}' failed`)
      )

      await service.login(dto, mockReq)
      await new Promise((r) => setImmediate(r))

      const logged = String(loggerSpy.mock.calls.at(-1)?.[0])
      expect(logged).toContain('updateLastLogin failed: ')
      expect(logged).not.toContain(USER.id)
      loggerSpy.mockRestore()
    })

    // Verifies that an error thrown by the afterLogin hook is logged and does not propagate (fire-and-forget).
    it('should log and swallow afterLogin hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockHooks.afterLogin.mockRejectedValue(new Error('hook error'))

      await service.login(dto, mockReq)

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('afterLogin hook threw: '))
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
    beforeEach(() => {
      // The stored session names its owner — logout reads it from there rather than from the
      // access token's claims, so an absent or expired token cannot name someone else's.
      mockRedis.readSessionOwner.mockResolvedValue({ userId: USER.id, tenantId: USER.tenantId })
    })

    // The owner is read under the presented token's OWN key. A wrong key here reads as "no
    // live session", which logout treats as a no-op — so a mistake would show up as logouts
    // that silently do nothing rather than as an error.
    it('should read the owner under the presented refresh token key', async () => {
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'j',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })

      await service.logout('access.jwt', 'the-refresh-token')

      expect(mockRedis.readSessionOwner).toHaveBeenCalledWith(`rt:${sha256('the-refresh-token')}`)
    })

    // The log line names the owner the stored record gave, and says so plainly when there was
    // none. An operator reading "userId=" with nothing after it cannot tell an account whose id
    // is empty from a session that was already gone.
    it.each([
      ['user-1', 'user-1'],
      ['', '(no live session)']
    ])('logs the owner as %s when the record names %s', async (owner, expected) => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      mockRedis.readSessionOwner.mockResolvedValue({ userId: owner, tenantId: 'tenant-1' })
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'j',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })

      await service.logout('access.jwt', 'the-refresh-token')

      expect(logSpy.mock.calls.map((call) => String(call[0])).join(' ')).toContain(
        `logout: userId=${expected}`
      )
      logSpy.mockRestore()
    })

    // Verifies that logout revokes the JWT jti in Redis with the correct key and a positive TTL.
    it('should blacklist the JWT jti and delete the refresh session', async () => {
      const jti = 'some-jti'
      const exp = Math.floor(Date.now() / 1000) + 900
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ jti, sub: 'user-1', exp })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh')

      expect(mockRedis.set).toHaveBeenCalledWith(`rv:${jti}`, '1', expect.any(Number))
      const ttl = (mockRedis.set.mock.calls[0] as [string, string, number])[2]
      expect(ttl).toBeGreaterThan(800)
      expect(ttl).toBeLessThanOrEqual(900)
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:/))
    })

    // Verifies that redis.set is NOT called when the access token is already expired at logout time.
    it('should skip the revocation redis.set when the token is already expired', async () => {
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'expired-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) - 10 // expired 10 s ago
      })
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh')

      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:/))
    })

    // Scenario: token whose exp equals "now" exactly, so remainingTtl === 0. Expected: redis.set
    // is NOT called. Why: kills the `remainingTtl > 0` -> `remainingTtl >= 0` EqualityOperator
    // mutant (line 282) — `>= 0` would (wrongly) write a revocation entry with a zero TTL.
    it('should NOT write a revocation entry when remainingTtl is exactly zero', async () => {
      const fixedNowMs = 1_700_000_000_000
      const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(fixedNowMs)
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'edge-jti',
        sub: 'user-1',
        exp: Math.floor(fixedNowMs / 1000) // remainingTtl = exp - now = 0
      })
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh')

      expect(mockRedis.set).not.toHaveBeenCalled()
      nowSpy.mockRestore()
    })

    // Scenario: a refresh token that has already rotated and is still inside its grace window,
    // presented at logout. Expected: both `rt:{hash}` and `rp:{hash}` are deleted. Why: the
    // grace pointer is what a rotated-away token recovers through, so leaving it behind makes
    // logout final only for a token that had NOT yet rotated — the one presented here would
    // still mint a fresh session for the rest of its window. The platform plane already clears
    // its `prp:` twin, and rust-auth clears the same pointer.
    it('should delete the rotation grace pointer alongside the refresh key', async () => {
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'jti-grace',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 300
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      await service.logout('access.token', 'raw-refresh')

      const hash = createHash('sha256').update('raw-refresh').digest('hex')
      expect(mockRedis.del).toHaveBeenCalledWith(`rt:${hash}`)
      expect(mockRedis.del).toHaveBeenCalledWith(`rp:${hash}`)
    })

    // Scenario: any logout. Expected: an info log carrying the userId. Why: pins the log
    // template (line 276) so blanking it to '' is caught.
    it('should log the userId on logout', async () => {
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.logout('access.token', 'raw-refresh')

      expect(logSpy).toHaveBeenCalledWith('logout: userId=user-1')
      logSpy.mockRestore()
    })

    // Verifies that logout resolves successfully even when the access token is malformed.
    // Scenario: the common one — the user comes back after their 15-minute access token
    // expired and clicks "sign out". Expected: the refresh session is revoked. Why: the route
    // used to sit behind the access-token guard, so this request answered 401 and `logout`
    // never ran — the refresh token, the long-lived credential logout exists to kill, stayed
    // valid for its full seven days on a device the user had just signed out. The access
    // token here is verified but its expiry waived, so its `jti` is still blacklisted.
    it('should revoke the session when the access token has expired', async () => {
      const expiredButSigned = { jti: 'jti-expired', sub: USER.id, exp: 1 }
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue(expiredButSigned)
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await expect(service.logout('expired.jwt', 'raw-refresh')).resolves.toBe(USER.id)

      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:[0-9a-f]{64}$/))
      // Nothing to blacklist: the token's remaining lifetime is already zero.
      expect(mockRedis.set).not.toHaveBeenCalledWith('rv:jti-expired', '1', expect.any(Number))
    })

    // Scenario: the owner is taken from the STORED session, never from the token's claims.
    // Expected: the session revoked is the one the refresh token names, whatever `sub` says.
    // Why: the route is public now, so `sub` is only as trustworthy as the signature — and
    // the whole point of allowing an expired token is that it may be missing entirely.
    it('should take the session owner from the stored record, not the token claims', async () => {
      mockRedis.readSessionOwner.mockResolvedValue({ userId: 'real-owner', tenantId: 'tenant-1' })
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'j',
        sub: 'someone-else',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await expect(service.logout('access.jwt', 'raw-refresh')).resolves.toBe('real-owner')
      expect(mockHooks.afterLogout).toHaveBeenCalledWith('real-owner', expect.anything())
    })

    // Scenario: an access token that is absent, malformed, or signed by a secret nobody holds.
    // Expected: logout still completes and still revokes the refresh session. Why: the access
    // token only contributes a blacklist entry; the refresh session is the credential logout
    // exists to kill, and refusing over an unusable access token is what left it alive.
    it('should still revoke the session when the access token cannot be verified', async () => {
      mockTokenManager.verifyIgnoringExpiry.mockImplementation(() => {
        throw new Error('Malformed')
      })
      mockRedis.del.mockResolvedValue(undefined)

      await expect(service.logout('bad.token', 'refresh')).resolves.toBe(USER.id)
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:[0-9a-f]{64}$/))
      // …and nothing was blacklisted, since no verified jti was available.
      expect(mockRedis.set).not.toHaveBeenCalledWith(
        expect.stringMatching(/^rv:/),
        '1',
        expect.any(Number)
      )
    })

    // Scenario: a refresh token that matches no live session — already logged out, or expired
    // while the user was away. Expected: no throw, no hook, and the caller learns nothing.
    it('should complete quietly when no live session matches the refresh token', async () => {
      mockRedis.readSessionOwner.mockResolvedValue({ userId: '', tenantId: undefined })
      mockTokenManager.verifyIgnoringExpiry.mockImplementation(() => {
        throw new Error('Malformed')
      })
      mockRedis.del.mockResolvedValue(undefined)

      await expect(service.logout('', 'refresh')).resolves.toBe('')
      expect(mockHooks.afterLogout).not.toHaveBeenCalled()
    })

    // Verifies that an error thrown by the afterLogout hook is logged and does not propagate (fire-and-forget).
    it('should log and swallow afterLogout hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockRejectedValue(new Error('hook error'))

      await service.logout('access.token', 'raw-refresh')

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('afterLogout hook threw: '))
      loggerSpy.mockRestore()
    })

    // Same duty on the hook path. `afterLogout(userId, createEmptyHookContext())` hands over
    // exactly one value and an empty context, which is why this is one of the three sites that
    // may still name what it passed rather than going opaque — and naming it only means something
    // if a test drives an error that contains it.
    it('removes the id it handed the hook from an error that quotes it', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockRejectedValue(new Error('audit sink refused user-1'))

      await service.logout('access.token', 'raw-refresh')
      await new Promise((r) => setImmediate(r))

      const logged = String(loggerSpy.mock.calls.at(-1)?.[0])
      expect(logged).toContain('afterLogout hook threw: ')
      expect(logged).not.toContain('user-1')
      loggerSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // refresh
  // ---------------------------------------------------------------------------

  describe('refresh', () => {
    // `refresh` decodes the token rotation just issued to compare its claims against the
    // account it re-reads. The default here matches the fixture most tests in this block use,
    // so a test that is not about the re-stamp does not have to restate it; the re-stamp tests
    // below override it with claims that deliberately diverge.
    beforeEach(() => {
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        role: 'member',
        tenantId: 't1',
        mfaVerified: false
      })
    })

    // Verifies the account is read TENANT-SCOPED. `findById` accepts an absent tenant for flows
    // that are deliberately cross-tenant, and ids may collide across tenants — the interface says
    // so, which is why `UserStatusGuard` passes both. Unscoped here, a homonym in another tenant
    // could pass the status gate on this caller's behalf and, on the re-stamp path, put that
    // account's tenant and role into the token this request hands back.
    it('reads the account scoped to the session tenant', async () => {
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'member',
        tenantId: 't1'
      })

      await service.refresh('old-refresh', '1.2.3.4', 'Browser')

      expect(mockUserRepo.findById).toHaveBeenCalledWith('u1', 't1')
    })

    // Verifies that refresh delegates to tokenManager.reissueTokens and returns the rotated result.
    it('should delegate to tokenManager.reissueTokens and return the account with it', async () => {
      const rotated = {
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      }
      mockTokenManager.reissueTokens.mockResolvedValue(rotated)
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'member',
        tenantId: 't1'
      })

      const result = await service.refresh('old-refresh', '1.2.3.4', 'Browser')
      expect(result.accessToken).toBe('new.access')
      expect(result.rawRefreshToken).toBe('new-refresh')
      // The account rides along so the caller does not pay a second repository read.
      expect(result.user.id).toBe('u1')
      expect(mockTokenManager.reissueTokens).toHaveBeenCalledWith(
        'old-refresh',
        '1.2.3.4',
        'Browser'
      )
    })

    // A ban has to end an existing session, not merely refuse the next login — a door a
    // signed-in user never needs to open again. Rotation works entirely from the Redis record,
    // so without this re-read a suspended account renews its access token every fifteen
    // minutes for the refresh token's whole seven days (ASVS v5 §7.4.2).
    it.each([['banned'], ['suspended'], ['inactive']])(
      'should refuse the rotation and end every session for a %s account',
      async (status) => {
        mockTokenManager.reissueTokens.mockResolvedValue({
          session: { userId: 'u1', tenantId: 't1', role: 'member' },
          accessToken: 'new.access',
          rawRefreshToken: 'new-refresh'
        })
        mockUserRepo.findById.mockResolvedValue({ id: 'u1', email: 'a@e.com', status })

        await expect(service.refresh('old-refresh', '1.2.3.4', 'Browser')).rejects.toThrow(
          AuthException
        )
        // The compensation is total: the session just minted goes with all the others, and the
        // epoch bump kills the access token that was issued a line earlier.
        expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u1', 't1', 'dashboard')
        expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u1', 't1', 'dashboard')
      }
    )

    // The email-verification gate on rotation, which had no test at all. `register` issues a
    // full session deliberately — a consumer needs one to render the "check your inbox" screen
    // — and the specification bounds that window at one access-token lifetime. Rotation is what
    // un-bounded it: the gate lived only on `login`, a door the caller never has to open again
    // once register handed them a refresh token, so an address nobody ever proved could hold an
    // authenticated session indefinitely.
    it('should refuse the rotation when the address is still unproven', async () => {
      const strict = await buildServiceWith({
        ...mockOptions,
        emailVerification: { required: true, otpTtlSeconds: 600 }
      })
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'member',
        tenantId: 't1',
        emailVerified: false
      })

      await expect(strict.refresh('old-refresh', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      // Refused, but NOT compensated. An unproven address is an unfinished onboarding, not a
      // denied account: revoking everything would also kill the access token the consumer is
      // using to render the "check your inbox" screen.
      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
      expect(mockRedis.bumpUserTokenEpoch).not.toHaveBeenCalled()
    })

    // …and a PROVEN address rotates normally under the same configuration, so the gate is the
    // verification flag and not the option being on.
    it('should rotate for a verified address when verification is required', async () => {
      const strict = await buildServiceWith({
        ...mockOptions,
        emailVerification: { required: true, otpTtlSeconds: 600 }
      })
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'member',
        tenantId: 't1',
        emailVerified: true
      })

      await expect(strict.refresh('old-refresh', '1.2.3.4', 'Browser')).resolves.toMatchObject({
        accessToken: 'new.access'
      })
    })

    // …and an unproven address rotates fine when verification is NOT required, which is the
    // default and the reason the gate reads the option first.
    it('should rotate for an unproven address when verification is not required', async () => {
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'member',
        tenantId: 't1',
        emailVerified: false
      })

      await expect(service.refresh('old-refresh', '1.2.3.4', 'Browser')).resolves.toMatchObject({
        accessToken: 'new.access'
      })
    })

    // Rotation builds its claims from the session record written at LOGIN, so a demotion had
    // no effect on a live session: the user kept minting ADMIN-roled tokens for the refresh
    // token's whole lifetime, and every role guard in the system reads that claim. The status
    // gate already re-reads the account — the authority was sitting there, unused.
    //
    // `mfaEnabled` is in the list because naming a subset is what left it out: `MfaRequiredGuard`
    // decides on `mfaEnabled && !mfaVerified`, so a session created while MFA was off kept
    // clearing every MFA-gated route for the refresh token's whole lifetime once the host
    // enabled MFA through its own admin surface rather than this library's `verifyAndEnable`.
    //
    // The stale claims live on the token rotation just issued — `verifyIgnoringExpiry` — not on
    // the session record, because the token is what the comparison reads and what the caller is
    // about to be handed.
    it.each([
      ['a demotion', { role: 'member' }],
      ['a tenant move', { tenantId: 't2' }],
      ['MFA being enabled out of band', { mfaEnabled: true }]
    ])('re-stamps the rotated access token after %s', async (_label, current) => {
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'admin' },
        accessToken: 'stale.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'admin',
        tenantId: 't1',
        mfaEnabled: false,
        ...current
      })
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        role: 'admin',
        tenantId: 't1',
        mfaEnabled: false,
        mfaVerified: false
      })
      mockTokenManager.issueAccess.mockReturnValue('restamped.access')
      mockRedis.getUserTokenEpoch.mockResolvedValue(3)

      const result = await service.refresh('old-refresh', '1.2.3.4', 'Browser')

      expect(result.accessToken).toBe('restamped.access')
      expect(mockTokenManager.issueAccess).toHaveBeenCalledWith(
        expect.objectContaining({ ...current, sub: 'u1', epoch: 3 })
      )
    })

    // …and the ordinary rotation, where nothing changed, pays nothing extra.
    it('leaves the rotated token alone when the authority is unchanged', async () => {
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'member',
        tenantId: 't1',
        mfaEnabled: false
      })
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        role: 'member',
        tenantId: 't1',
        mfaEnabled: false,
        mfaVerified: false
      })

      const result = await service.refresh('old-refresh', '1.2.3.4', 'Browser')

      expect(result.accessToken).toBe('new.access')
      expect(mockTokenManager.issueAccess).not.toHaveBeenCalled()
    })

    // A second factor already cleared on this session stays cleared — re-stamping the
    // authority must not silently demand it again.
    it('carries mfaVerified across the re-stamp', async () => {
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'admin' },
        accessToken: 'stale.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue({
        id: 'u1',
        email: 'a@e.com',
        status: 'active',
        role: 'member',
        tenantId: 't1',
        mfaEnabled: true
      })
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ mfaVerified: true })
      mockTokenManager.issueAccess.mockReturnValue('restamped.access')
      mockRedis.getUserTokenEpoch.mockResolvedValue(0)

      await service.refresh('old-refresh', '1.2.3.4', 'Browser')

      expect(mockTokenManager.issueAccess).toHaveBeenCalledWith(
        expect.objectContaining({ mfaVerified: true, mfaEnabled: true })
      )
    })

    // The account was deleted while the session record outlived it. Hand back nothing, and
    // clear the orphaned session rather than leaving it to be rotated again.
    it('should refuse the rotation when the account no longer exists', async () => {
      mockTokenManager.reissueTokens.mockResolvedValue({
        session: { userId: 'u1', tenantId: 't1', role: 'member' },
        accessToken: 'new.access',
        rawRefreshToken: 'new-refresh'
      })
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.refresh('old-refresh', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u1', 't1', 'dashboard')
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

      expect(mockSessionService.createSession).toHaveBeenCalledWith({
        userId: 'user-1',
        tenantId: 'tenant-1',
        rawRefreshToken: AUTH_RESULT.rawRefreshToken,
        ip: '1.2.3.4',
        userAgent: 'Browser'
      })
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

      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('updateLastLogin failed: '))
      loggerSpy.mockRestore()
    })

    // The second `updateLastLogin` site, and it needs its own case: the first one lives in
    // `login()` and a test there proves nothing about this method's list. Both name `user.id`
    // because both hand the repository exactly that, and both were unobservable until an error
    // quoted it — a repository echoing the parameter it failed on is the ordinary ORM shape.
    it('removes the id it handed the repository from an error that quotes it', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockUserRepo.findById.mockResolvedValue({ ...USER, mfaEnabled: false })
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockUserRepo.updateLastLogin.mockRejectedValue(
        new Error(`UPDATE users SET last_login WHERE id = '${USER.id}' failed`)
      )

      await service.issueTokensForUserId('user-1', '1.2.3.4', 'Browser')
      await new Promise((r) => setImmediate(r))

      const logged = String(loggerSpy.mock.calls.at(-1)?.[0])
      expect(logged).toContain('updateLastLogin failed: ')
      expect(logged).not.toContain(USER.id)
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

      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('afterLogin hook threw: '))
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

  describe('tenant resolution across every tenant-scoped flow', () => {
    /** An AuthService whose resolver always answers `resolved-tenant`. */
    async function serviceWithResolver(): Promise<AuthService> {
      const module = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...mockOptions, tenantIdResolver: () => 'resolved-tenant' }
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
      return module.get(AuthService)
    }

    // Scenario: a deployment resolves the tenant from the request, and a caller names a
    // different one in the body. Expected: the resolved tenant is what the OTP identifier is
    // derived from. Why: the option documents itself as ignoring the body value "to prevent
    // tenant spoofing", but only login and register honoured it — email verification read the
    // body verbatim, so a caller could probe for accounts in a tenant they have no
    // relationship with, and a verification issued under the resolved tenant could never be
    // completed because the two steps derived different identifiers.
    it('should refuse a body-named tenant on verifyEmail when a resolver is configured', async () => {
      const svc = await serviceWithResolver()
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await expect(
        svc.verifyEmail('attacker-tenant', 'user@example.com', '123456', mockReq)
      ).rejects.toBeInstanceOf(AuthException)

      // Refused before anything tenant-scoped ran, so the probe cannot be used to learn whether
      // an OTP exists under the resolved tenant either.
      expect(mockOtpService.verify).not.toHaveBeenCalled()
    })

    // The other half of the same guarantee, and the reason the refusal is not the whole test:
    // with the body silent, the RESOLVED tenant is what derives the identifier. Asserting only
    // the refusal would leave the resolver's value unpinned.
    it('should derive the verifyEmail identifier from the resolved tenant', async () => {
      const svc = await serviceWithResolver()
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await svc.verifyEmail(undefined, 'user@example.com', '123456', mockReq).catch(() => undefined)

      expect(mockOtpService.verify).toHaveBeenCalledWith(
        expect.any(String),
        hmacSha256('resolved-tenant:user@example.com', HMAC_KEY),
        '123456'
      )
    })

    // Scenario: the same, for the resend path — the one an attacker can drive without any
    // credential at all.
    it('should refuse a body-named tenant on resendVerificationEmail under a resolver', async () => {
      const svc = await serviceWithResolver()
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await expect(
        svc.resendVerificationEmail('attacker-tenant', 'user@example.com', mockReq)
      ).rejects.toBeInstanceOf(AuthException)

      // No cooldown key was written, so the refused request cannot consume the resolved tenant's
      // resend budget for an address the caller does not control.
      expect(mockRedis.setnx).not.toHaveBeenCalled()
    })

    // As above: the refusal is only half. With the body silent, the cooldown must key off the
    // RESOLVED tenant, which is what stops the two steps deriving different identifiers.
    it('should key the resend cooldown by the resolved tenant', async () => {
      const svc = await serviceWithResolver()
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await svc
        .resendVerificationEmail(undefined, 'user@example.com', mockReq)
        .catch(() => undefined)

      const cooldownKey = `resend:email_verification:${hmacSha256('resolved-tenant:user@example.com', HMAC_KEY)}`
      expect(mockRedis.setnx).toHaveBeenCalledWith(cooldownKey, expect.any(Number))
    })
  })

  describe('verifyEmail', () => {
    // Verifies that verifyEmail resolves the user from (tenantId, email) and updates the flag.
    it('should verify OTP and update emailVerified for the resolved user', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)
      mockHooks.afterEmailVerified.mockResolvedValue(undefined)

      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.verifyEmail('tenant-1', 'user@example.com', '123456', mockReq)

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
      // The UserStatusGuard verified-flag cache (`uev:{tenantId}:{userId}`) is invalidated under
      // the SAME tenant-scoped key the guard binds it to, so the account reaches its protected
      // routes on the next request rather than after the cache TTL. A bare-id delete would miss it.
      expect(mockRedis.del).toHaveBeenCalledWith(`uev:tenant-1:${USER.id}`)
      // Pin the success log template (line 408) so blanking it to '' is caught.
      expect(logSpy).toHaveBeenCalledWith(
        `verifyEmail: email verified userId=${USER.id} tenantId=tenant-1`
      )
      logSpy.mockRestore()
    })

    // The invalidation key must be percent-encoded exactly as the guard encodes it: a tenant or
    // id containing the `:` delimiter must not shift the boundary, or the delete would target a
    // different key than the guard wrote and leave the just-verified account locked out.
    it('percent-encodes the tenant and id in the verified-flag invalidation key', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, id: 'us:er', tenantId: 'ten:ant' })
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)
      mockHooks.afterEmailVerified.mockResolvedValue(undefined)

      await service.verifyEmail('ten:ant', 'user@example.com', '123456', mockReq)

      expect(mockRedis.del).toHaveBeenCalledWith('uev:ten%3Aant:us%3Aer')
    })

    // Verifies that OTP verification errors from otpService propagate to the caller.
    it('should propagate OTP errors', async () => {
      mockOtpService.verify.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_INVALID))
      await expect(
        service.verifyEmail('tenant-1', 'user@example.com', 'wrong', mockReq)
      ).rejects.toThrow(AuthException)
    })

    // Defends against the ownership-bypass path: valid OTP but user not found → OTP_INVALID.
    it('should throw OTP_INVALID when user does not exist after OTP succeeds', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      await expect(
        service.verifyEmail('tenant-1', 'ghost@example.com', '123456', mockReq)
      ).rejects.toThrow(AuthException)
      expect(mockUserRepo.updateEmailVerified).not.toHaveBeenCalled()
    })

    // Verifies that an error thrown by the afterEmailVerified hook is logged and does not propagate.
    it('should log and swallow afterEmailVerified hook errors (fire-and-forget)', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)
      mockHooks.afterEmailVerified.mockRejectedValue(new Error('hook error'))

      await service.verifyEmail('tenant-1', 'user@example.com', '123456', mockReq)

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('afterEmailVerified hook threw: ')
      )
      loggerSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // resendVerificationEmail
  // ---------------------------------------------------------------------------

  // The verification OTP, its five-attempt ceiling and the resend cooldown are all keyed on
  // `hmac(tenantId:email)`. Left raw, a change of case was a change of key: the same six-digit
  // code could be guessed five times per spelling, and one send per minute became one send per
  // spelling. Both doors canonicalize the address before it reaches the identifier.
  describe('email canonicalization on the verification paths', () => {
    it('verifies against the same OTP record whatever case the caller sends', async () => {
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockUserRepo.updateEmailVerified.mockResolvedValue(undefined)

      await service.verifyEmail('tenant-1', '  USER@Example.COM ', '123456', mockReq)

      expect(mockOtpService.verify).toHaveBeenCalledWith(
        'email_verification',
        hmacSha256('tenant-1:user@example.com', HMAC_KEY),
        '123456'
      )
      expect(mockUserRepo.findByEmail).toHaveBeenCalledWith('user@example.com', 'tenant-1')
    })

    it('draws on the same resend cooldown whatever case the caller sends', async () => {
      mockRedis.setnx.mockResolvedValue(false) // already sent within the window
      await service.resendVerificationEmail('tenant-1', 'USER@Example.COM', mockReq)

      expect(mockRedis.setnx).toHaveBeenCalledWith(
        `resend:email_verification:${hmacSha256('tenant-1:user@example.com', HMAC_KEY)}`,
        60
      )
    })
  })

  describe('resendVerificationEmail', () => {
    // Verifies that an OTP is generated and sent when the cooldown has not been triggered yet.
    it('should send OTP when cooldown is not active', async () => {
      mockRedis.setnx.mockResolvedValue(true) // key was newly set — first caller
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      mockOtpService.generate.mockReturnValue('654321')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockResolvedValue(undefined)

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)

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
      // The verification mail carries the tenant as its first argument, ahead of the recipient:
      // the port contract now propagates the tenant, so this asserts the value rather than only
      // that a send happened — a regression omitting or swapping it would otherwise pass here.
      expect(mockEmailProvider.sendEmailVerificationOtp).toHaveBeenCalledWith(
        'tenant-1',
        'user@example.com',
        '654321'
      )
    })

    // Verifies that when the cooldown is active (setnx=false) the endpoint silently succeeds without sending.
    it('should silently succeed when cooldown is active (anti-enumeration)', async () => {
      mockRedis.setnx.mockResolvedValue(false) // key already existed — cooldown active

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)

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
        await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)
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
        await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)
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

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)

      // Allow the fire-and-forget promise to settle.
      await new Promise((r) => setImmediate(r))

      // One argument, not two: the error object is never handed to the logger, because a relay
      // that rejects by quoting the message body would carry the OTP into the record Nest prints
      // from it. The description replaces it, and the code must not appear anywhere in the line.
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining('sendEmailVerificationOtp failed')
      )
      expect(loggerSpy.mock.calls[0]).toHaveLength(1)
      expect(loggerSpy.mock.calls[0]?.[0]).not.toContain('654321')
      loggerSpy.mockRestore()
    })

    // The seam at this site: the template puts `: ` between the identifier and the description,
    // so a withheld value spanning both is rebuilt from two fields that each contain nothing.
    // Reachable because the description opens with the error's NAME, which a custom class controls.
    it('withholds the line when the identifier and the error compose the address', async () => {
      // The composed value straddles the template's own `': '` separator: the identifier ends
      // one field and the description begins the next, and neither field contains the value.
      // The description opens with the opaque stand-in — nothing the channel wrote gets in — so
      // straddling value has to be built from.
      const named = new Error('channel down')

      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, id: 'u1', emailVerified: false })
      mockOtpService.generate.mockReturnValue('414141')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockRejectedValue(named)

      await service.resendVerificationEmail('tenant-1', 'u1: <error>', mockReq)
      await new Promise((r) => setImmediate(r))

      const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).not.toContain('u1: <error>')
      expect(logged).toContain('withheld')
      loggerSpy.mockRestore()
    })

    // `userId` reaches a log template and comes from the consumer's repository, which the
    // interface places no character constraint on. A CR in it closes the record and opens a
    // forged one — the attack `logSafe` exists for, and the same reasoning that already puts
    // `logSafe` around `tenantId` elsewhere in this codebase. Redaction alone does not cover it:
    // `redactSecrets` removes values, not control characters.
    it('neutralises a control character in the user id', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        ...USER,
        id: 'u1\nLOG [AuthService] login: success userId=victim',
        emailVerified: false
      })
      mockOtpService.generate.mockReturnValue('112358')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockRejectedValue(new Error('channel down'))

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)
      await new Promise((r) => setImmediate(r))

      const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).not.toContain('\n')
      expect(logged).toContain('<malformed>')
      loggerSpy.mockRestore()
    })

    // `userId` is the consumer's identifier and is interpolated into the same line as the error.
    // An id that happens to contain the generated code puts it back into the record after the
    // error text was cleaned — and a six-digit run inside a UUID-shaped id is not exotic. Every
    // field the template interpolates has to be sanitised, not only the one that obviously
    // carries channel text.
    it('redacts the code from the user id as well as from the error', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({
        ...USER,
        id: 'user-864209-abc',
        emailVerified: false
      })
      mockOtpService.generate.mockReturnValue('864209')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockRejectedValue(new Error('channel down'))

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)
      await new Promise((r) => setImmediate(r))

      const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).toContain('sendEmailVerificationOtp failed')
      expect(logged).not.toContain('864209')
      loggerSpy.mockRestore()
    })

    // The verification path's synchronous-throw case. The rejection tests above pass against the
    // pre-fix direct call, so without this the deferral here is unpinned and reverting it would
    // silently restore raw logging of a provider that throws instead of rejecting.
    it('keeps the verification code out of the log when the provider throws synchronously', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      mockOtpService.generate.mockReturnValue('975310')
      mockOtpService.store.mockResolvedValue(undefined)
      mockEmailProvider.sendEmailVerificationOtp.mockImplementation(() => {
        throw new Error('550 rejected by policy: "Your code is 975310."')
      })

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)
      await new Promise((r) => setImmediate(r))

      const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
      expect(logged).not.toContain('975310')
      // On a credential path nothing the relay wrote reaches the line, and nothing is parsed off it
      // either. What remains is the label this library owns plus the opaque stand-in — which IS the
      // diagnosis: it says the send failed and how deep the failure was reported from.
      expect(logged).not.toContain('rejected by policy')
      expect(logged).not.toContain('550')
      expect(logged).toBe('sendEmailVerificationOtp failed for user user-1: <error>')
      loggerSpy.mockRestore()
    })

    // The measured shape of the leak, at this call site. A policy or DLP relay rejects with 550
    // and QUOTES the offending content, so the provider's error carries the verification code
    // this service just generated. The previous version passed that error straight to the logger,
    // which put a working credential into the operator's pipeline until it expired.
    // Same distinction as the password-reset paths: a rejection test cannot see it, because a
    // rejection settles. A verification send that stalls must not hold the response open — the
    // account is already registered by then and the code is already stored.
    it('answers without waiting for a send that never settles', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      mockOtpService.generate.mockReturnValue('112358')
      mockOtpService.store.mockResolvedValue(undefined)
      // Initialised to a no-op rather than declared with `!`: the executor below runs
      // SYNCHRONOUSLY, so the real resolver is in place before this line's promise is returned.
      // The no-op is unreachable, and it keeps a definite-assignment assertion out of the file.
      let release = (): void => {}
      mockEmailProvider.sendEmailVerificationOtp.mockReturnValueOnce(
        new Promise<void>((resolve) => {
          release = resolve
        })
      )

      await expect(
        service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)
      ).resolves.toBeUndefined()

      expect(mockEmailProvider.sendEmailVerificationOtp).toHaveBeenCalled()

      release()
      await Promise.resolve()
    })

    it('keeps the verification code out of the log when the relay quotes it back', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: false })
      mockOtpService.generate.mockReturnValue('654321')
      mockOtpService.store.mockResolvedValue(undefined)
      // The error's NAME carries the code too. A mail client that names its error class after the
      // response is ordinary, and the name is as much the channel's field to fill as the message
      // is — which is why neither reaches the line.
      const named = new Error('550 rejected by policy: "Your code is 654321."')
      named.name = 'E654321'
      mockEmailProvider.sendEmailVerificationOtp.mockRejectedValue(named)

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)
      await new Promise((r) => setImmediate(r))

      // The error's NAME carries the code here, and no part of it reaches the line: the
      // description carries nothing the channel authored. The assertion is not merely that the
      // code is absent — it is that the ORDINARY line survives, because a build that let the name
      // through would have `safeLogLine` withhold the whole record to stop it, and the operator
      // would lose the diagnosis to a guard that should never have had to fire.
      const logged = loggerSpy.mock.calls[0]?.[0] as string
      expect(logged).not.toContain('654321')
      // On a credential path nothing the relay wrote reaches the line, and nothing is parsed off it
      // either. What remains is the label this library owns plus the opaque stand-in — which IS the
      // diagnosis: it says the send failed and how deep the failure was reported from.
      expect(logged).not.toContain('rejected by policy')
      expect(logged).not.toContain('550')
      expect(logged).toBe('sendEmailVerificationOtp failed for user user-1: <error>')
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
      expect(mockSessionService.createSession).toHaveBeenCalledWith({
        userId: USER.id,
        tenantId: 'tenant-1',
        rawRefreshToken: AUTH_RESULT.rawRefreshToken,
        ip: expect.any(String),
        userAgent: expect.any(String)
      })
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
      expect(mockSessionService.createSession).toHaveBeenCalledWith({
        userId: USER.id,
        tenantId: 'tenant-1',
        rawRefreshToken: AUTH_RESULT.rawRefreshToken,
        ip: expect.any(String),
        userAgent: expect.any(String)
      })
    })

    // Verifies that logout calls sessionService.revokeSession with the user id and the sha256 hash of the refresh token.
    it('logout: calls sessionService.revokeSession for the session hash', async () => {
      // Arrange
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ jti: 'jti1', exp: 9_999_999_999 })
      mockSessionService.revokeSession.mockResolvedValue(undefined)
      mockHooks.afterLogout.mockResolvedValue(undefined)

      // Act
      await sessionEnabledService.logout('access.jwt', 'raw-refresh-token')

      // Assert
      expect(mockSessionService.revokeSession).toHaveBeenCalledTimes(1)
      expect(mockSessionService.revokeSession).toHaveBeenCalledWith({
        userId: USER.id,
        tenantId: USER.tenantId,
        sessionHash: expect.stringMatching(/^[a-f0-9]{64}$/)
      })
    })

    // A record written before the session index carried a tenant. The index key cannot be named
    // without one, and guessing would sweep a key belonging to nobody while reading like a
    // revocation that happened — so the call is skipped. The session still dies: `rt:{hash}` is
    // deleted before this point, which is what actually ends it. Pinned because the branch is
    // reachable only from stored data, so nothing else in the suite reaches it.
    it('logout: skips the index revoke when the record names no tenant', async () => {
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      // Once, so the shared mock is not left tenant-less for the tests that follow.
      mockRedis.readSessionOwner.mockResolvedValueOnce({ userId: USER.id, tenantId: undefined })
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ jti: 'jti1', exp: 9_999_999_999 })
      mockHooks.afterLogout.mockResolvedValue(undefined)

      const owner = await sessionEnabledService.logout('access.jwt', 'raw-refresh-token')

      expect(owner).toBe(USER.id)
      expect(mockSessionService.revokeSession).not.toHaveBeenCalled()
      // The record itself is gone, which is what ends the session.
      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^rt:[0-9a-f]{64}$/))
    })

    // Verifies that logout completes without throwing when revokeSession rejects with SESSION_NOT_FOUND.
    it('logout: swallows SESSION_NOT_FOUND from sessionService.revokeSession', async () => {
      // Arrange
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ jti: 'jti2', exp: 9_999_999_999 })
      mockSessionService.revokeSession.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
      )
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Act & Assert
      await expect(
        sessionEnabledService.logout('access.jwt', 'raw-refresh-token')
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
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ jti: 'jti3', exp: 9_999_999_999 })
      const otherError = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      mockSessionService.revokeSession.mockRejectedValue(otherError)
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Act
      await sessionEnabledService.logout('access.jwt', 'raw-refresh-token')

      // Assert — warning is logged but logout still completes without throwing
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('session cleanup failed'))
      warnSpy.mockRestore()
    })

    // Verifies that a non-AuthException rejection from revokeSession triggers the warn path just like an unknown-code AuthException.
    it('logout: logs warn when revokeSession rejects with a non-AuthException error', async () => {
      // Arrange — plain Error covers the `err instanceof AuthException` false branch
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.set.mockResolvedValue(undefined)
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({ jti: 'jti4', exp: 9_999_999_999 })
      mockSessionService.revokeSession.mockRejectedValue(new Error('unexpected redis failure'))
      mockHooks.afterLogout.mockResolvedValue(undefined)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      // Act
      await sessionEnabledService.logout('access.jwt', 'raw-refresh-token')

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
      mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
        jti: 'some-jti',
        sub: 'user-1',
        exp: Math.floor(Date.now() / 1000) + 900
      })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.readSessionOwner.mockResolvedValue({ userId: 'user-1', tenantId: 'tenant-1' })

      await expect(noHooksService.logout('access.token', 'raw-refresh')).resolves.toBe('user-1')
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
        noHooksService.verifyEmail('tenant-1', 'user@example.com', '123456', mockReq)
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

      await service.resendVerificationEmail('tenant-1', 'ghost@example.com', mockReq)

      expect(mockOtpService.generate).not.toHaveBeenCalled()
    })

    // Scenario: cooldown free and the user exists but is already verified. Expected: no OTP is
    // sent. Why: covers the right-operand-false branch of `if (user && !user.emailVerified)`
    // (line 442) — an already-verified user must not receive a new verification OTP.
    it('should not send an OTP when the user is already verified', async () => {
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ ...USER, emailVerified: true })

      await service.resendVerificationEmail('tenant-1', 'user@example.com', mockReq)

      expect(mockOtpService.generate).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // Password hash upgrade on login
  // ---------------------------------------------------------------------------

  describe('password hash upgrade on login', () => {
    const dto = { email: 'user@example.com', password: 'correct', tenantId: 'tenant-1' }

    beforeEach(() => {
      mockUserRepo.findByEmail.mockResolvedValue(USER)
      mockPasswordService.compare.mockResolvedValue(true)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockUserRepo.updateLastLogin.mockResolvedValue(undefined)
      // The upgrade re-reads the account before writing, so every case here has to say what the
      // stored hash is at that moment. Set explicitly rather than left to whatever a previous
      // test in this file happened to leave on the shared mock: the whole point of the cases
      // below is which hash is in the row when the write is attempted.
      mockUserRepo.findById.mockResolvedValue(USER)
      mockUserRepo.updatePassword.mockClear()
    })

    // Scenario: a successful login whose stored hash was written under weaker parameters.
    // Expected: it is re-derived at the current cost and stored, without the user doing
    // anything. Why: this is what makes `password.costFactor` raisable at all — without it the
    // only route to stronger parameters would be to invalidate every stored hash, which is to
    // say lock every user out.
    it('should upgrade a stale password hash after a successful login', async () => {
      mockPasswordService.needsRehash.mockReturnValue(true)
      mockPasswordService.hash.mockResolvedValue('scrypt:131072:8:1:aa:bb')
      mockUserRepo.updatePassword.mockResolvedValue(undefined)

      await service.login(dto, mockReq)
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockPasswordService.needsRehash).toHaveBeenCalledWith(USER.passwordHash)
      expect(mockUserRepo.updatePassword).toHaveBeenCalledWith(USER.id, 'scrypt:131072:8:1:aa:bb')
    })

    // The re-read is TENANT-SCOPED. `IUserRepository.findById` takes the argument precisely so
    // a store whose ids are not globally unique cannot answer with another tenant's row, and
    // this is a read on behalf of one account rather than an admin flow. An unscoped answer
    // would have the guard comparing the verified hash against a DIFFERENT row — dropping a
    // legitimate upgrade, or admitting the write it exists to refuse.
    it('should scope the re-read to the account tenant', async () => {
      mockPasswordService.needsRehash.mockReturnValue(true)
      mockPasswordService.hash.mockResolvedValue('scrypt:131072:8:1:aa:bb')
      mockUserRepo.findById.mockClear()

      await service.login(dto, mockReq)
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.findById).toHaveBeenCalledWith(USER.id, USER.tenantId)
    })

    // Scenario: the account's password changed between the login that scheduled the upgrade and
    // the moment the upgrade tried to write. Expected: nothing written.
    //
    // Why this is the important case rather than an edge one. The task carries the PLAINTEXT it
    // is upgrading and a KDF derivation is slow by construction, so it lands well after the
    // login. The situation where a password changes in that window is not random — it is a user
    // resetting BECAUSE the old password was compromised, where the attacker's own login is what
    // scheduled the task. An unconditional write re-installs the compromised credential over the
    // new one: the old password works again, the new one does not, and the "password changed"
    // mail has already gone out. `needsRehash` is true for EVERY account during the parameter
    // migration this feature exists to serve, so the alignment is not rare either.
    it('should not overwrite a password that changed while the upgrade was deriving', async () => {
      mockPasswordService.needsRehash.mockReturnValue(true)
      mockPasswordService.hash.mockResolvedValue('scrypt:131072:8:1:aa:bb')
      // The reset landed first: the row no longer holds the hash that was verified.
      mockUserRepo.findById.mockResolvedValue({ ...USER, passwordHash: 'scrypt:1:1:1:zz:zz' })
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.login(dto, mockReq)
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
      // And it says so. This is a silent abandonment on a background task — the login already
      // succeeded, nothing surfaces to the user, and the account keeps a hash the migration was
      // supposed to replace. Without the line, an operator watching a parameter migration stall
      // on a subset of accounts has no record of why it skipped them.
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining(`the stored hash changed userId=${USER.id}`)
      )
      logSpy.mockRestore()
    })

    // The account disappearing between the login and the write is the same decision: there is no
    // row whose hash is the one that was verified, so there is nothing this upgrade may replace.
    it('should not write when the account is gone by the time the upgrade lands', async () => {
      mockPasswordService.needsRehash.mockReturnValue(true)
      mockPasswordService.hash.mockResolvedValue('scrypt:131072:8:1:aa:bb')
      mockUserRepo.findById.mockResolvedValue(null)

      await service.login(dto, mockReq)
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Scenario: the same login with a current hash. Expected: nothing written. Why: a rewrite
    // on every login is a write on the hot path for no gain, and it would leave the staleness
    // check deciding nothing.
    it('should not touch a hash already at the current parameters', async () => {
      mockPasswordService.needsRehash.mockReturnValue(false)

      await service.login(dto, mockReq)
      await new Promise((resolve) => setImmediate(resolve))

      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Scenario: the upgrade write fails. Expected: the login still succeeds, and the failure is
    // logged. Why: the user is already authenticated and the old hash keeps working — failing a
    // login over a housekeeping write would turn an optimisation into an outage.
    it('should not fail the login when the upgrade write fails', async () => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockPasswordService.needsRehash.mockReturnValue(true)
      mockPasswordService.hash.mockResolvedValue('scrypt:131072:8:1:aa:bb')
      mockUserRepo.updatePassword.mockRejectedValue(new Error('write failed'))

      await expect(service.login(dto, mockReq)).resolves.toBeDefined()
      await new Promise((resolve) => setImmediate(resolve))

      expect(errorSpy).toHaveBeenCalledWith(
        'rehash on verify failed — the stored hash is unchanged: <error>'
      )
      errorSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // unlockAccount()
  // ---------------------------------------------------------------------------

  describe('unlockAccount', () => {
    // The counter is keyed by an HMAC no consumer can derive, so before this the lockout
    // could only be waited out — and it is also the lever an attacker pulls to deny service
    // to one account, which makes undoing it part of the defence.
    it('clears the lockout under the same key login derives', async () => {
      await service.unlockAccount('user@example.com', 'tenant-1')

      expect(mockBruteForce.resetFailures).toHaveBeenCalledWith(
        hmacSha256('dashboard:tenant-1:user@example.com', HMAC_KEY)
      )
    })

    // Normalized the same way login normalizes it, or the derived key misses the counter the
    // lockout actually wrote and the unlock silently does nothing.
    it('normalizes the address before deriving the key', async () => {
      await service.unlockAccount('  USER@Example.com  ', 'tenant-1')

      expect(mockBruteForce.resetFailures).toHaveBeenCalledWith(
        hmacSha256('dashboard:tenant-1:user@example.com', HMAC_KEY)
      )
    })

    // The clear is logged with the address masked and the tenant named — an operator auditing
    // "who unlocked this account" needs both, and must not get the address in the clear.
    it('logs the clear with the address masked', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.unlockAccount('user@example.com', 'tenant-1')

      const logged = logSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(logged).toContain('unlockAccount: lockout cleared')
      expect(logged).toContain('tenantId=tenant-1')
      expect(logged).not.toContain('user@example.com')
      logSpy.mockRestore()
    })
  })
  describe('revokeAllSessions', () => {
    // A blank tenant derives `dashboard::{userId}` — an index and an epoch nobody writes. Both
    // Redis calls would succeed against them and this method would return normally: a
    // "sign out everywhere" reported as done while every session and access token stayed valid.
    // Refused at the boundary, because that is where a caller can be wrong; `userSubject` itself
    // has to stay total, since the rotation scripts are called with an empty placeholder identity
    // to discover a grace pointer.
    it('refuses a blank tenant instead of sweeping a key nobody writes', async () => {
      // The DETAILS, not merely the exception type: an empty payload would tell the caller
      // nothing about what to fix and would still satisfy `toThrow(AuthException)`.
      await expect(
        service.revokeAllSessions({ userId: 'user-1', tenantId: '' })
      ).rejects.toMatchObject({
        response: {
          error: {
            code: AUTH_ERROR_CODES.VALIDATION,
            details: [
              { field: 'tenantId', message: "tenantId is required to revoke a user's sessions" }
            ]
          }
        }
      })

      expect(mockRedis.invalidateUserSessions).not.toHaveBeenCalled()
      expect(mockRedis.bumpUserTokenEpoch).not.toHaveBeenCalled()
    })

    // The ordinary path still reaches both channels: the session index AND the token epoch, so a
    // revocation ends stateless access tokens rather than only refresh sessions.
    it('sweeps the index and bumps the epoch for a real tenant', async () => {
      await service.revokeAllSessions({ userId: 'user-1', tenantId: 'tenant-1' })

      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        'dashboard'
      )
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('user-1', 'tenant-1', 'dashboard')
    })
  })
})
