/**
 * @fileoverview Unit tests for PasswordResetService.
 *
 * Covers `initiateReset`, `resetPassword`, `verifyOtp`, and `resendOtp` across
 * both token and OTP reset methods. All external dependencies (Redis, email
 * provider, OtpService, PasswordService, user repository) are mocked — no real
 * Redis or I/O is exercised.
 *
 * Coverage target: ≥80% statements/lines.
 */

// Mock sleep so tests don't wait 300ms in timing normalization paths
jest.mock('../utils/sleep', () => ({ sleep: jest.fn().mockResolvedValue(undefined) }))

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test, type TestingModule } from '@nestjs/testing'

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
import { OtpService } from './otp.service'
import { PasswordResetService } from './password-reset.service'
import { PasswordService } from './password.service'
import { sleep } from '../utils/sleep'
import type { Request } from 'express'

const mockSleep = sleep as jest.MockedFunction<typeof sleep>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extracts the error code from a thrown AuthException. */
function getErrorCode(err: unknown): string {
  if (!(err instanceof AuthException)) throw new Error('Not an AuthException')
  const res = err.getResponse() as { error?: { code?: string } }
  return res.error?.code ?? ''
}

/** Flushes the microtask queue (fire-and-forget email calls). */
async function flushMicrotasks(ticks = 2): Promise<void> {
  for (let i = 0; i < ticks; i++) await Promise.resolve()
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const JWT_SECRET = 'test-secret-32-characters-minimum'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const mockOptions = {
  passwordReset: {
    method: 'token' as const,
    tokenTtlSeconds: 3600,
    otpLength: 6,
    otpTtlSeconds: 300
  },
  blockedStatuses: ['banned', 'suspended'],
  jwt: { secret: JWT_SECRET, accessCookieMaxAgeMs: 900_000 },
  hmacKey: HMAC_KEY,
  previousHmacKeys: []
}

const mockUserRepo = {
  findByEmail: jest.fn(),
  findById: jest.fn(),
  updatePassword: jest.fn()
}

const mockHooks = {
  afterPasswordReset: jest.fn()
}

const mockEmailProvider = {
  sendPasswordResetToken: jest.fn(),
  sendPasswordResetOtp: jest.fn()
}

const mockOtpService = {
  generate: jest.fn(),
  store: jest.fn(),
  verify: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn(),
  assertNotCompromised: jest.fn().mockResolvedValue(undefined)
}

const mockRedis = {
  set: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  getdel: jest.fn(),
  setnx: jest.fn(),
  invalidateUserSessions: jest.fn(),
  bumpUserTokenEpoch: jest.fn()
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

async function buildModule(
  emailProviderValue: unknown = mockEmailProvider,
  hooksValue: unknown = null
): Promise<TestingModule> {
  return Test.createTestingModule({
    providers: [
      PasswordResetService,
      { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: emailProviderValue },
      { provide: BYMAX_AUTH_HOOKS, useValue: hooksValue },
      { provide: OtpService, useValue: mockOtpService },
      { provide: PasswordService, useValue: mockPasswordService },
      { provide: AuthRedisService, useValue: mockRedis }
    ]
  }).compile()
}

// ---------------------------------------------------------------------------
// Suite setup
// ---------------------------------------------------------------------------

/** A minimal request double — the reset flows only hand it to the tenant resolver. */
const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser' }
} as unknown as Request

describe('PasswordResetService', () => {
  let service: PasswordResetService

  beforeEach(async () => {
    jest.clearAllMocks()

    // Default mock implementations
    mockUserRepo.findByEmail.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue(null)
    mockUserRepo.updatePassword.mockResolvedValue(undefined)
    mockHooks.afterPasswordReset.mockResolvedValue(undefined)
    mockEmailProvider.sendPasswordResetToken.mockResolvedValue(undefined)
    mockEmailProvider.sendPasswordResetOtp.mockResolvedValue(undefined)
    mockOtpService.generate.mockReturnValue('123456')
    mockOtpService.store.mockResolvedValue(undefined)
    mockOtpService.verify.mockResolvedValue(undefined)
    mockPasswordService.hash.mockResolvedValue('$hashed$')
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.get.mockResolvedValue(null)
    mockRedis.del.mockResolvedValue(undefined)
    mockRedis.getdel.mockResolvedValue(null)
    mockRedis.setnx.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockRedis.bumpUserTokenEpoch.mockResolvedValue(1)
    mockSleep.mockResolvedValue(undefined)

    const module = await buildModule()
    service = module.get(PasswordResetService)
  })

  // =========================================================================
  // initiateReset
  // =========================================================================

  describe('initiateReset', () => {
    const dto = { email: 'user@example.com', tenantId: 'tenant1' }

    // The cooldown is shared with `resendOtp`, under the same key, and this is the door that
    // matters more: every issuance rewrites the OTP record with `attempts: 0`, so an untimed
    // initiate turns the 5-attempt ceiling into 5 attempts PER CALL — an unbounded supply of
    // guesses at a six-digit code — and each call also mails an address the caller merely has
    // to know.
    it('claims the shared resend cooldown before sending anything', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      await service.initiateReset(dto, mockReq)

      const [key, ttl] = mockRedis.setnx.mock.calls[0] as [string, number]
      expect(key.startsWith('resend:password_reset:')).toBe(true)
      expect(ttl).toBe(60)
    })

    // A second call inside the window sends nothing at all: no repository read, no OTP write,
    // no mail. Silent success, so the throttle does not answer whether the account exists.
    it('sends nothing when the cooldown is already claimed', async () => {
      mockRedis.setnx.mockResolvedValue(false)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()

      expect(mockUserRepo.findByEmail).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetToken).not.toHaveBeenCalled()
      expect(mockOtpService.store).not.toHaveBeenCalled()
    })

    // Both entry points must draw on ONE budget: a per-endpoint cooldown lets a caller
    // alternate between them and halve the effective wait.
    it('uses the same cooldown key as resendOtp', async () => {
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      await service.initiateReset(dto, mockReq)
      const initiateKey = (mockRedis.setnx.mock.calls[0] as [string, number])[0]

      mockRedis.setnx.mockClear()
      await service.resendOtp(dto, mockReq)
      const resendKey = (mockRedis.setnx.mock.calls[0] as [string, number])[0]

      expect(initiateKey).toBe(resendKey)
    })

    // Verifies that does NOT throw when user is not found (anti-enumeration).
    it('does NOT throw when user is not found (anti-enumeration)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act & Assert
      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is blocked (anti-enumeration).
    it('does NOT throw when user is blocked (anti-enumeration)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'banned' })

      // Act & Assert
      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is suspended (blocked status).
    it('does NOT throw when user is suspended (blocked status)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'suspended' })

      // Act & Assert
      await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw even when email provider throws.
    // Also verifies the Redis token rollback fires so an undeliverable token does not
    // linger in Redis until natural TTL expiry.
    it('does NOT throw even when email provider throws (and rolls back Redis token)', async () => {
      // The service intentionally logs the provider error via its
      // Nest `Logger`. Silence that log in the test output — the
      // assertion below verifies the public contract (the call
      // resolves) which is the real behaviour under test.
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      try {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })
        mockEmailProvider.sendPasswordResetToken.mockRejectedValue(new Error('SMTP error'))

        // Act & Assert
        await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
        await flushMicrotasks()

        // Rollback: the pw_reset:{hash} key written before the email send must be
        // deleted after the email failure so it does not linger until natural TTL.
        expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^pw_reset:/))
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // Verifies that the rollback's `del` failure is also caught and logged — never
    // propagates out of `initiateReset` (the public contract is fire-and-forget).
    it('does NOT throw when both email AND rollback Redis del fail', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      try {
        mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })
        mockEmailProvider.sendPasswordResetToken.mockRejectedValue(new Error('SMTP error'))
        mockRedis.del.mockRejectedValueOnce(new Error('Redis down'))

        await expect(service.initiateReset(dto, mockReq)).resolves.toBeUndefined()
        await flushMicrotasks()

        // Both errors must be logged: the original email failure AND the rollback failure.
        const logged = loggerSpy.mock.calls.map((c) => String(c[0])).join(' | ')
        expect(logged).toMatch(/sendPasswordResetToken failed/)
        expect(logged).toMatch(/pw_reset rollback delete failed/)
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // Verifies that calls sendToken path (token method) when user exists and is not blocked.
    it('calls sendToken path (token method) when user exists and is not blocked', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await service.initiateReset(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendPasswordResetToken).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendPasswordResetToken).toHaveBeenCalledWith(
        dto.email,
        expect.any(String)
      )
    })

    // Verifies that skips email and logs warn when no email provider is configured.
    it('skips email and logs warn when no email provider is configured', async () => {
      // Arrange
      const module = await buildModule(null)
      const noEmailService = module.get(PasswordResetService)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await noEmailService.initiateReset(dto, mockReq)

      // Assert
      expect(mockEmailProvider.sendPasswordResetToken).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('no email provider configured'))

      warnSpy.mockRestore()
    })

    // Verifies that applies timing normalization — calls sleep.
    it('applies timing normalization — calls sleep', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      await service.initiateReset(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Scenario: 100 ms elapse between the start timestamp and the finally block; expected: sleep
    // is called with exactly the REMAINING budget (300 - 100 = 200). Why: pins the
    // `Math.max(0, 300 - (now - start))` formula — Math.min collapses it to 0, the `300 + elapsed`
    // mutant yields 400, and the `now + start` mutant yields a huge negative -> 0. Only the
    // original produces 200.
    it('sleeps for the remaining budget (max(0, 300 - elapsed)) in the finally block', async () => {
      // Arrange — first Date.now() is `start`, every later call is 100 ms after.
      mockUserRepo.findByEmail.mockResolvedValue(null)
      const nowSpy = jest.spyOn(Date, 'now')
      nowSpy.mockReturnValue(1_000_100)
      nowSpy.mockReturnValueOnce(1_000_000)

      // Act
      await service.initiateReset(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledWith(200)
      nowSpy.mockRestore()
    })

    // Verifies that logs error when unexpected error occurs during initiation.
    it('logs error when unexpected error occurs during initiation', async () => {
      // Arrange
      const unexpectedError = new Error('Database connection failed')
      mockUserRepo.findByEmail.mockRejectedValue(unexpectedError)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await service.initiateReset(dto, mockReq)

      // Assert
      expect(errorSpy).toHaveBeenCalledWith('initiateReset: unexpected error', unexpectedError)
      expect(mockSleep).toHaveBeenCalledTimes(1)
      errorSpy.mockRestore()
    })

    // Verifies that does NOT send email to blocked user.
    it('does NOT send email to blocked user', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'banned' })

      // Act
      await service.initiateReset(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetToken).not.toHaveBeenCalled()
    })

    describe('otp method', () => {
      let otpMethodService: PasswordResetService

      beforeEach(async () => {
        const optionsWithOtp = {
          ...mockOptions,
          passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
        }
        const module = await Test.createTestingModule({
          providers: [
            PasswordResetService,
            { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
            { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
            { provide: BYMAX_AUTH_HOOKS, useValue: null },
            { provide: OtpService, useValue: mockOtpService },
            { provide: PasswordService, useValue: mockPasswordService },
            { provide: AuthRedisService, useValue: mockRedis }
          ]
        }).compile()
        otpMethodService = module.get(PasswordResetService)
      })

      // Verifies that calls sendOtp path when user exists and is not blocked.
      it('calls sendOtp path when user exists and is not blocked', async () => {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

        // Act
        await otpMethodService.initiateReset(dto, mockReq)
        await flushMicrotasks()

        // Assert
        expect(mockOtpService.generate).toHaveBeenCalledTimes(1)
        expect(mockOtpService.store).toHaveBeenCalledTimes(1)
        expect(mockEmailProvider.sendPasswordResetOtp).toHaveBeenCalledTimes(1)
      })

      // Scenario: OTP send path; expected: otpService.store receives the purpose 'password_reset'
      // and the HMAC identifier derived from `${tenantId}:${email}`. Why: pins the
      // PASSWORD_RESET_PURPOSE constant (emptying it -> '') and the otpIdentifier message
      // (`${tenantId}:${email}` -> '' would change the HMAC), both of which determine the Redis
      // OTP keyspace.
      it('stores the OTP under purpose=password_reset with the tenant:email HMAC identifier', async () => {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

        // Act
        await otpMethodService.initiateReset(dto, mockReq)
        await flushMicrotasks()

        // Assert
        const [purpose, identifier] = mockOtpService.store.mock.calls[0] as [string, string]
        expect(purpose).toBe('password_reset')
        expect(identifier).toBe(hmacSha256(`${dto.tenantId}:${dto.email}`, HMAC_KEY))
      })

      // Verifies that does NOT send OTP email to blocked user.
      it('does NOT send OTP email to blocked user', async () => {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'banned' })

        // Act
        await otpMethodService.initiateReset(dto, mockReq)
        await flushMicrotasks()

        // Assert
        expect(mockOtpService.generate).not.toHaveBeenCalled()
        expect(mockOtpService.store).not.toHaveBeenCalled()
        expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
      })
    })
  })

  // =========================================================================
  // resetPassword — token method
  // =========================================================================

  describe('resetPassword (token method)', () => {
    const baseDto = {
      email: 'user@example.com',
      tenantId: 'tenant1',
      newPassword: 'NewPassword123!'
    }

    const validContext = JSON.stringify({
      userId: 'u1',
      email: 'user@example.com',
      tenantId: 'tenant1'
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + otp).
    it('throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + otp)', async () => {
      // Arrange
      const dto = { ...baseDto, token: 'tok', otp: '123456' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Scenario: proofCount > 1 (token + otp) while the token would otherwise resolve to a VALID
    // context; expected: still rejected by the mutual-exclusivity guard BEFORE any reset happens.
    // Why: prior proofCount tests left getdel=null, so the request would fail downstream anyway —
    // masking the guard. With a valid context, neutering the guard (proofCount filter ->
    // () => undefined / false, or `if (proofCount > 1)` -> if(false)/{}) would let the reset
    // succeed. Asserting it rejects AND that the password is never updated kills all four mutants.
    it('rejects (and never updates the password) when proofCount > 1 even with a valid stored token', async () => {
      // Arrange — token resolves to a context matching the dto, so only the proofCount guard can reject.
      mockRedis.getdel.mockResolvedValue(validContext)
      const dto = { ...baseDto, token: 'mytoken', otp: '123456' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      expect(mockPasswordService.hash).not.toHaveBeenCalled()
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + verifiedToken).
    it('throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + verifiedToken)', async () => {
      // Arrange
      const dto = { ...baseDto, token: 'tok', verifiedToken: 'v'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (otp + verifiedToken).
    it('throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (otp + verifiedToken)', async () => {
      // Arrange
      const dto = { ...baseDto, otp: '123456', verifiedToken: 'v'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when method=token but dto.token is absent.
    it('throws PASSWORD_RESET_TOKEN_INVALID when method=token but dto.token is absent', async () => {
      // Arrange
      const dto = { ...baseDto }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when token not in Redis (getdel returns null).
    it('throws PASSWORD_RESET_TOKEN_INVALID when token not in Redis (getdel returns null)', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(null)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when email mismatch in stored context.
    it('throws PASSWORD_RESET_TOKEN_INVALID when email mismatch in stored context', async () => {
      // Arrange
      const mismatchContext = JSON.stringify({
        userId: 'u1',
        email: 'other@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(mismatchContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when tenantId mismatch in stored context.
    it('throws PASSWORD_RESET_TOKEN_INVALID when tenantId mismatch in stored context', async () => {
      // Arrange
      const mismatchContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'other-tenant'
      })
      mockRedis.getdel.mockResolvedValue(mismatchContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is malformed.
    it('throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is malformed', async () => {
      // Arrange
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.getdel.mockResolvedValue('{{{invalid')
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      // The holder gets the same code as for a replayed token, by design. The operator gets
      // the one line that says the record was corrupted rather than spent.
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('not parseable JSON'))
      warnSpy.mockRestore()
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is missing required fields.
    it('throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is missing required fields', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(JSON.stringify({ userId: 'u1' }))
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that resets password and invalidates sessions on success (token flow).
    it('resets password and invalidates sessions on success (token flow)', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(validContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      await service.resetPassword(dto, mockReq)

      // Assert
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockUserRepo.updatePassword).toHaveBeenCalledWith('u1', '$hashed$')
      // Full revocation: refresh sessions are deleted AND the user's token epoch is advanced,
      // so already-issued stateless access tokens are rejected immediately rather than staying
      // valid until their exp.
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u1')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u1')
    })

    // Scenario: token flow; expected: getdel is called with a `pw_reset:<sha256>` key, never an
    // empty string. Why: pins the Redis key template — emptying it (`getdel('')`) would read the
    // wrong key, breaking single-use token consumption.
    it('reads the token from a pw_reset:{sha256} Redis key', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(validContext)
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      await service.resetPassword(dto, mockReq)

      // Assert
      const [key] = mockRedis.getdel.mock.calls[0] as [string]
      expect(key).toMatch(/^pw_reset:[0-9a-f]{64}$/)
    })

    // ---- parseResetContext clause isolation (defence against Redis tampering) ----
    // Each test feeds a stored context where exactly ONE validation clause should reject it, with
    // every other field valid (and email/tenantId matching the dto so the later equality check
    // cannot be the cause). This kills the ConditionalExpression `clause -> false` and the
    // LogicalOperator `|| -> &&` mutants on the parseResetContext guard chain. For non-string
    // email/tenantId the bypassed mutant reaches sha256(<number>) which throws a TypeError, so we
    // assert the thrown error is specifically an AuthException (a TypeError would not be).

    // Scenario: stored JSON is the literal null; expected: AuthException. Why: kills the
    // `parsed === null -> false` mutant — bypassing it reaches `'userId' in null`, a TypeError.
    it('throws AuthException when stored context is JSON null', async () => {
      mockRedis.getdel.mockResolvedValue('null')
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Scenario: stored JSON is a number primitive; expected: AuthException. Why: kills the
    // `typeof parsed !== 'object' -> false` mutant — bypassing it reaches `'userId' in 42`, a TypeError.
    it('throws AuthException when stored context is a JSON number primitive', async () => {
      mockRedis.getdel.mockResolvedValue('42')
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Scenario: the `userId` KEY is absent (email/tenantId present and valid); expected: rejected
    // and password never updated. Why: kills the false-prefix mutant that drops the leading
    // clauses through `userId in parsed` — bypassing them would return a context with no userId
    // and call applyPasswordReset(undefined).
    it('throws AuthException when the userId key is missing from the stored context', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ email: baseDto.email, tenantId: baseDto.tenantId })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Scenario: `userId` is a number, all else valid and matching; expected: rejected, no update.
    // Why: kills the `typeof userId !== 'string' -> false` clause and the false-prefix mutant that
    // keeps only `|| email-type || tenantId-type` — both would return the context and reset with a
    // numeric userId.
    it('throws AuthException when stored userId is not a string', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 123, email: baseDto.email, tenantId: baseDto.tenantId })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect(mockUserRepo.updatePassword).not.toHaveBeenCalled()
    })

    // Scenario: `email` is a number, userId/tenantId valid; expected: AuthException specifically.
    // Why: kills the `typeof email !== 'string' -> false` clause and the matching `|| -> &&`
    // mutant — bypassing reaches sha256(<number>) (TypeError), which is NOT an AuthException.
    it('throws AuthException (not a TypeError) when stored email is not a string', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u1', email: 123, tenantId: baseDto.tenantId })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
    })

    // Scenario: `tenantId` is a number, userId/email valid and email matches; expected:
    // AuthException specifically. Why: kills the `typeof tenantId !== 'string' -> false` clause
    // and the last `|| -> &&` mutant — bypassing reaches sha256(<number>) (TypeError).
    it('throws AuthException (not a TypeError) when stored tenantId is not a string', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u1', email: baseDto.email, tenantId: 999 })
      )
      const dto = { ...baseDto, token: 'mytoken' }

      let caught: unknown
      try {
        await service.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
    })
  })

  // =========================================================================
  // resetPassword — otp method
  // =========================================================================

  describe('resetPassword (otp method)', () => {
    let otpMethodService: PasswordResetService

    const baseDto = {
      email: 'user@example.com',
      tenantId: 'tenant1',
      newPassword: 'NewPassword123!'
    }

    beforeEach(async () => {
      const optionsWithOtp = {
        ...mockOptions,
        passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
      }
      const module = await Test.createTestingModule({
        providers: [
          PasswordResetService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: OtpService, useValue: mockOtpService },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: AuthRedisService, useValue: mockRedis }
        ]
      }).compile()
      otpMethodService = module.get(PasswordResetService)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when method=otp but dto.token is present (method mismatch).
    it('throws PASSWORD_RESET_TOKEN_INVALID when method=otp but dto.token is present (method mismatch)', async () => {
      // Arrange
      const dto = { ...baseDto, token: 'sometoken' }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that resets password via verifiedToken path when dto.verifiedToken is present.
    it('resets password via verifiedToken path when dto.verifiedToken is present', async () => {
      // Arrange
      const verifiedContext = JSON.stringify({
        userId: 'u2',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(verifiedContext)
      const dto = { ...baseDto, verifiedToken: 'a'.repeat(64) }

      // Act
      await otpMethodService.resetPassword(dto, mockReq)

      // Assert
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u2')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u2')
      // Pin the verifiedToken Redis key template — emptying it (`getdel('')`) reads the wrong key.
      const [key] = mockRedis.getdel.mock.calls[0] as [string]
      expect(key).toMatch(/^pw_vtok:[0-9a-f]{64}$/)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken is consumed (getdel returns null).
    it('throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken is consumed (getdel returns null)', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(null)
      const dto = { ...baseDto, verifiedToken: 'b'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context email does not match.
    it('throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context email does not match', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u2', email: 'other@example.com', tenantId: 'tenant1' })
      )
      const dto = { ...baseDto, verifiedToken: 'c'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context tenantId does not match.
    it('throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken context tenantId does not match', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ userId: 'u2', email: 'user@example.com', tenantId: 'other-tenant' })
      )
      const dto = { ...baseDto, verifiedToken: 'd'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that resets password via direct OTP path when dto.otp is present.
    it('resets password via direct OTP path when dto.otp is present', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u3', status: 'active' })
      const dto = { ...baseDto, otp: '654321' }

      // Act
      await otpMethodService.resetPassword(dto, mockReq)

      // Assert
      expect(mockOtpService.verify).toHaveBeenCalledTimes(1)
      // Pin the OTP purpose and the tenant:email HMAC identifier passed to verify, so emptying
      // PASSWORD_RESET_PURPOSE ('' ) or the otpIdentifier message ('') is caught.
      expect(mockOtpService.verify).toHaveBeenCalledWith(
        'password_reset',
        hmacSha256(`${baseDto.tenantId}:${baseDto.email}`, HMAC_KEY),
        '654321'
      )
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u3')
      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('u3')
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when no proof field is present (otp method).
    it('throws PASSWORD_RESET_TOKEN_INVALID when no proof field is present (otp method)', async () => {
      // Arrange
      const dto = { ...baseDto }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that propagates OTP_INVALID from OtpService.verify in direct OTP path.
    it('propagates OTP_INVALID from OtpService.verify in direct OTP path', async () => {
      // Arrange
      mockOtpService.verify.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_INVALID))
      const dto = { ...baseDto, otp: '000000' }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when user disappears between OTP verification and password update (direct OTP path).
    it('throws PASSWORD_RESET_TOKEN_INVALID when user disappears between OTP verification and password update (direct OTP path)', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)
      const dto = { ...baseDto, otp: '123456' }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })
  })

  // =========================================================================
  // verifyOtp
  // =========================================================================

  describe('verifyOtp', () => {
    const dto = { email: 'user@example.com', tenantId: 'tenant1', otp: '123456' }

    // Verifies that propagates OTP errors from OtpService.verify.
    it('propagates OTP errors from OtpService.verify', async () => {
      // Arrange
      mockOtpService.verify.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_EXPIRED))

      // Act
      let caught: unknown
      try {
        await service.verifyOtp(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_EXPIRED)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when user not found after OTP verification.
    it('throws PASSWORD_RESET_TOKEN_INVALID when user not found after OTP verification', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      let caught: unknown
      try {
        await service.verifyOtp(dto, mockReq)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that returns a 64-character hex string on success.
    it('returns a 64-character hex string on success', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      const result = await service.verifyOtp(dto, mockReq)

      // Assert
      expect(typeof result).toBe('string')
      expect(result).toHaveLength(64)
      expect(result).toMatch(/^[0-9a-f]{64}$/)
    })

    // Verifies that stores the verifiedToken in Redis with correct key prefix and 300s TTL.
    it('stores the verifiedToken in Redis with correct key prefix and 300s TTL', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await service.verifyOtp(dto, mockReq)

      // Assert
      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const [key, , ttl] = mockRedis.set.mock.calls[0]! as [string, string, number]
      expect(key).toMatch(/^pw_vtok:/)
      expect(ttl).toBe(300)
    })

    // Verifies that stores context JSON with userId, email, tenantId.
    it('stores context JSON with userId, email, tenantId', async () => {
      // Arrange
      mockOtpService.verify.mockResolvedValue(undefined)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await service.verifyOtp(dto, mockReq)

      // Assert
      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const [, contextJson] = mockRedis.set.mock.calls[0]! as [string, string, number]
      const context = JSON.parse(contextJson) as { userId: string; email: string; tenantId: string }
      expect(context.userId).toBe('u1')
      expect(context.email).toBe(dto.email)
      expect(context.tenantId).toBe(dto.tenantId)
    })
  })

  // =========================================================================
  // resendOtp
  // =========================================================================

  // Note: `resendOtp` only applies when method='otp'. This describe uses `otpMethodService`,
  // not the outer `service` (which uses method='token'). The outer beforeEach still runs first
  // — clearing mocks and setting defaults — then this inner beforeEach builds the OTP module.
  describe('resendOtp', () => {
    let otpMethodService: PasswordResetService
    const dto = { email: 'user@example.com', tenantId: 'tenant1' }

    beforeEach(async () => {
      const optionsWithOtp = {
        ...mockOptions,
        passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
      }
      const module = await Test.createTestingModule({
        providers: [
          PasswordResetService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: OtpService, useValue: mockOtpService },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: AuthRedisService, useValue: mockRedis }
        ]
      }).compile()
      otpMethodService = module.get(PasswordResetService)
    })

    // Verifies that does NOT throw when user not found (anti-enumeration).
    it('does NOT throw when user not found (anti-enumeration)', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is blocked.
    it('does NOT throw when user is blocked', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'banned' })

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when cooldown is active (setnx returns false).
    it('does NOT throw when cooldown is active (setnx returns false)', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto, mockReq)).resolves.toBeUndefined()
    })

    // Verifies that does NOT send OTP when cooldown is active.
    it('does NOT send OTP when cooldown is active', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockOtpService.generate).not.toHaveBeenCalled()
      expect(mockOtpService.store).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
    })

    // Scenario: cooldown is active (setnx=false) AND the user exists and is eligible; expected:
    // the method returns early WITHOUT generating/sending an OTP. Why: prior cooldown tests left
    // findByEmail=null, so even if `if (!wasSet)` were neutered the null user would prevent a
    // send — masking the guard. With an active user, dropping the early return (`if(false)` or
    // `{}`) would proceed into the try block and send an OTP. Asserting no generate fires kills both.
    it('returns early without generating an OTP when cooldown is active even if the user exists', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockUserRepo.findByEmail).not.toHaveBeenCalled()
      expect(mockOtpService.generate).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
    })

    // Scenario: a resend attempt; expected: the cooldown is registered under a
    // `resend:password_reset:<hmac>` NX key with a 60-second TTL. Why: pins the cooldown key
    // template — emptying it (`''`) or emptying PASSWORD_RESET_PURPOSE / the otpIdentifier message
    // would collide all users onto one cooldown key, breaking per-account flood protection.
    it('registers the cooldown under resend:password_reset:{identifier} with a 60s TTL', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      const [key, ttl] = mockRedis.setnx.mock.calls[0] as [string, number]
      const expectedIdentifier = hmacSha256(`${dto.tenantId}:${dto.email}`, HMAC_KEY)
      expect(key).toBe(`resend:password_reset:${expectedIdentifier}`)
      expect(ttl).toBe(60)
    })

    // Verifies that sends OTP when cooldown not active and user found and not blocked.
    it('sends OTP when cooldown not active and user found and not blocked', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(mockOtpService.generate).toHaveBeenCalledTimes(1)
      expect(mockOtpService.store).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendPasswordResetOtp).toHaveBeenCalledTimes(1)
    })

    // Verifies that applies timing normalization — calls sleep.
    it('applies timing normalization — calls sleep', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Verifies that applies timing normalization even when cooldown is active.
    it('applies timing normalization even when cooldown is active', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Scenario: cooldown active, 100 ms elapsed; expected: the cooldown-branch sleep uses the
    // remaining budget max(0, 300 - 100) = 200. Why: pins that branch's formula — Math.min -> 0,
    // `300 + elapsed` -> 400, `now + start` -> huge negative -> 0. Only the original yields 200.
    it('sleeps for the remaining budget on the cooldown-active branch', async () => {
      // Arrange — first Date.now() is `start`, later calls are 100 ms after.
      mockRedis.setnx.mockResolvedValue(false)
      const nowSpy = jest.spyOn(Date, 'now')
      nowSpy.mockReturnValue(2_000_100)
      nowSpy.mockReturnValueOnce(2_000_000)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledWith(200)
      nowSpy.mockRestore()
    })

    // Scenario: cooldown NOT active, user not found, 100 ms elapsed; expected: the finally-block
    // sleep uses max(0, 300 - 100) = 200. Why: pins the main-path timing formula (same mutants as
    // the cooldown branch, different call site).
    it('sleeps for the remaining budget in the finally block (cooldown not active)', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue(null)
      const nowSpy = jest.spyOn(Date, 'now')
      nowSpy.mockReturnValue(3_000_100)
      nowSpy.mockReturnValueOnce(3_000_000)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(mockSleep).toHaveBeenCalledWith(200)
      nowSpy.mockRestore()
    })

    // Verifies that logs error on unexpected error inside resendOtp.
    it('logs error on unexpected error inside resendOtp', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      const unexpectedError = new Error('Unexpected failure')
      mockUserRepo.findByEmail.mockRejectedValue(unexpectedError)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)

      // Assert
      expect(errorSpy).toHaveBeenCalledWith('resendOtp: unexpected error', unexpectedError)
      errorSpy.mockRestore()
    })

    // Verifies that resendOtp logs a warning and skips the email send when no email provider is configured.
    it('skips email and logs warn when no email provider is configured (sendOtp null path)', async () => {
      // Arrange: build OTP service with null email provider
      const optionsWithOtp = {
        ...mockOptions,
        passwordReset: { ...mockOptions.passwordReset, method: 'otp' as const }
      }
      const noEmailModule = await Test.createTestingModule({
        providers: [
          PasswordResetService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWithOtp },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: null },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: OtpService, useValue: mockOtpService },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: AuthRedisService, useValue: mockRedis }
        ]
      }).compile()
      const noEmailOtpService = noEmailModule.get(PasswordResetService)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await noEmailOtpService.resendOtp(dto, mockReq)

      // Assert
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('no email provider configured'))
      warnSpy.mockRestore()
    })

    // Verifies that a rejection from sendPasswordResetOtp is caught and logged without propagating to the caller.
    it('logs error when sendPasswordResetOtp fire-and-forget rejects', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })
      mockEmailProvider.sendPasswordResetOtp.mockRejectedValue(new Error('SMTP down'))
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await otpMethodService.resendOtp(dto, mockReq)
      await flushMicrotasks()

      // Assert
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('sendPasswordResetOtp failed'),
        expect.any(Error)
      )
      errorSpy.mockRestore()
    })
  })

  // =========================================================================
  // afterPasswordReset hook
  // =========================================================================

  describe('afterPasswordReset hook', () => {
    const FULL_USER = {
      id: 'u1',
      email: 'user@example.com',
      tenantId: 'tenant1',
      name: 'Test User',
      role: 'member',
      status: 'active',
      emailVerified: true,
      mfaEnabled: false,
      passwordHash: 'secret',
      mfaSecret: null,
      mfaRecoveryCodes: null,
      lastLoginAt: null,
      createdAt: new Date()
    }

    // Verifies that afterPasswordReset is called once after a successful reset and receives a SafeAuthUser with credential fields stripped.
    it('fires afterPasswordReset hook after successful password reset', async () => {
      // Arrange: build service with hooks injected
      const module = await buildModule(mockEmailProvider, mockHooks)
      const hookedService = module.get(PasswordResetService)
      const validContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(validContext)
      mockUserRepo.findById.mockResolvedValue(FULL_USER)

      // Act
      await hookedService.resetPassword(
        {
          email: 'user@example.com',
          tenantId: 'tenant1',
          newPassword: 'NewPass123!',
          token: 'tok'
        },
        mockReq
      )
      await flushMicrotasks()

      // Assert
      expect(mockHooks.afterPasswordReset).toHaveBeenCalledTimes(1)
      // Verify credential fields are stripped from the hook argument
      const [hookUser] = mockHooks.afterPasswordReset.mock.calls[0]! as [Record<string, unknown>]
      expect(hookUser['passwordHash']).toBeUndefined()
      expect(hookUser['mfaSecret']).toBeUndefined()
      expect(hookUser['id']).toBe('u1')
    })

    // Verifies that afterPasswordReset is not called when findById returns null after the reset.
    it('does not fire hook when findById returns null after reset', async () => {
      // Arrange
      const module = await buildModule(mockEmailProvider, mockHooks)
      const hookedService = module.get(PasswordResetService)
      const validContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(validContext)
      mockUserRepo.findById.mockResolvedValue(null)

      // Act
      await hookedService.resetPassword(
        {
          email: 'user@example.com',
          tenantId: 'tenant1',
          newPassword: 'NewPass123!',
          token: 'tok'
        },
        mockReq
      )
      await flushMicrotasks()

      // Assert
      expect(mockHooks.afterPasswordReset).not.toHaveBeenCalled()
    })

    // Verifies that a rejection from the afterPasswordReset hook is caught and logged without propagating to the caller.
    it('logs error and does not throw when afterPasswordReset hook throws', async () => {
      // Arrange
      const module = await buildModule(mockEmailProvider, mockHooks)
      const hookedService = module.get(PasswordResetService)
      const validContext = JSON.stringify({
        userId: 'u1',
        email: 'user@example.com',
        tenantId: 'tenant1'
      })
      mockRedis.getdel.mockResolvedValue(validContext)
      mockUserRepo.findById.mockResolvedValue(FULL_USER)
      mockHooks.afterPasswordReset.mockRejectedValue(new Error('hook failure'))
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await hookedService.resetPassword(
        {
          email: 'user@example.com',
          tenantId: 'tenant1',
          newPassword: 'NewPass123!',
          token: 'tok'
        },
        mockReq
      )
      await flushMicrotasks()

      // Assert
      expect(errorSpy).toHaveBeenCalledWith('afterPasswordReset hook threw', expect.any(Error))
      errorSpy.mockRestore()
    })
  })
})
