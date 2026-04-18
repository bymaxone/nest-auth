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
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { OtpService } from './otp.service'
import { PasswordResetService } from './password-reset.service'
import { PasswordService } from './password.service'
import { sleep } from '../utils/sleep'

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
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY
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
  hash: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  get: jest.fn(),
  getdel: jest.fn(),
  setnx: jest.fn(),
  invalidateUserSessions: jest.fn()
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
    mockRedis.getdel.mockResolvedValue(null)
    mockRedis.setnx.mockResolvedValue(true)
    mockRedis.invalidateUserSessions.mockResolvedValue(undefined)
    mockSleep.mockResolvedValue(undefined)

    const module = await buildModule()
    service = module.get(PasswordResetService)
  })

  // =========================================================================
  // initiateReset
  // =========================================================================

  describe('initiateReset', () => {
    const dto = { email: 'user@example.com', tenantId: 'tenant1' }

    // Verifies that does NOT throw when user is not found (anti-enumeration).
    it('does NOT throw when user is not found (anti-enumeration)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue(null)

      // Act & Assert
      await expect(service.initiateReset(dto)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is blocked (anti-enumeration).
    it('does NOT throw when user is blocked (anti-enumeration)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'banned' })

      // Act & Assert
      await expect(service.initiateReset(dto)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is suspended (blocked status).
    it('does NOT throw when user is suspended (blocked status)', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'suspended' })

      // Act & Assert
      await expect(service.initiateReset(dto)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw even when email provider throws.
    it('does NOT throw even when email provider throws', async () => {
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
        await expect(service.initiateReset(dto)).resolves.toBeUndefined()
        await flushMicrotasks()
      } finally {
        loggerSpy.mockRestore()
      }
    })

    // Verifies that calls sendToken path (token method) when user exists and is not blocked.
    it('calls sendToken path (token method) when user exists and is not blocked', async () => {
      // Arrange
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await service.initiateReset(dto)
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
      await noEmailService.initiateReset(dto)

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
      await service.initiateReset(dto)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Verifies that logs error when unexpected error occurs during initiation.
    it('logs error when unexpected error occurs during initiation', async () => {
      // Arrange
      const unexpectedError = new Error('Database connection failed')
      mockUserRepo.findByEmail.mockRejectedValue(unexpectedError)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await service.initiateReset(dto)

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
      await service.initiateReset(dto)
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
        await otpMethodService.initiateReset(dto)
        await flushMicrotasks()

        // Assert
        expect(mockOtpService.generate).toHaveBeenCalledTimes(1)
        expect(mockOtpService.store).toHaveBeenCalledTimes(1)
        expect(mockEmailProvider.sendPasswordResetOtp).toHaveBeenCalledTimes(1)
      })

      // Verifies that does NOT send OTP email to blocked user.
      it('does NOT send OTP email to blocked user', async () => {
        // Arrange
        mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'banned' })

        // Act
        await otpMethodService.initiateReset(dto)
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
        await service.resetPassword(dto)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + verifiedToken).
    it('throws PASSWORD_RESET_TOKEN_INVALID when proofCount > 1 (token + verifiedToken)', async () => {
      // Arrange
      const dto = { ...baseDto, token: 'tok', verifiedToken: 'v'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto)
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
        await service.resetPassword(dto)
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
        await service.resetPassword(dto)
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
        await service.resetPassword(dto)
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
        await service.resetPassword(dto)
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
        await service.resetPassword(dto)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is malformed.
    it('throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is malformed', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue('{{{invalid')
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto)
      } catch (err) {
        caught = err
      }

      // Assert
      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is missing required fields.
    it('throws PASSWORD_RESET_TOKEN_INVALID when stored JSON is missing required fields', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(JSON.stringify({ userId: 'u1' }))
      const dto = { ...baseDto, token: 'mytoken' }

      // Act
      let caught: unknown
      try {
        await service.resetPassword(dto)
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
      await service.resetPassword(dto)

      // Assert
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockUserRepo.updatePassword).toHaveBeenCalledWith('u1', '$hashed$')
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u1')
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
        await otpMethodService.resetPassword(dto)
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
      await otpMethodService.resetPassword(dto)

      // Assert
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u2')
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken is consumed (getdel returns null).
    it('throws PASSWORD_RESET_TOKEN_INVALID when verifiedToken is consumed (getdel returns null)', async () => {
      // Arrange
      mockRedis.getdel.mockResolvedValue(null)
      const dto = { ...baseDto, verifiedToken: 'b'.repeat(64) }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto)
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
        await otpMethodService.resetPassword(dto)
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
        await otpMethodService.resetPassword(dto)
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
      await otpMethodService.resetPassword(dto)

      // Assert
      expect(mockOtpService.verify).toHaveBeenCalledTimes(1)
      expect(mockPasswordService.hash).toHaveBeenCalledWith(baseDto.newPassword)
      expect(mockRedis.invalidateUserSessions).toHaveBeenCalledWith('u3')
    })

    // Verifies that throws PASSWORD_RESET_TOKEN_INVALID when no proof field is present (otp method).
    it('throws PASSWORD_RESET_TOKEN_INVALID when no proof field is present (otp method)', async () => {
      // Arrange
      const dto = { ...baseDto }

      // Act
      let caught: unknown
      try {
        await otpMethodService.resetPassword(dto)
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
        await otpMethodService.resetPassword(dto)
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
        await otpMethodService.resetPassword(dto)
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
        await service.verifyOtp(dto)
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
        await service.verifyOtp(dto)
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
      const result = await service.verifyOtp(dto)

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
      await service.verifyOtp(dto)

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
      await service.verifyOtp(dto)

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
      await expect(otpMethodService.resendOtp(dto)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when user is blocked.
    it('does NOT throw when user is blocked', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'banned' })

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto)).resolves.toBeUndefined()
    })

    // Verifies that does NOT throw when cooldown is active (setnx returns false).
    it('does NOT throw when cooldown is active (setnx returns false)', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act & Assert
      await expect(otpMethodService.resendOtp(dto)).resolves.toBeUndefined()
    })

    // Verifies that does NOT send OTP when cooldown is active.
    it('does NOT send OTP when cooldown is active', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act
      await otpMethodService.resendOtp(dto)

      // Assert
      expect(mockOtpService.generate).not.toHaveBeenCalled()
      expect(mockOtpService.store).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendPasswordResetOtp).not.toHaveBeenCalled()
    })

    // Verifies that sends OTP when cooldown not active and user found and not blocked.
    it('sends OTP when cooldown not active and user found and not blocked', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      mockUserRepo.findByEmail.mockResolvedValue({ id: 'u1', status: 'active' })

      // Act
      await otpMethodService.resendOtp(dto)
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
      await otpMethodService.resendOtp(dto)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Verifies that applies timing normalization even when cooldown is active.
    it('applies timing normalization even when cooldown is active', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(false)

      // Act
      await otpMethodService.resendOtp(dto)

      // Assert
      expect(mockSleep).toHaveBeenCalledTimes(1)
    })

    // Verifies that logs error on unexpected error inside resendOtp.
    it('logs error on unexpected error inside resendOtp', async () => {
      // Arrange
      mockRedis.setnx.mockResolvedValue(true)
      const unexpectedError = new Error('Unexpected failure')
      mockUserRepo.findByEmail.mockRejectedValue(unexpectedError)
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act
      await otpMethodService.resendOtp(dto)

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
      await noEmailOtpService.resendOtp(dto)

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
      await otpMethodService.resendOtp(dto)
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
      await hookedService.resetPassword({
        email: 'user@example.com',
        tenantId: 'tenant1',
        newPassword: 'NewPass123!',
        token: 'tok'
      })
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
      await hookedService.resetPassword({
        email: 'user@example.com',
        tenantId: 'tenant1',
        newPassword: 'NewPass123!',
        token: 'tok'
      })
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
      await hookedService.resetPassword({
        email: 'user@example.com',
        tenantId: 'tenant1',
        newPassword: 'NewPass123!',
        token: 'tok'
      })
      await flushMicrotasks()

      // Assert
      expect(errorSpy).toHaveBeenCalledWith('afterPasswordReset hook threw', expect.any(Error))
      errorSpy.mockRestore()
    })
  })
})
