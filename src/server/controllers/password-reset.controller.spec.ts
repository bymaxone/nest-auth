/**
 * @fileoverview Tests for PasswordResetController, which provides thin HTTP
 * endpoints delegating to PasswordResetService for all password-reset flows.
 */

import { GUARDS_METADATA } from '@nestjs/common/constants'
import { Test, type TestingModule } from '@nestjs/testing'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { IS_PUBLIC_KEY } from '../decorators/public.decorator'
import type { ForgotPasswordDto } from '../dto/forgot-password.dto'
import type { ResendOtpDto } from '../dto/resend-otp.dto'
import type { ResetPasswordDto } from '../dto/reset-password.dto'
import type { VerifyOtpDto } from '../dto/verify-otp.dto'
import { PasswordResetService } from '../services/password-reset.service'
import { PasswordResetController } from './password-reset.controller'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const mockPasswordResetService = {
  initiateReset: jest.fn(),
  resetPassword: jest.fn(),
  verifyOtp: jest.fn(),
  resendOtp: jest.fn()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getErrorCode(err: unknown): string {
  if (!(err instanceof AuthException)) throw new Error('Not an AuthException')
  const res = err.getResponse() as { error?: { code?: string } }
  return res.error?.code ?? ''
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('PasswordResetController', () => {
  let controller: PasswordResetController

  beforeEach(async () => {
    jest.clearAllMocks()

    const module: TestingModule = await Test.createTestingModule({
      controllers: [PasswordResetController],
      providers: [{ provide: PasswordResetService, useValue: mockPasswordResetService }]
    }).compile()

    controller = module.get(PasswordResetController)
  })

  // ---------------------------------------------------------------------------
  // Class-level metadata
  // ---------------------------------------------------------------------------

  // Verifies that the controller is decorated with @Public() so unauthenticated callers can access password-reset endpoints.
  it('should be decorated with @Public()', () => {
    const isPublic: unknown = Reflect.getMetadata(IS_PUBLIC_KEY, PasswordResetController)
    expect(isPublic).toBe(true)
  })

  // Verifies that no access guards are attached at the controller level because @Public() marks it as open.
  it('should not have guards metadata at the controller level', () => {
    const guards: unknown = Reflect.getMetadata(GUARDS_METADATA, PasswordResetController)
    expect(guards).toBeUndefined()
  })

  // ---------------------------------------------------------------------------
  // forgotPassword
  // ---------------------------------------------------------------------------

  describe('forgotPassword', () => {
    const dto: ForgotPasswordDto = { email: 'user@example.com', tenantId: 'tenant-1' }

    // Verifies that forgotPassword delegates to passwordResetService.initiateReset with the DTO unchanged.
    it('should delegate to passwordResetService.initiateReset with the dto', async () => {
      mockPasswordResetService.initiateReset.mockResolvedValue(undefined)

      await controller.forgotPassword(dto)

      expect(mockPasswordResetService.initiateReset).toHaveBeenCalledWith(dto)
      expect(mockPasswordResetService.initiateReset).toHaveBeenCalledTimes(1)
    })
  })

  // ---------------------------------------------------------------------------
  // resetPassword
  // ---------------------------------------------------------------------------

  describe('resetPassword', () => {
    const dto: ResetPasswordDto = {
      email: 'user@example.com',
      tenantId: 'tenant-1',
      newPassword: 'NewPass123!'
    }

    // Verifies that resetPassword delegates to passwordResetService.resetPassword with the DTO unchanged.
    it('should delegate to passwordResetService.resetPassword with the dto', async () => {
      mockPasswordResetService.resetPassword.mockResolvedValue(undefined)

      await controller.resetPassword(dto)

      expect(mockPasswordResetService.resetPassword).toHaveBeenCalledWith(dto)
      expect(mockPasswordResetService.resetPassword).toHaveBeenCalledTimes(1)
    })

    // Verifies that PASSWORD_RESET_TOKEN_INVALID thrown by the service propagates to the caller unchanged.
    it('should propagate PASSWORD_RESET_TOKEN_INVALID from service', async () => {
      mockPasswordResetService.resetPassword.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      )

      let caught: unknown
      try {
        await controller.resetPassword(dto)
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
    })

    // Verifies that OTP_INVALID thrown by the service on the direct OTP path propagates to the caller unchanged.
    it('should propagate OTP_INVALID from service', async () => {
      mockPasswordResetService.resetPassword.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
      )

      let caught: unknown
      try {
        await controller.resetPassword({ ...dto, otp: '123456' })
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
    })

    // Verifies that OTP_EXPIRED thrown by the service on the direct OTP path propagates to the caller unchanged.
    it('should propagate OTP_EXPIRED from service', async () => {
      mockPasswordResetService.resetPassword.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OTP_EXPIRED)
      )

      let caught: unknown
      try {
        await controller.resetPassword({ ...dto, otp: '123456' })
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_EXPIRED)
    })

    // Verifies that OTP_MAX_ATTEMPTS thrown by the service on the direct OTP path propagates to the caller unchanged.
    it('should propagate OTP_MAX_ATTEMPTS from service', async () => {
      mockPasswordResetService.resetPassword.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OTP_MAX_ATTEMPTS)
      )

      let caught: unknown
      try {
        await controller.resetPassword({ ...dto, otp: '123456' })
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_MAX_ATTEMPTS)
    })
  })

  // ---------------------------------------------------------------------------
  // verifyOtp
  // ---------------------------------------------------------------------------

  describe('verifyOtp', () => {
    const dto: VerifyOtpDto = { email: 'user@example.com', tenantId: 'tenant-1', otp: '123456' }

    // Verifies that verifyOtp delegates to passwordResetService.verifyOtp with the DTO unchanged.
    it('should delegate to passwordResetService.verifyOtp with the dto', async () => {
      mockPasswordResetService.verifyOtp.mockResolvedValue('a'.repeat(64))

      await controller.verifyOtp(dto)

      expect(mockPasswordResetService.verifyOtp).toHaveBeenCalledWith(dto)
      expect(mockPasswordResetService.verifyOtp).toHaveBeenCalledTimes(1)
    })

    // Verifies that the raw token from the service is wrapped in { verifiedToken } with no extra keys.
    it('should return the verifiedToken wrapped in an object', async () => {
      const rawToken = 'c'.repeat(64)
      mockPasswordResetService.verifyOtp.mockResolvedValue(rawToken)

      const result = await controller.verifyOtp(dto)

      expect(result).toEqual({ verifiedToken: rawToken })
      expect(Object.keys(result)).toEqual(['verifiedToken'])
    })

    // Verifies that OTP_INVALID thrown by the service propagates to the caller unchanged.
    it('should propagate OTP_INVALID from service', async () => {
      mockPasswordResetService.verifyOtp.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OTP_INVALID)
      )

      let caught: unknown
      try {
        await controller.verifyOtp(dto)
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
    })

    // Verifies that OTP_EXPIRED thrown by the service propagates to the caller unchanged.
    it('should propagate OTP_EXPIRED from service', async () => {
      mockPasswordResetService.verifyOtp.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OTP_EXPIRED)
      )

      let caught: unknown
      try {
        await controller.verifyOtp(dto)
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_EXPIRED)
    })

    // Verifies that OTP_MAX_ATTEMPTS thrown by the service propagates to the caller unchanged.
    it('should propagate OTP_MAX_ATTEMPTS from service', async () => {
      mockPasswordResetService.verifyOtp.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OTP_MAX_ATTEMPTS)
      )

      let caught: unknown
      try {
        await controller.verifyOtp(dto)
      } catch (err) {
        caught = err
      }

      expect(getErrorCode(caught)).toBe(AUTH_ERROR_CODES.OTP_MAX_ATTEMPTS)
    })
  })

  // ---------------------------------------------------------------------------
  // resendOtp
  // ---------------------------------------------------------------------------

  describe('resendOtp', () => {
    const dto: ResendOtpDto = { email: 'user@example.com', tenantId: 'tenant-1' }

    // Verifies that resendOtp delegates to passwordResetService.resendOtp with the DTO unchanged.
    it('should delegate to passwordResetService.resendOtp with the dto', async () => {
      mockPasswordResetService.resendOtp.mockResolvedValue(undefined)

      await controller.resendOtp(dto)

      expect(mockPasswordResetService.resendOtp).toHaveBeenCalledWith(dto)
      expect(mockPasswordResetService.resendOtp).toHaveBeenCalledTimes(1)
    })
  })
})
