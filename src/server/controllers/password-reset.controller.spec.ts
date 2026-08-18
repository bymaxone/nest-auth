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
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import type { ChangePasswordDto } from '../dto/change-password.dto'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { PasswordResetService } from '../services/password-reset.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

const mockTokenDelivery = {
  extractRefreshToken: jest.fn()
}
import { PasswordResetController } from './password-reset.controller'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import type { Request } from 'express'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const mockPasswordResetService = {
  initiateReset: jest.fn(),
  resetPassword: jest.fn(),
  changePassword: jest.fn(),
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

/** A minimal request double — the controller only forwards it to the service. */
const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser' }
} as unknown as Request

describe('PasswordResetController', () => {
  let controller: PasswordResetController

  beforeEach(async () => {
    jest.clearAllMocks()

    const module: TestingModule = await Test.createTestingModule({
      controllers: [PasswordResetController],
      providers: [
        { provide: PasswordResetService, useValue: mockPasswordResetService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery }
      ]
    })
      .overrideGuard(TrustedOriginGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AuthRateLimitGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(UserStatusGuard)
      .useValue({ canActivate: () => true })
      .compile()

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
  // Neither class-level guard authorizes anything: one refuses a cross-site state-changing
  // request riding in on the session cookie, the other enforces the per-IP limit. Every route
  // here stays public — a password reset is performed by someone who cannot authenticate.
  it('applies only the origin and rate-limit guards at the controller level', () => {
    const guards = Reflect.getMetadata(GUARDS_METADATA, PasswordResetController) as unknown[]

    expect(guards).toEqual([TrustedOriginGuard, AuthRateLimitGuard])
  })

  // ---------------------------------------------------------------------------
  // forgotPassword
  // ---------------------------------------------------------------------------

  describe('forgotPassword', () => {
    const dto: ForgotPasswordDto = { email: 'user@example.com', tenantId: 'tenant-1' }

    // Verifies that forgotPassword delegates to passwordResetService.initiateReset with the DTO unchanged.
    it('should delegate to passwordResetService.initiateReset with the dto', async () => {
      mockPasswordResetService.initiateReset.mockResolvedValue(undefined)

      await controller.forgotPassword(dto, mockReq)

      expect(mockPasswordResetService.initiateReset).toHaveBeenCalledWith(dto, mockReq)
      expect(mockPasswordResetService.initiateReset).toHaveBeenCalledTimes(1)
    })
  })

  // ---------------------------------------------------------------------------
  // changePassword
  // ---------------------------------------------------------------------------

  describe('changePassword', () => {
    const dto: ChangePasswordDto = {
      currentPassword: 'the-old-one',
      newPassword: 'gliding-walnut-forecast'
    }

    // The caller's own subject decides whose password changes — never the body. A change that
    // took an id from the request would let anyone holding any session rewrite any account's
    // credential, which is the whole of account takeover in one route.
    it('should change the password of the authenticated caller, not of anyone the body names', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue('current-refresh')
      mockPasswordResetService.changePassword.mockResolvedValue(undefined)

      await controller.changePassword(
        { sub: 'user-1', tenantId: 'tenant-1' } as DashboardJwtPayload,
        dto,
        mockReq
      )

      expect(mockPasswordResetService.changePassword).toHaveBeenCalledWith(
        'user-1',
        // The tenant is read from the same verified claims as the subject — the body cannot
        // name it either.
        'tenant-1',
        dto,
        // The caller's own refresh token rides along so the service can spare THIS session
        // while ending every other one. Without it the user is signed out of the device they
        // just changed their password on, which reads as the change having failed.
        'current-refresh'
      )
    })

    // A bearer-mode caller sends no refresh cookie. The change still has to work — it just has
    // no session to spare, so every session including this one ends.
    it('should pass an absent refresh token through unchanged', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue(undefined)
      mockPasswordResetService.changePassword.mockResolvedValue(undefined)

      await controller.changePassword(
        { sub: 'user-1', tenantId: 'tenant-1' } as DashboardJwtPayload,
        dto,
        mockReq
      )

      expect(mockPasswordResetService.changePassword).toHaveBeenCalledWith(
        'user-1',
        'tenant-1',
        dto,
        undefined
      )
    })

    // 204: the route answers with nothing, so a client cannot read anything about the account
    // out of a successful change.
    it('should return undefined (HTTP 204 No Content)', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue('current-refresh')
      mockPasswordResetService.changePassword.mockResolvedValue(undefined)

      await expect(
        controller.changePassword(
          { sub: 'user-1', tenantId: 'tenant-1' } as DashboardJwtPayload,
          dto,
          mockReq
        )
      ).resolves.toBeUndefined()
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

      await controller.resetPassword(dto, mockReq)

      expect(mockPasswordResetService.resetPassword).toHaveBeenCalledWith(dto, mockReq)
      expect(mockPasswordResetService.resetPassword).toHaveBeenCalledTimes(1)
    })

    // Verifies that PASSWORD_RESET_TOKEN_INVALID thrown by the service propagates to the caller unchanged.
    it('should propagate PASSWORD_RESET_TOKEN_INVALID from service', async () => {
      mockPasswordResetService.resetPassword.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
      )

      let caught: unknown
      try {
        await controller.resetPassword(dto, mockReq)
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
        await controller.resetPassword({ ...dto, otp: '123456' }, mockReq)
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
        await controller.resetPassword({ ...dto, otp: '123456' }, mockReq)
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
        await controller.resetPassword({ ...dto, otp: '123456' }, mockReq)
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

      await controller.verifyOtp(dto, mockReq)

      expect(mockPasswordResetService.verifyOtp).toHaveBeenCalledWith(dto, mockReq)
      expect(mockPasswordResetService.verifyOtp).toHaveBeenCalledTimes(1)
    })

    // Verifies that the raw token from the service is wrapped in { verifiedToken } with no extra keys.
    it('should return the verifiedToken wrapped in an object', async () => {
      const rawToken = 'c'.repeat(64)
      mockPasswordResetService.verifyOtp.mockResolvedValue(rawToken)

      const result = await controller.verifyOtp(dto, mockReq)

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
        await controller.verifyOtp(dto, mockReq)
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
        await controller.verifyOtp(dto, mockReq)
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
        await controller.verifyOtp(dto, mockReq)
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

      await controller.resendOtp(dto, mockReq)

      expect(mockPasswordResetService.resendOtp).toHaveBeenCalledWith(dto, mockReq)
      expect(mockPasswordResetService.resendOtp).toHaveBeenCalledTimes(1)
    })
  })
})
