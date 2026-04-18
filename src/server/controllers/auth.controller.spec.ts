/**
 * @fileoverview Tests for AuthController, which provides thin HTTP endpoints
 * delegating to AuthService and TokenDeliveryService for all authentication flows.
 */

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { AuthService } from '../services/auth.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { AuthController } from './auth.controller'

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

const AUTH_RESULT = {
  user: SAFE_USER,
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh-token'
}

const ROTATED_RESULT = {
  session: { userId: 'user-1', tenantId: 'tenant-1', role: 'member' },
  accessToken: 'new.access.jwt',
  rawRefreshToken: 'new-raw-refresh'
}

const JWT_PAYLOAD = {
  jti: 'test-jti',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard',
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

const mockAuthService = {
  register: jest.fn(),
  login: jest.fn(),
  logout: jest.fn(),
  refresh: jest.fn(),
  getMe: jest.fn(),
  verifyEmail: jest.fn(),
  resendVerificationEmail: jest.fn()
}

const mockTokenDelivery = {
  deliverAuthResponse: jest.fn(),
  deliverRefreshResponse: jest.fn(),
  extractAccessToken: jest.fn(),
  extractRefreshToken: jest.fn(),
  clearAuthSession: jest.fn()
}

const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser' },
  cookies: {}
} as unknown as Request

const mockRes = {
  cookie: jest.fn(),
  clearCookie: jest.fn()
} as unknown as Response

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('AuthController', () => {
  let controller: AuthController

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery }
      ]
    })
      // Override guards applied via @UseGuards() — unit tests should not instantiate guard deps.
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile()

    controller = module.get(AuthController)
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

    // Verifies that register delegates to authService and delivers the auth result as a response.
    it('should call authService.register and deliver auth response', async () => {
      mockAuthService.register.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })

      await controller.register(dto as never, mockReq, mockRes)

      expect(mockAuthService.register).toHaveBeenCalledWith(dto, mockReq)
      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        AUTH_RESULT,
        mockReq
      )
    })

    // Verifies that the controller returns exactly what deliverAuthResponse returns.
    it('should return the result of deliverAuthResponse', async () => {
      const expected = { user: SAFE_USER }
      mockAuthService.register.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue(expected)

      const result = await controller.register(dto as never, mockReq, mockRes)
      expect(result).toBe(expected)
    })
  })

  // ---------------------------------------------------------------------------
  // login
  // ---------------------------------------------------------------------------

  describe('login', () => {
    const dto = { email: 'user@example.com', password: 'correct', tenantId: 'tenant-1' }

    // Verifies that a successful login delivers the auth response through TokenDeliveryService.
    it('should deliver auth response for a normal login', async () => {
      mockAuthService.login.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })

      const result = await controller.login(dto as never, mockReq, mockRes)

      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        AUTH_RESULT,
        mockReq
      )
      expect(result).toEqual({ user: SAFE_USER })
    })

    // Verifies that an MFA challenge result is returned directly without setting cookies or tokens.
    it('should return MfaChallengeResult directly without delivering tokens', async () => {
      const mfaResult = { mfaRequired: true as const, mfaTempToken: 'mfa.token' }
      mockAuthService.login.mockResolvedValue(mfaResult)

      const result = await controller.login(dto as never, mockReq, mockRes)

      expect(result).toBe(mfaResult)
      expect(mockTokenDelivery.deliverAuthResponse).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // logout
  // ---------------------------------------------------------------------------

  describe('logout', () => {
    // Verifies that logout extracts both tokens, calls authService.logout, and clears cookies.
    it('should extract tokens, call logout, and clear session', async () => {
      mockTokenDelivery.extractAccessToken.mockReturnValue('access.jwt')
      mockTokenDelivery.extractRefreshToken.mockReturnValue('raw-refresh-token')
      mockAuthService.logout.mockResolvedValue(undefined)
      mockTokenDelivery.clearAuthSession.mockReturnValue(undefined)

      await controller.logout(JWT_PAYLOAD as never, mockReq, mockRes)

      expect(mockTokenDelivery.extractAccessToken).toHaveBeenCalledWith(mockReq)
      expect(mockTokenDelivery.extractRefreshToken).toHaveBeenCalledWith(mockReq)
      expect(mockAuthService.logout).toHaveBeenCalledWith(
        'access.jwt',
        'raw-refresh-token',
        JWT_PAYLOAD.sub
      )
      expect(mockTokenDelivery.clearAuthSession).toHaveBeenCalledWith(mockRes, mockReq)
    })

    // Verifies that logout uses empty strings when tokens are not found, avoiding undefined arguments.
    it('should use empty strings when tokens are not found (graceful fallback)', async () => {
      mockTokenDelivery.extractAccessToken.mockReturnValue(undefined)
      mockTokenDelivery.extractRefreshToken.mockReturnValue(undefined)
      mockAuthService.logout.mockResolvedValue(undefined)
      mockTokenDelivery.clearAuthSession.mockReturnValue(undefined)

      await controller.logout(JWT_PAYLOAD as never, mockReq, mockRes)

      expect(mockAuthService.logout).toHaveBeenCalledWith('', '', JWT_PAYLOAD.sub)
    })
  })

  // ---------------------------------------------------------------------------
  // refresh
  // ---------------------------------------------------------------------------

  describe('refresh', () => {
    // Verifies that refresh rotates the token, fetches the user, and delivers new tokens.
    it('should rotate refresh token, fetch user, and deliver new tokens', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue('old-refresh')
      mockAuthService.refresh.mockResolvedValue(ROTATED_RESULT)
      mockAuthService.getMe.mockResolvedValue(SAFE_USER)
      mockTokenDelivery.deliverRefreshResponse.mockReturnValue({ user: SAFE_USER })

      const result = await controller.refresh(mockReq, mockRes)

      expect(mockAuthService.refresh).toHaveBeenCalledWith('old-refresh', '1.2.3.4', 'TestBrowser')
      expect(mockAuthService.getMe).toHaveBeenCalledWith(ROTATED_RESULT.session.userId)
      expect(mockTokenDelivery.deliverRefreshResponse).toHaveBeenCalledWith(
        mockRes,
        {
          user: SAFE_USER,
          accessToken: ROTATED_RESULT.accessToken,
          rawRefreshToken: ROTATED_RESULT.rawRefreshToken
        },
        mockReq
      )
      expect(result).toEqual({ user: SAFE_USER })
    })

    // Verifies that refresh falls back to empty strings when req.ip, user-agent, and the refresh token are undefined.
    it('should call authService.refresh with empty strings when req.ip, user-agent, and refresh token are undefined', async () => {
      const reqWithoutMeta = {
        ip: undefined,
        headers: {},
        cookies: {}
      } as unknown as Request

      // Return undefined to exercise the ?? '' fallback on extractRefreshToken
      mockTokenDelivery.extractRefreshToken.mockReturnValue(undefined)
      mockAuthService.refresh.mockResolvedValue(ROTATED_RESULT)
      mockAuthService.getMe.mockResolvedValue(SAFE_USER)
      mockTokenDelivery.deliverRefreshResponse.mockReturnValue({ user: SAFE_USER })

      await controller.refresh(reqWithoutMeta, mockRes)

      expect(mockAuthService.refresh).toHaveBeenCalledWith('', '', '')
    })
  })

  // ---------------------------------------------------------------------------
  // me
  // ---------------------------------------------------------------------------

  describe('me', () => {
    // Verifies that the me endpoint returns the safe user object for the authenticated user.
    it('should return the safe user for the authenticated user', async () => {
      mockAuthService.getMe.mockResolvedValue(SAFE_USER)

      const result = await controller.me(JWT_PAYLOAD as never)

      expect(mockAuthService.getMe).toHaveBeenCalledWith(JWT_PAYLOAD.sub)
      expect(result).toBe(SAFE_USER)
    })

    // Verifies that TOKEN_INVALID is propagated when the authenticated user no longer exists.
    it('should propagate TOKEN_INVALID when user is not found', async () => {
      mockAuthService.getMe.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID))

      await expect(controller.me(JWT_PAYLOAD as never)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // verifyEmail
  // ---------------------------------------------------------------------------

  describe('verifyEmail', () => {
    const body = {
      tenantId: 'tenant-1',
      email: 'user@example.com',
      otp: '123456'
    }

    // Verifies that verifyEmail delegates to authService with (tenantId, email, otp) only.
    it('should call verifyEmail without accepting a client-supplied userId', async () => {
      mockAuthService.verifyEmail.mockResolvedValue(undefined)

      await controller.verifyEmail(body as never)

      expect(mockAuthService.verifyEmail).toHaveBeenCalledWith(body.tenantId, body.email, body.otp)
    })

    // Verifies that OTP validation errors from the service are propagated to the caller.
    it('should propagate OTP errors from the service', async () => {
      mockAuthService.verifyEmail.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.OTP_INVALID))

      await expect(controller.verifyEmail(body as never)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // resendVerification
  // ---------------------------------------------------------------------------

  describe('resendVerification', () => {
    const body = { tenantId: 'tenant-1', email: 'user@example.com' }

    // Verifies that resendVerification delegates to authService with tenantId and email.
    it('should call resendVerificationEmail with tenantId and email', async () => {
      mockAuthService.resendVerificationEmail.mockResolvedValue(undefined)

      await controller.resendVerification(body as never)

      expect(mockAuthService.resendVerificationEmail).toHaveBeenCalledWith(
        body.tenantId,
        body.email
      )
    })

    // Verifies that resendVerification always resolves to prevent email enumeration.
    it('should always resolve regardless of whether email exists (anti-enumeration)', async () => {
      mockAuthService.resendVerificationEmail.mockResolvedValue(undefined)

      await expect(controller.resendVerification(body as never)).resolves.toBeUndefined()
    })
  })
})
