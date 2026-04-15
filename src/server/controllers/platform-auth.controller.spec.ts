/**
 * @fileoverview Tests for PlatformAuthController.
 *
 * Verifies that the controller delegates correctly to PlatformAuthService,
 * MfaService, and TokenDeliveryService without containing any business logic
 * of its own.
 *
 * All service providers are replaced with Jest mocks. JwtPlatformGuard is
 * overridden so tests do not need to instantiate its JWT/Redis dependencies.
 * Controller methods are called directly (bypassing NestJS interceptors, pipes,
 * and middleware), which is the standard NestJS unit-test pattern.
 */

import { Test, type TestingModule } from '@nestjs/testing'
import type { Request } from 'express'

import type { MfaChallengeDto } from '../dto/mfa-challenge.dto'
import type { PlatformLoginDto } from '../dto/platform-login.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { JwtPlatformGuard } from '../guards/jwt-platform.guard'
import type { MfaChallengeResult, PlatformAuthResult } from '../interfaces/auth-result.interface'
import type { PlatformJwtPayload } from '../interfaces/jwt-payload.interface'
import type { SafeAuthPlatformUser } from '../interfaces/platform-user-repository.interface'
import { MfaService } from '../services/mfa.service'
import { PlatformAuthService } from '../services/platform-auth.service'
import type { PlatformBearerAuthResponse } from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { PlatformAuthController } from './platform-auth.controller'

// ---------------------------------------------------------------------------
// Test doubles — fixtures
// ---------------------------------------------------------------------------

const SAFE_ADMIN: SafeAuthPlatformUser = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super_admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  updatedAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01')
}

const PLATFORM_AUTH_RESULT: PlatformAuthResult = {
  admin: SAFE_ADMIN,
  accessToken: 'platform.access.jwt',
  rawRefreshToken: 'platform-raw-refresh-uuid'
}

const PLATFORM_BEARER_RESPONSE: PlatformBearerAuthResponse = {
  admin: SAFE_ADMIN,
  accessToken: 'platform.access.jwt',
  refreshToken: 'platform-raw-refresh-uuid'
}

const MFA_CHALLENGE_RESULT: MfaChallengeResult = {
  mfaRequired: true,
  mfaTempToken: 'platform-mfa-temp-jwt'
}

const JWT_PAYLOAD: PlatformJwtPayload = {
  jti: '00000000-0000-4000-a000-000000000001',
  sub: 'admin-1',
  role: 'super_admin',
  type: 'platform',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

const LOGIN_DTO: PlatformLoginDto = {
  email: 'admin@platform.com',
  password: 'SecureP@ss1'
}

const MFA_CHALLENGE_DTO: MfaChallengeDto = {
  mfaTempToken: 'platform-mfa-temp-jwt',
  code: '123456'
}

// ---------------------------------------------------------------------------
// Mock service factories
// ---------------------------------------------------------------------------

const mockPlatformAuthService = {
  login: jest.fn(),
  getMe: jest.fn(),
  logout: jest.fn(),
  refresh: jest.fn(),
  revokeAllPlatformSessions: jest.fn()
}

const mockMfaService = {
  challenge: jest.fn()
}

const mockTokenDelivery = {
  deliverPlatformAuthResponse: jest.fn(),
  extractPlatformRefreshToken: jest.fn()
}

// ---------------------------------------------------------------------------
// Module builder helper
// ---------------------------------------------------------------------------

async function buildModule(): Promise<TestingModule> {
  return (
    Test.createTestingModule({
      controllers: [PlatformAuthController],
      providers: [
        { provide: PlatformAuthService, useValue: mockPlatformAuthService },
        { provide: MfaService, useValue: mockMfaService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery }
      ]
    })
      // Override guard to avoid instantiating JwtService / Redis / Reflector.
      .overrideGuard(JwtPlatformGuard)
      .useValue({ canActivate: () => true })
      .compile()
  )
}

// ---------------------------------------------------------------------------
// Helper to build an Express request stub
// ---------------------------------------------------------------------------

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    ip: '1.2.3.4',
    headers: { 'user-agent': 'TestClient/1.0' },
    body: {},
    ...overrides
  } as unknown as Request
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('PlatformAuthController', () => {
  let controller: PlatformAuthController

  beforeEach(async () => {
    jest.clearAllMocks()
    const module = await buildModule()
    controller = module.get(PlatformAuthController)
  })

  // ---------------------------------------------------------------------------
  // login — POST /platform/login
  // ---------------------------------------------------------------------------

  describe('login', () => {
    beforeEach(() => {
      mockTokenDelivery.deliverPlatformAuthResponse.mockReturnValue(PLATFORM_BEARER_RESPONSE)
    })

    // Happy path: service returns a PlatformAuthResult → deliverPlatformAuthResponse is called.
    it('should call platformAuthService.login with dto, ip, and truncated userAgent, then return deliverPlatformAuthResponse result', async () => {
      mockPlatformAuthService.login.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const req = makeReq({ ip: '10.0.0.1', headers: { 'user-agent': 'Mozilla/5.0' } })

      const result = await controller.login(LOGIN_DTO, req)

      expect(mockPlatformAuthService.login).toHaveBeenCalledWith(
        LOGIN_DTO,
        '10.0.0.1',
        'Mozilla/5.0'
      )
      expect(mockTokenDelivery.deliverPlatformAuthResponse).toHaveBeenCalledWith(
        PLATFORM_AUTH_RESULT
      )
      expect(result).toBe(PLATFORM_BEARER_RESPONSE)
    })

    // User-Agent must be capped at 512 characters to prevent storage amplification in Redis.
    it('should truncate User-Agent to 512 characters before passing it to the service', async () => {
      mockPlatformAuthService.login.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const longUserAgent = 'A'.repeat(600)
      const req = makeReq({ headers: { 'user-agent': longUserAgent } })

      await controller.login(LOGIN_DTO, req)

      const [, , uaArg] = mockPlatformAuthService.login.mock.calls[0] as [
        PlatformLoginDto,
        string,
        string
      ]
      expect(uaArg).toHaveLength(512)
      expect(uaArg).toBe('A'.repeat(512))
    })

    // MFA path: when login returns mfaRequired, deliverPlatformAuthResponse must NOT be called.
    it('should return MfaChallengeResult directly when mfaRequired is true, without calling deliverPlatformAuthResponse', async () => {
      mockPlatformAuthService.login.mockResolvedValue(MFA_CHALLENGE_RESULT)
      const req = makeReq()

      const result = await controller.login(LOGIN_DTO, req)

      expect(result).toEqual(MFA_CHALLENGE_RESULT)
      expect(mockTokenDelivery.deliverPlatformAuthResponse).not.toHaveBeenCalled()
    })

    // Service throws → controller propagates the error without catching it.
    it('should propagate errors thrown by platformAuthService.login', async () => {
      const error = new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
      mockPlatformAuthService.login.mockRejectedValue(error)
      const req = makeReq()

      await expect(controller.login(LOGIN_DTO, req)).rejects.toThrow(error)
    })

    // Fallback when req.ip is undefined — should pass empty string to service.
    it('should use empty string for ip when req.ip is undefined', async () => {
      mockPlatformAuthService.login.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const req = makeReq({ ip: undefined })

      await controller.login(LOGIN_DTO, req)

      const [, ipArg] = mockPlatformAuthService.login.mock.calls[0] as [
        PlatformLoginDto,
        string,
        string
      ]
      expect(ipArg).toBe('')
    })

    // Fallback when user-agent header is absent — should pass empty string to service.
    it('should use empty string for userAgent when user-agent header is absent', async () => {
      mockPlatformAuthService.login.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const req = makeReq({ headers: {} })

      await controller.login(LOGIN_DTO, req)

      const [, , uaArg] = mockPlatformAuthService.login.mock.calls[0] as [
        PlatformLoginDto,
        string,
        string
      ]
      expect(uaArg).toBe('')
    })
  })

  // ---------------------------------------------------------------------------
  // mfaChallenge — POST /platform/mfa/challenge
  // ---------------------------------------------------------------------------

  describe('mfaChallenge', () => {
    beforeEach(() => {
      mockTokenDelivery.deliverPlatformAuthResponse.mockReturnValue(PLATFORM_BEARER_RESPONSE)
    })

    // Happy path: mfaService.challenge returns a PlatformAuthResult (has 'admin').
    it('should call mfaService.challenge with correct args, then return deliverPlatformAuthResponse result', async () => {
      mockMfaService.challenge.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const req = makeReq({ ip: '5.5.5.5', headers: { 'user-agent': 'AdminDashboard/2.0' } })

      const result = await controller.mfaChallenge(MFA_CHALLENGE_DTO, req)

      expect(mockMfaService.challenge).toHaveBeenCalledWith(
        MFA_CHALLENGE_DTO.mfaTempToken,
        MFA_CHALLENGE_DTO.code,
        '5.5.5.5',
        'AdminDashboard/2.0'
      )
      expect(mockTokenDelivery.deliverPlatformAuthResponse).toHaveBeenCalledWith(
        PLATFORM_AUTH_RESULT
      )
      expect(result).toBe(PLATFORM_BEARER_RESPONSE)
    })

    // Cross-context abuse: mfaService returns a dashboard AuthResult (has 'user', not 'admin').
    it('should throw PLATFORM_AUTH_REQUIRED when mfaService returns a dashboard AuthResult (cross-context abuse)', async () => {
      const dashboardResult = {
        user: {
          id: 'user-1',
          email: 'u@d.com',
          name: 'User',
          role: 'member',
          status: 'active',
          tenantId: 'tenant-1',
          emailVerified: true,
          mfaEnabled: false,
          lastLoginAt: null,
          createdAt: new Date()
        },
        accessToken: 'dashboard.access.jwt',
        rawRefreshToken: 'dashboard-refresh'
      }
      mockMfaService.challenge.mockResolvedValue(dashboardResult)
      const req = makeReq()

      // Capture the thrown exception and inspect its error code.
      let thrown: unknown
      try {
        await controller.mfaChallenge(MFA_CHALLENGE_DTO, req)
      } catch (err) {
        thrown = err
      }

      expect(thrown).toBeInstanceOf(AuthException)
      const body = (thrown as AuthException).getResponse() as { error: { code: string } }
      expect(body.error.code).toBe(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    })

    // Service throws → controller propagates the error without catching it.
    it('should propagate errors thrown by mfaService.challenge', async () => {
      const error = new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
      mockMfaService.challenge.mockRejectedValue(error)
      const req = makeReq()

      await expect(controller.mfaChallenge(MFA_CHALLENGE_DTO, req)).rejects.toThrow(error)
    })

    // User-Agent must be capped at 512 characters.
    it('should truncate User-Agent to 512 characters in mfaChallenge', async () => {
      mockMfaService.challenge.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const longUserAgent = 'B'.repeat(600)
      const req = makeReq({ headers: { 'user-agent': longUserAgent } })

      await controller.mfaChallenge(MFA_CHALLENGE_DTO, req)

      const [, , , uaArg] = mockMfaService.challenge.mock.calls[0] as [
        string,
        string,
        string,
        string
      ]
      expect(uaArg).toHaveLength(512)
      expect(uaArg).toBe('B'.repeat(512))
    })

    // Fallback when req.ip is undefined in mfaChallenge — empty string passed to service.
    it('should use empty string for ip when req.ip is undefined in mfaChallenge', async () => {
      mockMfaService.challenge.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const req = makeReq({ ip: undefined })

      await controller.mfaChallenge(MFA_CHALLENGE_DTO, req)

      const [, , ipArg] = mockMfaService.challenge.mock.calls[0] as [string, string, string, string]
      expect(ipArg).toBe('')
    })

    // Fallback when user-agent header is absent in mfaChallenge — empty string passed to service.
    it('should use empty string for userAgent when user-agent header is absent in mfaChallenge', async () => {
      mockMfaService.challenge.mockResolvedValue(PLATFORM_AUTH_RESULT)
      const req = makeReq({ headers: {} })

      await controller.mfaChallenge(MFA_CHALLENGE_DTO, req)

      const [, , , uaArg] = mockMfaService.challenge.mock.calls[0] as [
        string,
        string,
        string,
        string
      ]
      expect(uaArg).toBe('')
    })

    // Cross-context throw: deliverPlatformAuthResponse must NOT be called when context is wrong.
    it('should NOT call deliverPlatformAuthResponse when the MFA result is from a dashboard context', async () => {
      const dashboardResult = {
        user: {
          id: 'u',
          email: 'u@d.com',
          name: 'U',
          role: 'member',
          status: 'active',
          tenantId: 't',
          emailVerified: true,
          mfaEnabled: false,
          lastLoginAt: null,
          createdAt: new Date()
        },
        accessToken: 'a',
        rawRefreshToken: 'r'
      }
      mockMfaService.challenge.mockResolvedValue(dashboardResult)
      const req = makeReq()

      await expect(controller.mfaChallenge(MFA_CHALLENGE_DTO, req)).rejects.toBeInstanceOf(
        AuthException
      )
      expect(mockTokenDelivery.deliverPlatformAuthResponse).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // me — GET /platform/me
  // ---------------------------------------------------------------------------

  describe('me', () => {
    // Returns the result of platformAuthService.getMe(user.sub).
    it('should return the admin record from platformAuthService.getMe(user.sub)', async () => {
      mockPlatformAuthService.getMe.mockResolvedValue(SAFE_ADMIN)

      const result = await controller.me(JWT_PAYLOAD)

      expect(mockPlatformAuthService.getMe).toHaveBeenCalledWith(JWT_PAYLOAD.sub)
      expect(result).toBe(SAFE_ADMIN)
    })

    // Service throws → propagates.
    it('should propagate errors thrown by platformAuthService.getMe', async () => {
      const error = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      mockPlatformAuthService.getMe.mockRejectedValue(error)

      await expect(controller.me(JWT_PAYLOAD)).rejects.toThrow(error)
    })
  })

  // ---------------------------------------------------------------------------
  // logout — POST /platform/logout
  // ---------------------------------------------------------------------------

  describe('logout', () => {
    beforeEach(() => {
      mockPlatformAuthService.logout.mockResolvedValue(undefined)
    })

    // Happy path: reads refresh token from body via extractPlatformRefreshToken.
    it('should call extractPlatformRefreshToken and then platformAuthService.logout with the correct arguments', async () => {
      mockTokenDelivery.extractPlatformRefreshToken.mockReturnValue('raw-rt-from-body')
      const req = makeReq({ body: { refreshToken: 'raw-rt-from-body' } })

      await controller.logout(JWT_PAYLOAD, req)

      expect(mockTokenDelivery.extractPlatformRefreshToken).toHaveBeenCalledWith(req)
      expect(mockPlatformAuthService.logout).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        JWT_PAYLOAD.jti,
        JWT_PAYLOAD.exp,
        'raw-rt-from-body'
      )
    })

    // When extractPlatformRefreshToken returns undefined, the ?? '' fallback sends empty string.
    it('should pass empty string to logout when no refresh token is present in the body', async () => {
      mockTokenDelivery.extractPlatformRefreshToken.mockReturnValue(undefined)
      const req = makeReq({ body: {} })

      await controller.logout(JWT_PAYLOAD, req)

      const [, , , rtArg] = mockPlatformAuthService.logout.mock.calls[0] as [
        string,
        string,
        number,
        string
      ]
      expect(rtArg).toBe('')
    })

    // The method must use extractPlatformRefreshToken, NOT extractRefreshToken.
    it('should use extractPlatformRefreshToken (not extractRefreshToken) for token extraction', async () => {
      mockTokenDelivery.extractPlatformRefreshToken.mockReturnValue('token-value')
      const req = makeReq()

      await controller.logout(JWT_PAYLOAD, req)

      expect(mockTokenDelivery.extractPlatformRefreshToken).toHaveBeenCalledTimes(1)
      // extractRefreshToken should not be present in the mock at all.
      expect((mockTokenDelivery as Record<string, unknown>)['extractRefreshToken']).toBeUndefined()
    })

    // Service throws → propagates.
    it('should propagate errors thrown by platformAuthService.logout', async () => {
      mockTokenDelivery.extractPlatformRefreshToken.mockReturnValue('token')
      const error = new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
      mockPlatformAuthService.logout.mockRejectedValue(error)

      await expect(controller.logout(JWT_PAYLOAD, makeReq())).rejects.toThrow(error)
    })
  })

  // ---------------------------------------------------------------------------
  // refresh — POST /platform/refresh
  // ---------------------------------------------------------------------------

  describe('refresh', () => {
    const ROTATED_RESULT = {
      session: { userId: 'admin-1', tenantId: '', role: 'super_admin' },
      accessToken: 'new.platform.access.jwt',
      rawRefreshToken: 'new-platform-refresh-uuid'
    }

    const NEW_PLATFORM_BEARER: PlatformBearerAuthResponse = {
      admin: SAFE_ADMIN,
      accessToken: 'new.platform.access.jwt',
      refreshToken: 'new-platform-refresh-uuid'
    }

    beforeEach(() => {
      mockTokenDelivery.extractPlatformRefreshToken.mockReturnValue('old-refresh-token')
      mockPlatformAuthService.refresh.mockResolvedValue(ROTATED_RESULT)
      mockPlatformAuthService.getMe.mockResolvedValue(SAFE_ADMIN)
      mockTokenDelivery.deliverPlatformAuthResponse.mockReturnValue(NEW_PLATFORM_BEARER)
    })

    // Happy path: extract token, rotate, fetch admin, deliver platform bearer response.
    it('should extract refresh token, rotate it, fetch admin, and return deliverPlatformAuthResponse result', async () => {
      const req = makeReq({
        ip: '9.9.9.9',
        headers: { 'user-agent': 'PlatformClient/3.0' },
        body: { refreshToken: 'old-refresh-token' }
      })

      const result = await controller.refresh(req)

      expect(mockTokenDelivery.extractPlatformRefreshToken).toHaveBeenCalledWith(req)
      expect(mockPlatformAuthService.refresh).toHaveBeenCalledWith(
        'old-refresh-token',
        '9.9.9.9',
        'PlatformClient/3.0'
      )
      expect(mockPlatformAuthService.getMe).toHaveBeenCalledWith(ROTATED_RESULT.session.userId)
      expect(mockTokenDelivery.deliverPlatformAuthResponse).toHaveBeenCalledWith({
        admin: SAFE_ADMIN,
        accessToken: ROTATED_RESULT.accessToken,
        rawRefreshToken: ROTATED_RESULT.rawRefreshToken
      })
      expect(result).toBe(NEW_PLATFORM_BEARER)
    })

    // The refresh endpoint must use extractPlatformRefreshToken (reads body), not extractRefreshToken.
    it('should use extractPlatformRefreshToken (not extractRefreshToken) during refresh', async () => {
      const req = makeReq({ body: { refreshToken: 'my-token' } })

      await controller.refresh(req)

      expect(mockTokenDelivery.extractPlatformRefreshToken).toHaveBeenCalledTimes(1)
      expect((mockTokenDelivery as Record<string, unknown>)['extractRefreshToken']).toBeUndefined()
    })

    // User-Agent is truncated to 512 characters during refresh as well.
    it('should truncate User-Agent to 512 characters before passing it to platformAuthService.refresh', async () => {
      const longUA = 'C'.repeat(600)
      const req = makeReq({ headers: { 'user-agent': longUA } })

      await controller.refresh(req)

      const [, , uaArg] = mockPlatformAuthService.refresh.mock.calls[0] as [string, string, string]
      expect(uaArg).toHaveLength(512)
      expect(uaArg).toBe('C'.repeat(512))
    })

    // When extractPlatformRefreshToken returns undefined, the ?? '' fallback is passed.
    it('should pass empty string to platformAuthService.refresh when no token found in body', async () => {
      mockTokenDelivery.extractPlatformRefreshToken.mockReturnValue(undefined)
      const req = makeReq({ body: {} })

      await controller.refresh(req)

      const [tokenArg] = mockPlatformAuthService.refresh.mock.calls[0] as [string, string, string]
      expect(tokenArg).toBe('')
    })

    // Service throws during refresh → propagates.
    it('should propagate errors thrown by platformAuthService.refresh', async () => {
      const error = new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
      mockPlatformAuthService.refresh.mockRejectedValue(error)

      await expect(controller.refresh(makeReq())).rejects.toThrow(error)
    })

    // req.ip absent → falls back to empty string.
    it('should use empty string for ip when req.ip is undefined during refresh', async () => {
      const req = makeReq({ ip: undefined })

      await controller.refresh(req)

      const [, ipArg] = mockPlatformAuthService.refresh.mock.calls[0] as [string, string, string]
      expect(ipArg).toBe('')
    })

    // User-Agent header absent during refresh — empty string fallback.
    it('should use empty string for userAgent when user-agent header is absent during refresh', async () => {
      const req = makeReq({ headers: {} })

      await controller.refresh(req)

      const [, , uaArg] = mockPlatformAuthService.refresh.mock.calls[0] as [string, string, string]
      expect(uaArg).toBe('')
    })
  })

  // ---------------------------------------------------------------------------
  // revokeSessions — DELETE /platform/sessions
  // ---------------------------------------------------------------------------

  describe('revokeSessions', () => {
    // Happy path: delegates to revokeAllPlatformSessions with user.sub.
    it('should call platformAuthService.revokeAllPlatformSessions with user.sub', async () => {
      mockPlatformAuthService.revokeAllPlatformSessions.mockResolvedValue(undefined)

      await controller.revokeSessions(JWT_PAYLOAD)

      expect(mockPlatformAuthService.revokeAllPlatformSessions).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub
      )
    })

    // Service throws → propagates.
    it('should propagate errors thrown by platformAuthService.revokeAllPlatformSessions', async () => {
      const error = new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
      mockPlatformAuthService.revokeAllPlatformSessions.mockRejectedValue(error)

      await expect(controller.revokeSessions(JWT_PAYLOAD)).rejects.toThrow(error)
    })
  })
})
