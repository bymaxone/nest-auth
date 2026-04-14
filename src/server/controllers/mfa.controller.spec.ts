/**
 * @fileoverview Tests for MfaController — thin HTTP endpoints for MFA setup,
 * verify-enable, challenge, and disable flows.
 */

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { MfaService } from '../services/mfa.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { MfaController } from './mfa.controller'

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

const SAFE_ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: true,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01')
}

const JWT_PAYLOAD = {
  jti: 'test-jti',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  // 'dashboard' as const is the discriminant for DashboardJwtPayload; kept for documentation
  type: 'dashboard' as const,
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

// TEST FIXTURE ONLY — not a real credential.
// 'JBSWY3DPEHPK3PXP' is a well-known TOTP example key (decodes to "Hello!\xDE\xAD\xBE\xEF").
// It is used here only to test controller delegation — the controller never interprets the secret.
const MFA_SETUP_RESULT = {
  secret: 'JBSWY3DPEHPK3PXP',
  qrCodeUri: 'otpauth://totp/App:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=App',
  recoveryCodes: ['1234-5678-9012', '2345-6789-0123']
}

const AUTH_RESULT = {
  user: SAFE_USER,
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh-uuid'
}

// PLATFORM_AUTH_RESULT uses the `admin` field as the discriminant for isPlatformResult().
// The controller's isPlatformResult type guard checks `'admin' in result` to route platform
// challenges to the PlatformChallengeResponse branch. Do not rename this field without
// updating the type guard in mfa.controller.ts.
const PLATFORM_AUTH_RESULT = {
  admin: SAFE_ADMIN,
  accessToken: 'platform.access.jwt',
  rawRefreshToken: 'platform-raw-refresh-uuid'
}

const mockMfaService = {
  setup: jest.fn(),
  verifyAndEnable: jest.fn(),
  challenge: jest.fn(),
  disable: jest.fn()
}

const mockTokenDelivery = {
  deliverAuthResponse: jest.fn()
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

describe('MfaController', () => {
  let controller: MfaController

  beforeEach(async () => {
    // resetAllMocks clears both call history and mock implementations, ensuring no state
    // bleeds between tests. Each test must configure its own return values.
    jest.resetAllMocks()

    const module = await Test.createTestingModule({
      controllers: [MfaController],
      providers: [
        { provide: MfaService, useValue: mockMfaService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery }
      ]
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile()

    controller = module.get(MfaController)
  })

  // ---------------------------------------------------------------------------
  // setup
  // ---------------------------------------------------------------------------

  describe('setup', () => {
    // Verifies that setup delegates to mfaService.setup with the authenticated user's sub.
    it('should call mfaService.setup with the user sub and return the setup result', async () => {
      mockMfaService.setup.mockResolvedValue(MFA_SETUP_RESULT)

      const result = await controller.setup(JWT_PAYLOAD as never)

      expect(mockMfaService.setup).toHaveBeenCalledWith(JWT_PAYLOAD.sub)
      expect(result).toBe(MFA_SETUP_RESULT)
    })

    // Verifies that MFA_ALREADY_ENABLED errors from the service propagate to the caller.
    it('should propagate MFA_ALREADY_ENABLED when MFA is already active', async () => {
      mockMfaService.setup.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)
      )

      await expect(controller.setup(JWT_PAYLOAD as never)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // verifyEnable
  // ---------------------------------------------------------------------------

  describe('verifyEnable', () => {
    const dto = { code: '123456' }

    // Verifies that verifyEnable delegates to mfaService.verifyAndEnable with ip and userAgent.
    it('should call mfaService.verifyAndEnable with userId, code, ip, and userAgent', async () => {
      mockMfaService.verifyAndEnable.mockResolvedValue(undefined)

      await controller.verifyEnable(JWT_PAYLOAD as never, dto as never, mockReq)

      expect(mockMfaService.verifyAndEnable).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        dto.code,
        '1.2.3.4',
        'TestBrowser'
      )
    })

    // Verifies that verifyEnable returns undefined (204 No Content).
    it('should return undefined (204 No Content)', async () => {
      mockMfaService.verifyAndEnable.mockResolvedValue(undefined)

      const result = await controller.verifyEnable(JWT_PAYLOAD as never, dto as never, mockReq)

      expect(result).toBeUndefined()
    })

    // Verifies that ip and userAgent fall back to empty strings when absent from the request.
    it('should use empty strings when ip and user-agent are absent', async () => {
      mockMfaService.verifyAndEnable.mockResolvedValue(undefined)
      const reqWithoutMeta = { ip: undefined, headers: {}, cookies: {} } as unknown as Request

      await controller.verifyEnable(JWT_PAYLOAD as never, dto as never, reqWithoutMeta)

      expect(mockMfaService.verifyAndEnable).toHaveBeenCalledWith(JWT_PAYLOAD.sub, dto.code, '', '')
    })

    // Verifies that MFA_SETUP_REQUIRED propagates when no pending setup is found.
    it('should propagate MFA_SETUP_REQUIRED when no pending setup exists', async () => {
      mockMfaService.verifyAndEnable.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
      )

      await expect(
        controller.verifyEnable(JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // challenge
  // ---------------------------------------------------------------------------

  describe('challenge', () => {
    const dto = { mfaTempToken: 'mfa.temp.token', code: '654321' }

    // Verifies that a dashboard challenge delivers the auth response via TokenDeliveryService.
    it('should deliver auth response for a dashboard challenge', async () => {
      mockMfaService.challenge.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })

      const result = await controller.challenge(dto as never, mockReq, mockRes)

      expect(mockMfaService.challenge).toHaveBeenCalledWith(
        dto.mfaTempToken,
        dto.code,
        '1.2.3.4',
        'TestBrowser'
      )
      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        AUTH_RESULT,
        mockReq
      )
      expect(result).toEqual({ user: SAFE_USER })
    })

    // Verifies that a platform challenge returns a PlatformChallengeResponse with refreshToken
    // (not rawRefreshToken) so the internal naming convention is not leaked to clients.
    it('should return PlatformChallengeResponse with refreshToken field for platform challenges', async () => {
      mockMfaService.challenge.mockResolvedValue(PLATFORM_AUTH_RESULT)

      const result = await controller.challenge(dto as never, mockReq, mockRes)

      // Must NOT call deliverAuthResponse — cookies are not set for platform admins.
      expect(mockTokenDelivery.deliverAuthResponse).not.toHaveBeenCalled()
      expect(result).toEqual({
        admin: SAFE_ADMIN,
        accessToken: PLATFORM_AUTH_RESULT.accessToken,
        refreshToken: PLATFORM_AUTH_RESULT.rawRefreshToken
      })
      // Ensure rawRefreshToken is not present in the serialised response.
      expect((result as unknown as Record<string, unknown>)['rawRefreshToken']).toBeUndefined()
    })

    // Verifies that MFA_TEMP_TOKEN_INVALID propagates when the temp token is invalid.
    it('should propagate MFA_TEMP_TOKEN_INVALID for an invalid temp token', async () => {
      mockMfaService.challenge.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
      )

      await expect(controller.challenge(dto as never, mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that MFA_INVALID_CODE propagates when the submitted code is wrong.
    it('should propagate MFA_INVALID_CODE for an incorrect TOTP code', async () => {
      mockMfaService.challenge.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
      )

      await expect(controller.challenge(dto as never, mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that ip and userAgent fall back to empty strings when absent from the request.
    it('should use empty strings when ip and user-agent are absent', async () => {
      mockMfaService.challenge.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })
      const reqWithoutMeta = { ip: undefined, headers: {}, cookies: {} } as unknown as Request

      await controller.challenge(dto as never, reqWithoutMeta, mockRes)

      expect(mockMfaService.challenge).toHaveBeenCalledWith(dto.mfaTempToken, dto.code, '', '')
    })
  })

  // ---------------------------------------------------------------------------
  // disable
  // ---------------------------------------------------------------------------

  describe('disable', () => {
    const dto = { code: '111222' }

    // Verifies that disable delegates to mfaService.disable with userId, code, ip, and userAgent.
    it('should call mfaService.disable with userId, code, ip, and userAgent', async () => {
      mockMfaService.disable.mockResolvedValue(undefined)

      await controller.disable(JWT_PAYLOAD as never, dto as never, mockReq)

      expect(mockMfaService.disable).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        dto.code,
        '1.2.3.4',
        'TestBrowser',
        'dashboard'
      )
    })

    // Verifies that disable returns undefined (204 No Content).
    it('should return undefined (204 No Content)', async () => {
      mockMfaService.disable.mockResolvedValue(undefined)

      const result = await controller.disable(JWT_PAYLOAD as never, dto as never, mockReq)

      expect(result).toBeUndefined()
    })

    // Verifies that MFA_NOT_ENABLED propagates when MFA is not active on the account.
    it('should propagate MFA_NOT_ENABLED when MFA is not active', async () => {
      mockMfaService.disable.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED))

      await expect(controller.disable(JWT_PAYLOAD as never, dto as never, mockReq)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that MFA_INVALID_CODE propagates when the TOTP code is wrong.
    it('should propagate MFA_INVALID_CODE for an incorrect code', async () => {
      mockMfaService.disable.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE))

      await expect(controller.disable(JWT_PAYLOAD as never, dto as never, mockReq)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that ACCOUNT_LOCKED propagates when the brute-force threshold is reached.
    it('should propagate ACCOUNT_LOCKED when the user is locked out', async () => {
      mockMfaService.disable.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED))

      await expect(controller.disable(JWT_PAYLOAD as never, dto as never, mockReq)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that ip and userAgent fall back to empty strings when absent from the request.
    it('should use empty strings when ip and user-agent are absent', async () => {
      mockMfaService.disable.mockResolvedValue(undefined)
      const reqWithoutMeta = { ip: undefined, headers: {}, cookies: {} } as unknown as Request

      await controller.disable(JWT_PAYLOAD as never, dto as never, reqWithoutMeta)

      expect(mockMfaService.disable).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        dto.code,
        '',
        '',
        'dashboard'
      )
    })

    // Verifies that a PlatformJwtPayload user triggers context='platform' in the service call.
    it('should pass context=platform when user.type is platform', async () => {
      mockMfaService.disable.mockResolvedValue(undefined)
      const platformUser = {
        sub: 'admin-1',
        type: 'platform' as const,
        role: 'super-admin',
        jti: 'jti',
        mfaEnabled: true,
        mfaVerified: false,
        iat: 0,
        exp: 9_999_999_999
      }

      await controller.disable(platformUser as never, dto as never, mockReq)

      expect(mockMfaService.disable).toHaveBeenCalledWith(
        'admin-1',
        dto.code,
        '1.2.3.4',
        'TestBrowser',
        'platform'
      )
    })
  })
})
