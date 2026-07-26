/**
 * @fileoverview Tests for PlatformMfaController — thin HTTP endpoints for
 * platform admin MFA setup, verify-enable, disable, and recovery code
 * regeneration. Mirrors the dashboard MfaController contract but uses
 * JwtPlatformGuard and forwards the 'platform' context to MfaService.
 */

import { Test } from '@nestjs/testing'
import type { Request } from 'express'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { JwtPlatformGuard } from '../guards/jwt-platform.guard'
import { MfaService } from '../services/mfa.service'
import { PlatformMfaController } from './platform-mfa.controller'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const PLATFORM_JWT_PAYLOAD = {
  jti: 'platform-jti',
  sub: 'admin-1',
  role: 'super-admin',
  type: 'platform' as const,
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

// TEST FIXTURE ONLY — not a real credential. 'JBSWY3DPEHPK3PXP' is a well-known
// public TOTP example secret used solely to test controller delegation.
const MFA_SETUP_RESULT = {
  secret: 'JBSWY3DPEHPK3PXP',
  qrCodeUri: 'otpauth://totp/App:admin@platform.com?secret=JBSWY3DPEHPK3PXP&issuer=App',
  recoveryCodes: ['ABCD-1234-EFGH-5678-IJKL-9012', 'MNOP-3456-QRST-7890-UVWX-1234']
}

const REGENERATE_RESULT = { recoveryCodes: ['AAAA-1111-BBBB-2222-CCCC-3333'] }

const mockMfaService = {
  setup: jest.fn(),
  verifyAndEnable: jest.fn(),
  disable: jest.fn(),
  regenerateRecoveryCodes: jest.fn()
}

const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'PlatformBrowser' },
  cookies: {}
} as unknown as Request

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('PlatformMfaController', () => {
  let controller: PlatformMfaController

  beforeEach(async () => {
    // resetAllMocks clears both call history and mock implementations so no
    // configured return value bleeds between tests.
    jest.resetAllMocks()

    const module = await Test.createTestingModule({
      controllers: [PlatformMfaController],
      providers: [{ provide: MfaService, useValue: mockMfaService }]
    })
      .overrideGuard(JwtPlatformGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(TrustedOriginGuard)
      .useValue({ canActivate: () => true })
      .compile()

    controller = module.get(PlatformMfaController)
  })

  // ---------------------------------------------------------------------------
  // setup
  // ---------------------------------------------------------------------------

  describe('setup', () => {
    // Verifies that setup delegates to mfaService.setup with context='platform'
    // — this is the critical wiring that prevents a platform admin from
    // accidentally creating an MFA secret on the dashboard userRepo.
    it('should call mfaService.setup with the admin sub and platform context', async () => {
      mockMfaService.setup.mockResolvedValue(MFA_SETUP_RESULT)

      const result = await controller.setup(PLATFORM_JWT_PAYLOAD as never)

      expect(mockMfaService.setup).toHaveBeenCalledWith(PLATFORM_JWT_PAYLOAD.sub, 'platform')
      expect(result).toBe(MFA_SETUP_RESULT)
    })

    // Verifies that MFA_ALREADY_ENABLED errors from the service propagate.
    it('should propagate MFA_ALREADY_ENABLED when MFA is already active', async () => {
      mockMfaService.setup.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED)
      )

      await expect(controller.setup(PLATFORM_JWT_PAYLOAD as never)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // verifyEnable
  // ---------------------------------------------------------------------------

  describe('verifyEnable', () => {
    const dto = { code: '123456' }

    // Verifies that verifyEnable delegates to mfaService.verifyAndEnable with
    // the platform context flag. Without this argument, the service would
    // persist the new MFA state on the dashboard repo.
    it('should call mfaService.verifyAndEnable with userId, code, ip, userAgent, and platform context', async () => {
      mockMfaService.verifyAndEnable.mockResolvedValue(undefined)

      await controller.verifyEnable(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)

      expect(mockMfaService.verifyAndEnable).toHaveBeenCalledWith(
        PLATFORM_JWT_PAYLOAD.sub,
        dto.code,
        '1.2.3.4',
        'PlatformBrowser',
        'platform'
      )
    })

    // Verifies that verifyEnable returns undefined (204 No Content).
    it('should return undefined (204 No Content)', async () => {
      mockMfaService.verifyAndEnable.mockResolvedValue(undefined)

      const result = await controller.verifyEnable(
        PLATFORM_JWT_PAYLOAD as never,
        dto as never,
        mockReq
      )

      expect(result).toBeUndefined()
    })

    // Verifies that ip and userAgent fall back to empty strings when absent.
    it('should use empty strings when ip and user-agent are absent', async () => {
      mockMfaService.verifyAndEnable.mockResolvedValue(undefined)
      const reqWithoutMeta = { ip: undefined, headers: {}, cookies: {} } as unknown as Request

      await controller.verifyEnable(PLATFORM_JWT_PAYLOAD as never, dto as never, reqWithoutMeta)

      expect(mockMfaService.verifyAndEnable).toHaveBeenCalledWith(
        PLATFORM_JWT_PAYLOAD.sub,
        dto.code,
        '',
        '',
        'platform'
      )
    })

    // Verifies that MFA_SETUP_REQUIRED propagates when no pending setup exists.
    it('should propagate MFA_SETUP_REQUIRED when no pending setup exists', async () => {
      mockMfaService.verifyAndEnable.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED)
      )

      await expect(
        controller.verifyEnable(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // disable
  // ---------------------------------------------------------------------------

  describe('disable', () => {
    const dto = { code: '111222' }

    // Verifies that disable delegates with the platform context flag.
    it('should call mfaService.disable with userId, code, ip, userAgent, and platform context', async () => {
      mockMfaService.disable.mockResolvedValue(undefined)

      await controller.disable(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)

      expect(mockMfaService.disable).toHaveBeenCalledWith(
        PLATFORM_JWT_PAYLOAD.sub,
        dto.code,
        '1.2.3.4',
        'PlatformBrowser',
        'platform'
      )
    })

    // Verifies that disable returns undefined (204 No Content).
    it('should return undefined (204 No Content)', async () => {
      mockMfaService.disable.mockResolvedValue(undefined)

      const result = await controller.disable(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)

      expect(result).toBeUndefined()
    })

    // Verifies that ip and userAgent fall back to empty strings when absent.
    it('should use empty strings when ip and user-agent are absent', async () => {
      mockMfaService.disable.mockResolvedValue(undefined)
      const reqWithoutMeta = { ip: undefined, headers: {}, cookies: {} } as unknown as Request

      await controller.disable(PLATFORM_JWT_PAYLOAD as never, dto as never, reqWithoutMeta)

      expect(mockMfaService.disable).toHaveBeenCalledWith(
        PLATFORM_JWT_PAYLOAD.sub,
        dto.code,
        '',
        '',
        'platform'
      )
    })

    // Verifies that MFA_NOT_ENABLED propagates when MFA is not active.
    it('should propagate MFA_NOT_ENABLED when MFA is not active', async () => {
      mockMfaService.disable.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED))

      await expect(
        controller.disable(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })

    // Verifies that MFA_INVALID_CODE propagates when the TOTP code is wrong.
    it('should propagate MFA_INVALID_CODE for an incorrect code', async () => {
      mockMfaService.disable.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE))

      await expect(
        controller.disable(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // regenerateRecoveryCodes
  // ---------------------------------------------------------------------------

  describe('regenerateRecoveryCodes', () => {
    const dto = { code: '654321' }

    // Verifies that regenerateRecoveryCodes delegates with the platform context
    // flag and returns the service result unchanged.
    it('should call mfaService.regenerateRecoveryCodes with userId, code, ip, userAgent, and platform context', async () => {
      mockMfaService.regenerateRecoveryCodes.mockResolvedValue(REGENERATE_RESULT)

      const result = await controller.regenerateRecoveryCodes(
        PLATFORM_JWT_PAYLOAD as never,
        dto as never,
        mockReq
      )

      expect(mockMfaService.regenerateRecoveryCodes).toHaveBeenCalledWith(
        PLATFORM_JWT_PAYLOAD.sub,
        dto.code,
        '1.2.3.4',
        'PlatformBrowser',
        'platform'
      )
      expect(result).toBe(REGENERATE_RESULT)
    })

    // Verifies that ip and userAgent fall back to empty strings when absent.
    it('should use empty strings when ip and user-agent are absent', async () => {
      mockMfaService.regenerateRecoveryCodes.mockResolvedValue(REGENERATE_RESULT)
      const reqWithoutMeta = { ip: undefined, headers: {}, cookies: {} } as unknown as Request

      await controller.regenerateRecoveryCodes(
        PLATFORM_JWT_PAYLOAD as never,
        dto as never,
        reqWithoutMeta
      )

      expect(mockMfaService.regenerateRecoveryCodes).toHaveBeenCalledWith(
        PLATFORM_JWT_PAYLOAD.sub,
        dto.code,
        '',
        '',
        'platform'
      )
    })

    // Verifies that MFA_NOT_ENABLED propagates when MFA is not active.
    it('should propagate MFA_NOT_ENABLED when MFA is not active', async () => {
      mockMfaService.regenerateRecoveryCodes.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
      )

      await expect(
        controller.regenerateRecoveryCodes(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })

    // Verifies that MFA_INVALID_CODE propagates when the TOTP code is wrong.
    it('should propagate MFA_INVALID_CODE for an incorrect code', async () => {
      mockMfaService.regenerateRecoveryCodes.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
      )

      await expect(
        controller.regenerateRecoveryCodes(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })

    // Verifies that ACCOUNT_LOCKED propagates when the brute-force threshold is reached.
    it('should propagate ACCOUNT_LOCKED when the user is locked out', async () => {
      mockMfaService.regenerateRecoveryCodes.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
      )

      await expect(
        controller.regenerateRecoveryCodes(PLATFORM_JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })
  })
})
