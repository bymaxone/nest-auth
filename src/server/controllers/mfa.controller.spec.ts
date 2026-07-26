/**
 * @fileoverview Tests for MfaController — thin HTTP endpoints for MFA setup,
 * verify-enable, challenge, and disable flows.
 */

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { MfaService } from '../services/mfa.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { MfaController } from './mfa.controller'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'

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
  disable: jest.fn(),
  regenerateRecoveryCodes: jest.fn()
}

const mockTokenDelivery = {
  deliverAuthResponse: jest.fn(),
  deliverPlatformAuthResponse: jest.fn()
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

/**
 * Minimal `ResolvedOptions` shape exercised by `MfaController.challenge`. Only
 * `routePrefix`, `secureCookies`, `cookies.sameSite`, and
 * `cookies.mfaTempCookiePath` are consumed by the clear-cookie path; the rest
 * of the shape is intentionally left as `unknown` via a cast so the test
 * fixture does not need to mirror the full options tree.
 */
const MOCK_OPTIONS = {
  routePrefix: 'auth',
  secureCookies: false,
  cookies: { sameSite: 'lax' as const, mfaTempCookiePath: '/auth/mfa' }
} as unknown as ResolvedOptions

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
        { provide: TokenDeliveryService, useValue: mockTokenDelivery },
        { provide: BYMAX_AUTH_OPTIONS, useValue: MOCK_OPTIONS }
      ]
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(TrustedOriginGuard)
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

    // Verifies that a platform challenge delegates to deliverPlatformAuthResponse (not
    // deliverAuthResponse) so the response shape stays consistent with PlatformAuthController.
    it('should return PlatformChallengeResponse with refreshToken field for platform challenges', async () => {
      const platformResponse = {
        admin: SAFE_ADMIN,
        accessToken: PLATFORM_AUTH_RESULT.accessToken,
        refreshToken: PLATFORM_AUTH_RESULT.rawRefreshToken
      }
      mockMfaService.challenge.mockResolvedValue(PLATFORM_AUTH_RESULT)
      mockTokenDelivery.deliverPlatformAuthResponse.mockReturnValue(platformResponse)

      const result = await controller.challenge(dto as never, mockReq, mockRes)

      // Must NOT call deliverAuthResponse — cookies are not set for platform admins.
      expect(mockTokenDelivery.deliverAuthResponse).not.toHaveBeenCalled()
      // Must delegate to deliverPlatformAuthResponse for consistent response shape.
      expect(mockTokenDelivery.deliverPlatformAuthResponse).toHaveBeenCalledWith(
        PLATFORM_AUTH_RESULT
      )
      expect(result).toEqual(platformResponse)
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

    // ─── Cookie fallback branch (1.0.7) ────────────────────────────────────

    /**
     * Verifies the cookie-fallback path: when the request body lacks an
     * `mfaTempToken` but the HttpOnly `mfa_temp_token` cookie carries one,
     * the controller forwards that cookie value to the service. This is the
     * browser-driven OAuth + MFA flow — the OAuth callback plants the cookie,
     * the destination page POSTs only `{ code }`, and the cookie travels
     * automatically along the Path scope.
     */
    it('should read mfaTempToken from the mfa_temp_token cookie when body lacks it', async () => {
      mockMfaService.challenge.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })
      const reqWithCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const bodyWithoutToken = { code: '654321' }

      await controller.challenge(bodyWithoutToken as never, reqWithCookie, mockRes)

      expect(mockMfaService.challenge).toHaveBeenCalledWith(
        'cookie.temp.jwt',
        '654321',
        '1.2.3.4',
        'UA'
      )
    })

    /**
     * Verifies the precedence rule: the body value wins over the cookie when
     * both are present. This preserves back-compat with the password-login
     * SPA flow that posts the token explicitly in the body.
     */
    it('should prefer the body mfaTempToken over the cookie when both are present', async () => {
      mockMfaService.challenge.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })
      const reqWithCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const bodyWithToken = { mfaTempToken: 'body.temp.jwt', code: '654321' }

      await controller.challenge(bodyWithToken as never, reqWithCookie, mockRes)

      expect(mockMfaService.challenge).toHaveBeenCalledWith(
        'body.temp.jwt',
        '654321',
        '1.2.3.4',
        'UA'
      )
    })

    /**
     * Verifies the clearCookie path: after a successful challenge that came
     * via the cookie, the controller clears the cookie on the response so
     * the temp token is not left around if the user closes the tab. Path
     * matches the path used by the OAuth callback so the browser deletes
     * the right cookie.
     */
    it('should clear the mfa_temp_token cookie after a successful cookie-sourced challenge', async () => {
      mockMfaService.challenge.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })
      const reqWithCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const res = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response

      await controller.challenge({ code: '654321' } as never, reqWithCookie, res)

      expect(res.clearCookie).toHaveBeenCalledWith('mfa_temp_token', {
        path: '/auth/mfa',
        httpOnly: true,
        secure: false,
        sameSite: 'lax'
      })
    })

    /**
     * Verifies that the cookie is NOT cleared when the body value drove the
     * call. The cookie clean-up is skipped because there is nothing to
     * clean — `readMfaTempCookie` returns `undefined` on an empty jar so
     * the `if (cookieToken !== undefined)` guard in `finally` is false.
     */
    it('should not call clearCookie when the request carries no mfa_temp_token cookie at all', async () => {
      mockMfaService.challenge.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })
      const reqWithoutCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: {}
      } as unknown as Request
      const res = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response
      const dtoWithToken = { mfaTempToken: 'body.temp.jwt', code: '654321' }

      await controller.challenge(dtoWithToken as never, reqWithoutCookie, res)

      expect(res.clearCookie).not.toHaveBeenCalled()
    })

    /**
     * Verifies the clear-on-success policy when both sources are present:
     * the body wins precedence for the service call (back-compat with the
     * sessionStorage flow), but the OAuth cookie still gets cleaned up
     * because the underlying JWT has been consumed by a successful
     * challenge. Leaving the dead cookie would confuse subsequent visits.
     */
    it('should clear the cookie when body provides the token AND cookie is also present (success path)', async () => {
      mockMfaService.challenge.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })
      const reqWithBoth = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const res = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response
      const dtoWithToken = { mfaTempToken: 'body.temp.jwt', code: '654321' }

      await controller.challenge(dtoWithToken as never, reqWithBoth, res)

      // Body wins for the service call, but the cookie is still cleaned up.
      expect(mockMfaService.challenge).toHaveBeenCalledWith(
        'body.temp.jwt',
        '654321',
        '1.2.3.4',
        'UA'
      )
      expect(res.clearCookie).toHaveBeenCalledWith(
        'mfa_temp_token',
        expect.objectContaining({ path: '/auth/mfa', httpOnly: true })
      )
    })

    /**
     * Verifies retry-friendly cookie semantics on `MFA_INVALID_CODE` (v1.0.8+):
     * the JWT is still alive in Redis because verify and consume are split
     * in `MfaService.challenge`, so the cookie must stay in the jar to let
     * the user retry with the correct code under the same temp token.
     * Clearing here would force a needless OAuth re-drive on every typo.
     */
    it('should keep the cookie when the challenge throws MFA_INVALID_CODE (retry path)', async () => {
      mockMfaService.challenge.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
      )
      const reqWithCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const res = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response

      await expect(
        controller.challenge({ code: '654321' } as never, reqWithCookie, res)
      ).rejects.toThrow(AuthException)
      expect(res.clearCookie).not.toHaveBeenCalled()
    })

    /**
     * Verifies that ACCOUNT_LOCKED also keeps the cookie alive. The user is
     * locked out for the configured brute-force window, but once the window
     * expires (or an admin unlocks the account) the same JWT is still valid
     * in Redis until its 5-minute TTL elapses. Clearing the cookie here
     * would force an OAuth re-drive after every accidental lockout.
     */
    it('should keep the cookie when the challenge throws ACCOUNT_LOCKED (retry-after-cooldown path)', async () => {
      mockMfaService.challenge.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED))
      const reqWithCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const res = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response

      await expect(
        controller.challenge({ code: '654321' } as never, reqWithCookie, res)
      ).rejects.toThrow(AuthException)
      expect(res.clearCookie).not.toHaveBeenCalled()
    })

    /**
     * Verifies clear-on-dead-token: `MFA_TEMP_TOKEN_INVALID` is unrecoverable
     * — the JWT is forged, expired, or already consumed, so a retry under
     * the same cookie can never succeed. Clearing makes the dead state
     * physical in the browser jar so a fresh OAuth drive can plant a new
     * cookie cleanly.
     */
    it('should clear the cookie when the challenge throws MFA_TEMP_TOKEN_INVALID (unrecoverable path)', async () => {
      mockMfaService.challenge.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID)
      )
      const reqWithCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const res = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response

      await expect(
        controller.challenge({ code: '654321' } as never, reqWithCookie, res)
      ).rejects.toThrow(AuthException)
      expect(res.clearCookie).toHaveBeenCalledWith(
        'mfa_temp_token',
        expect.objectContaining({ path: '/auth/mfa', httpOnly: true })
      )
    })

    /**
     * Defence-in-depth: a non-AuthException thrown by the service (e.g. a
     * transient Redis outage) must not clear the cookie either — the user's
     * temp token is still presumed alive once the infra recovers.
     */
    it('should keep the cookie when the challenge throws a non-AuthException (transient error)', async () => {
      mockMfaService.challenge.mockRejectedValue(new Error('boom'))
      const reqWithCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 'cookie.temp.jwt' }
      } as unknown as Request
      const res = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response

      await expect(
        controller.challenge({ code: '654321' } as never, reqWithCookie, res)
      ).rejects.toThrow('boom')
      expect(res.clearCookie).not.toHaveBeenCalled()
    })

    /**
     * Verifies the missing-token branch: with neither body field nor cookie
     * present, the controller surfaces `MFA_TEMP_TOKEN_INVALID` rather than
     * forwarding an empty/undefined value to the service.
     */
    it('should throw MFA_TEMP_TOKEN_INVALID when no body token and no cookie are present', async () => {
      const reqEmpty = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: {}
      } as unknown as Request

      await expect(
        controller.challenge({ code: '654321' } as never, reqEmpty, mockRes)
      ).rejects.toThrow(AuthException)
      expect(mockMfaService.challenge).not.toHaveBeenCalled()
    })

    it('should throw MFA_TEMP_TOKEN_INVALID when req.cookies itself is undefined', async () => {
      /*
       * Scenario: an exotic Express setup (or a deeply mocked test
       * harness) hands the controller a request without the
       * `cookies` property at all. `readMfaTempCookie` must early-out
       * via `cookies === undefined` rather than crashing on
       * destructuring. Protects line 73 of mfa.controller.ts — the
       * defence-in-depth guard for non-cookie-parser middleware.
       */
      const reqNoCookieJar = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' }
        // cookies field intentionally omitted
      } as unknown as Request

      await expect(
        controller.challenge({ code: '654321' } as never, reqNoCookieJar, mockRes)
      ).rejects.toThrow(AuthException)
      expect(mockMfaService.challenge).not.toHaveBeenCalled()
    })

    /**
     * Defence-in-depth: a non-string value in the cookie jar (e.g. set by a
     * misbehaving cookie parser) is treated as missing rather than coerced.
     */
    it('should ignore a non-string mfa_temp_token cookie value', async () => {
      const reqWithBadCookie = {
        ip: '1.2.3.4',
        headers: { 'user-agent': 'UA' },
        cookies: { mfa_temp_token: 12345 }
      } as unknown as Request

      await expect(
        controller.challenge({ code: '654321' } as never, reqWithBadCookie, mockRes)
      ).rejects.toThrow(AuthException)
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

  // ---------------------------------------------------------------------------
  // regenerateRecoveryCodes
  // ---------------------------------------------------------------------------

  describe('regenerateRecoveryCodes', () => {
    const dto = { code: '654321' }
    const REGENERATE_RESULT = { recoveryCodes: ['AAAA-1111-BBBB-2222-CCCC-3333'] }

    // Verifies that regenerateRecoveryCodes delegates to mfaService with the
    // dashboard context derived from the JWT type claim and returns the
    // service's response unchanged.
    it('should call mfaService.regenerateRecoveryCodes with userId, code, ip, userAgent, and context', async () => {
      mockMfaService.regenerateRecoveryCodes.mockResolvedValue(REGENERATE_RESULT)

      const result = await controller.regenerateRecoveryCodes(
        JWT_PAYLOAD as never,
        dto as never,
        mockReq
      )

      expect(mockMfaService.regenerateRecoveryCodes).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        dto.code,
        '1.2.3.4',
        'TestBrowser',
        'dashboard'
      )
      expect(result).toBe(REGENERATE_RESULT)
    })

    // Verifies that a PlatformJwtPayload user routes the call with context='platform'.
    it('should pass context=platform when user.type is platform', async () => {
      mockMfaService.regenerateRecoveryCodes.mockResolvedValue(REGENERATE_RESULT)
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

      await controller.regenerateRecoveryCodes(platformUser as never, dto as never, mockReq)

      expect(mockMfaService.regenerateRecoveryCodes).toHaveBeenCalledWith(
        'admin-1',
        dto.code,
        '1.2.3.4',
        'TestBrowser',
        'platform'
      )
    })

    // Verifies that ip and userAgent fall back to empty strings when absent
    // from the incoming request — mirrors the disable() fallback pattern.
    it('should use empty strings when ip and user-agent are absent', async () => {
      mockMfaService.regenerateRecoveryCodes.mockResolvedValue(REGENERATE_RESULT)
      const reqWithoutMeta = { ip: undefined, headers: {}, cookies: {} } as unknown as Request

      await controller.regenerateRecoveryCodes(JWT_PAYLOAD as never, dto as never, reqWithoutMeta)

      expect(mockMfaService.regenerateRecoveryCodes).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        dto.code,
        '',
        '',
        'dashboard'
      )
    })

    // Verifies that MFA_NOT_ENABLED propagates when MFA is not active.
    it('should propagate MFA_NOT_ENABLED when MFA is not active', async () => {
      mockMfaService.regenerateRecoveryCodes.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_NOT_ENABLED)
      )

      await expect(
        controller.regenerateRecoveryCodes(JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })

    // Verifies that MFA_INVALID_CODE propagates when the TOTP code is wrong.
    it('should propagate MFA_INVALID_CODE for an incorrect code', async () => {
      mockMfaService.regenerateRecoveryCodes.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
      )

      await expect(
        controller.regenerateRecoveryCodes(JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })

    // Verifies that ACCOUNT_LOCKED propagates when the brute-force threshold is reached.
    it('should propagate ACCOUNT_LOCKED when the user is locked out', async () => {
      mockMfaService.regenerateRecoveryCodes.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)
      )

      await expect(
        controller.regenerateRecoveryCodes(JWT_PAYLOAD as never, dto as never, mockReq)
      ).rejects.toThrow(AuthException)
    })
  })
})
