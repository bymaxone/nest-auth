/**
 * @fileoverview Tests for TokenDeliveryService, which manages token delivery via
 * cookies (HttpOnly) or bearer tokens in response bodies, and handles domain
 * resolution for multi-domain cookie scenarios.
 */

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import { TokenDeliveryService } from './token-delivery.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

function makeRes(): jest.Mocked<Partial<Response>> {
  return {
    cookie: jest.fn(),
    clearCookie: jest.fn()
  }
}

function makeReq(overrides: Partial<Request> = {}): Partial<Request> {
  return {
    cookies: {},
    headers: {},
    hostname: 'example.com',
    body: {},
    ...overrides
  }
}

const AUTH_RESULT = {
  user: {
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
  },
  accessToken: 'access.jwt.token',
  rawRefreshToken: 'raw-refresh-uuid'
}

/** Mirrors the resolved options shape for cookies and jwt. */
function makeOptions(tokenDelivery: 'cookie' | 'bearer' | 'both') {
  return {
    tokenDelivery,
    jwt: {
      accessCookieMaxAgeMs: 900_000,
      refreshExpiresInDays: 7,
      algorithm: 'HS256'
    },
    cookies: {
      accessTokenName: 'access_token',
      refreshTokenName: 'refresh_token',
      sessionSignalName: 'has_session',
      refreshCookiePath: '/auth/refresh'
    }
  }
}

async function buildService(tokenDelivery: 'cookie' | 'bearer' | 'both') {
  const module = await Test.createTestingModule({
    providers: [
      TokenDeliveryService,
      { provide: BYMAX_AUTH_OPTIONS, useValue: makeOptions(tokenDelivery) }
    ]
  }).compile()
  return module.get(TokenDeliveryService)
}

async function buildServiceWithOptions(
  options: ReturnType<typeof makeOptions> & {
    cookies?: { resolveDomains?: (hostname: string) => string[] } & Partial<
      ReturnType<typeof makeOptions>['cookies']
    >
  }
) {
  const module = await Test.createTestingModule({
    providers: [TokenDeliveryService, { provide: BYMAX_AUTH_OPTIONS, useValue: options }]
  }).compile()
  return module.get(TokenDeliveryService)
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('TokenDeliveryService', () => {
  // ---------------------------------------------------------------------------
  // deliverAuthResponse — cookie mode
  // ---------------------------------------------------------------------------

  describe('cookie mode', () => {
    // Verifies that all three auth cookies (access, refresh, session signal) are set in cookie mode.
    it('should set access_token, refresh_token, and has_session cookies', async () => {
      const service = await buildService('cookie')
      const res = makeRes()
      const req = makeReq()

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      const cookieNames = (res.cookie as jest.Mock).mock.calls.map(
        (call: [string, ...unknown[]]) => call[0]
      )
      expect(cookieNames).toContain('access_token')
      expect(cookieNames).toContain('refresh_token')
      expect(cookieNames).toContain('has_session')
    })

    // Verifies that in cookie mode the response body only contains the user object, not the tokens.
    it('should return only the user in the response body', async () => {
      const service = await buildService('cookie')
      const res = makeRes()
      const req = makeReq()

      const result = service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      expect(result).toEqual({ user: AUTH_RESULT.user })
      expect(result).not.toHaveProperty('accessToken')
      expect(result).not.toHaveProperty('refreshToken')
    })

    // Verifies that the access token cookie is HttpOnly to prevent JavaScript access.
    it('access_token cookie should be HttpOnly', async () => {
      const service = await buildService('cookie')
      const res = makeRes()
      const req = makeReq()

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      const accessCookieCall = (res.cookie as jest.Mock).mock.calls.find(
        (call: [string, ...unknown[]]) => call[0] === 'access_token'
      ) as [string, string, Record<string, unknown>] | undefined
      expect(accessCookieCall?.[2]?.['httpOnly']).toBe(true)
    })

    // Verifies that the session signal cookie is NOT HttpOnly so client JS can read it.
    it('has_session signal cookie should NOT be HttpOnly', async () => {
      const service = await buildService('cookie')
      const res = makeRes()
      const req = makeReq()

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      const sessionCookieCall = (res.cookie as jest.Mock).mock.calls.find(
        (call: [string, ...unknown[]]) => call[0] === 'has_session'
      ) as [string, string, Record<string, unknown>] | undefined
      expect(sessionCookieCall?.[2]?.['httpOnly']).toBe(false)
    })

    // Verifies that the refresh token cookie uses the configured path to limit its scope.
    it('refresh_token cookie should use the configured refreshCookiePath', async () => {
      const service = await buildService('cookie')
      const res = makeRes()
      const req = makeReq()

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      const refreshCall = (res.cookie as jest.Mock).mock.calls.find(
        (call: [string, ...unknown[]]) => call[0] === 'refresh_token'
      ) as [string, string, Record<string, unknown>] | undefined
      expect(refreshCall?.[2]?.['path']).toBe('/auth/refresh')
    })

    // Verifies that when no valid domain can be extracted (empty hostname), setAuthCookies is called without a domain attribute.
    it('should call setAuthCookies with undefined domain when hostname is invalid', async () => {
      const service = await buildService('cookie')
      const res = makeRes()
      // A request with an empty hostname yields no extractable domain, triggering the domains.length === 0 branch.
      const req = makeReq({ hostname: '' })

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      // Cookies should still be set (without a domain attribute).
      expect(res.cookie).toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // deliverAuthResponse — bearer mode
  // ---------------------------------------------------------------------------

  describe('bearer mode', () => {
    // Verifies that bearer mode returns all token data in the response body.
    it('should return user, accessToken, and refreshToken in body', async () => {
      const service = await buildService('bearer')
      const res = makeRes()
      const req = makeReq()

      const result = service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      expect(result).toEqual({
        user: AUTH_RESULT.user,
        accessToken: AUTH_RESULT.accessToken,
        refreshToken: AUTH_RESULT.rawRefreshToken
      })
    })

    // Verifies that bearer mode does not set any cookies.
    it('should NOT set any cookies in bearer mode', async () => {
      const service = await buildService('bearer')
      const res = makeRes()
      const req = makeReq()

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      expect(res.cookie).not.toHaveBeenCalled()
    })

    // Verifies that deliverRefreshResponse without a req argument still works (no cookies, returns tokens).
    it('should handle deliverRefreshResponse called without req parameter', async () => {
      const service = await buildService('bearer')
      const res = makeRes()

      const result = service.deliverRefreshResponse(res as Response, AUTH_RESULT)

      expect(result).toMatchObject({
        user: AUTH_RESULT.user,
        accessToken: AUTH_RESULT.accessToken,
        refreshToken: AUTH_RESULT.rawRefreshToken
      })
      expect(res.cookie).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // deliverAuthResponse — both mode
  // ---------------------------------------------------------------------------

  describe('both mode', () => {
    // Verifies that both mode sets cookies AND returns tokens in the response body.
    it('should set cookies AND return tokens in body', async () => {
      const service = await buildService('both')
      const res = makeRes()
      const req = makeReq()

      const result = service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      expect(res.cookie).toHaveBeenCalled()
      expect(result).toMatchObject({
        user: AUTH_RESULT.user,
        accessToken: AUTH_RESULT.accessToken,
        refreshToken: AUTH_RESULT.rawRefreshToken
      })
    })
  })

  // ---------------------------------------------------------------------------
  // extractAccessToken
  // ---------------------------------------------------------------------------

  describe('extractAccessToken', () => {
    // Verifies that extractAccessToken reads from the cookie in cookie mode.
    it('should read from cookie in cookie mode', async () => {
      const service = await buildService('cookie')
      const req = makeReq({ cookies: { access_token: 'cookie-access-token' } })

      expect(service.extractAccessToken(req as Request)).toBe('cookie-access-token')
    })

    // Verifies that extractAccessToken reads the Bearer token from the Authorization header in bearer mode.
    it('should read from Authorization header in bearer mode', async () => {
      const service = await buildService('bearer')
      const req = makeReq({ headers: { authorization: 'Bearer header-access-token' } })

      expect(service.extractAccessToken(req as Request)).toBe('header-access-token')
    })

    // Verifies that the cookie takes precedence over the Authorization header in both mode.
    it('should prefer cookie over header in both mode', async () => {
      const service = await buildService('both')
      const req = makeReq({
        cookies: { access_token: 'cookie-access-token' },
        headers: { authorization: 'Bearer header-access-token' }
      })

      expect(service.extractAccessToken(req as Request)).toBe('cookie-access-token')
    })

    // Verifies that extractAccessToken falls back to the Authorization header when the cookie is absent in both mode.
    it('should fall back to header when cookie absent in both mode', async () => {
      const service = await buildService('both')
      const req = makeReq({ headers: { authorization: 'Bearer header-access-token' } })

      expect(service.extractAccessToken(req as Request)).toBe('header-access-token')
    })

    // Verifies that a non-Bearer Authorization header returns undefined to prevent misuse of Basic auth tokens.
    it('should return undefined when Authorization header is missing Bearer prefix', async () => {
      const service = await buildService('bearer')
      const req = makeReq({ headers: { authorization: 'Basic dXNlcjpwYXNz' } })

      expect(service.extractAccessToken(req as Request)).toBeUndefined()
    })

    // Verifies that readBearerHeader returns undefined early when there is no Authorization header at all.
    it('should return undefined when Authorization header is absent in bearer mode', async () => {
      // req.headers.authorization is undefined → typeof auth !== 'string' → early return undefined.
      const service = await buildService('bearer')
      const req = makeReq() // no authorization header

      expect(service.extractAccessToken(req as Request)).toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // extractRefreshToken
  // ---------------------------------------------------------------------------

  describe('extractRefreshToken', () => {
    // Verifies that extractRefreshToken reads from the cookie in cookie mode.
    it('should read from cookie in cookie mode', async () => {
      const service = await buildService('cookie')
      const req = makeReq({ cookies: { refresh_token: 'cookie-refresh-token' } })

      expect(service.extractRefreshToken(req as Request)).toBe('cookie-refresh-token')
    })

    // Verifies that extractRefreshToken reads from the request body in bearer mode.
    it('should read from request body in bearer mode', async () => {
      const service = await buildService('bearer')
      const req = makeReq({ body: { refreshToken: 'body-refresh-token' } })

      expect(service.extractRefreshToken(req as Request)).toBe('body-refresh-token')
    })

    // Verifies that readBodyRefresh returns undefined when body has no refreshToken value (not a string).
    it('should return undefined when body has no refreshToken in bearer mode', async () => {
      const service = await buildService('bearer')
      const req = makeReq() // body: {} — no refreshToken key

      expect(service.extractRefreshToken(req as Request)).toBeUndefined()
    })

    // Verifies that the cookie takes precedence over the request body in both mode.
    it('should prefer cookie over body in both mode', async () => {
      const service = await buildService('both')
      const req = makeReq({
        cookies: { refresh_token: 'cookie-refresh-token' },
        body: { refreshToken: 'body-refresh-token' }
      })

      expect(service.extractRefreshToken(req as Request)).toBe('cookie-refresh-token')
    })

    // Verifies that extractRefreshToken falls back to the request body when the cookie is absent in both mode.
    it('should fall back to request body when cookie is absent in both mode', async () => {
      // No refresh_token cookie → readCookie returns undefined → ?? triggers readBodyRefresh.
      const service = await buildService('both')
      const req = makeReq({ body: { refreshToken: 'body-only-token' } })

      expect(service.extractRefreshToken(req as Request)).toBe('body-only-token')
    })
  })

  // ---------------------------------------------------------------------------
  // clearAuthSession
  // ---------------------------------------------------------------------------

  describe('clearAuthSession', () => {
    // Verifies that clearAuthSession clears all three auth cookies in cookie mode.
    it('should clear access_token, refresh_token, and has_session cookies in cookie mode', async () => {
      const service = await buildService('cookie')
      const res = makeRes()
      const req = makeReq()

      service.clearAuthSession(res as Response, req as Request)

      const clearedNames = (res.clearCookie as jest.Mock).mock.calls.map(
        (call: [string, ...unknown[]]) => call[0]
      )
      expect(clearedNames).toContain('access_token')
      expect(clearedNames).toContain('refresh_token')
      expect(clearedNames).toContain('has_session')
    })

    // Verifies that clearAuthSession is a no-op in bearer mode since no cookies were set.
    it('should be a no-op in bearer mode', async () => {
      const service = await buildService('bearer')
      const res = makeRes()
      const req = makeReq()

      service.clearAuthSession(res as Response, req as Request)

      expect(res.clearCookie).not.toHaveBeenCalled()
    })

    // Verifies that clearAuthSession uses [undefined] as the domain list when no valid domain can be resolved.
    it('should clear cookies without a domain attribute when hostname is empty', async () => {
      // hostname: '' → extractDomain returns undefined → resolveCookieDomains returns []
      // → clearOn falls back to [undefined], triggering the domains.length === 0 branch.
      const service = await buildService('cookie')
      const res = makeRes()
      const req = makeReq({ hostname: '' })

      service.clearAuthSession(res as Response, req as Request)

      // Cookies are still cleared (once, without a domain attribute).
      expect(res.clearCookie).toHaveBeenCalled()
    })

    // Verifies that clearAuthSession works when req is omitted (e.g. non-HTTP contexts).
    it('should clear cookies using no domain when req is not provided', async () => {
      // When req is undefined, resolveCookieDomains returns [] and clearOn is [undefined].
      const service = await buildService('cookie')
      const res = makeRes()

      service.clearAuthSession(res as Response)

      expect(res.clearCookie).toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // extractDomain
  // ---------------------------------------------------------------------------

  describe('extractDomain', () => {
    // Verifies that a valid hostname is returned as the cookie domain.
    it('should return the request hostname when valid', async () => {
      const service = await buildService('cookie')
      const req = makeReq({ hostname: 'app.example.com' })

      expect(service.extractDomain(req as Request)).toBe('app.example.com')
    })

    // Verifies that a hostname containing injection characters is rejected to prevent header injection.
    it('should return undefined when hostname contains invalid chars', async () => {
      const service = await buildService('cookie')
      const req = makeReq({ hostname: 'evil.com; Path=/' })

      expect(service.extractDomain(req as Request)).toBeUndefined()
    })

    // Verifies that an empty hostname returns undefined rather than setting an empty domain attribute.
    it('should return undefined when hostname is empty', async () => {
      const service = await buildService('cookie')
      const req = makeReq({ hostname: '' })

      expect(service.extractDomain(req as Request)).toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // resolveCookieDomains with resolveDomains callback
  // ---------------------------------------------------------------------------

  describe('resolveCookieDomains with resolveDomains callback', () => {
    // Verifies that when resolveDomains is configured, cookies are set for each domain it returns.
    it('should use resolveDomains callback result when configured and set cookies for each domain', async () => {
      const resolveDomains = jest.fn().mockReturnValue(['.example.com', '.api.example.com'])
      const options = {
        ...makeOptions('cookie'),
        cookies: {
          ...makeOptions('cookie').cookies,
          resolveDomains
        }
      }

      const service = await buildServiceWithOptions(options as never)
      const res = makeRes()
      const req = makeReq({ hostname: 'app.example.com' })

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      // resolveDomains returns 2 domains — cookies should be called twice for each of 3 cookie types.
      expect(resolveDomains).toHaveBeenCalledWith('app.example.com')
      // At minimum 6 cookie calls (3 cookies × 2 domains).
      expect((res.cookie as jest.Mock).mock.calls.length).toBeGreaterThanOrEqual(6)
    })

    // Verifies that resolveDomains receives an empty string when extractDomain returns undefined (invalid hostname).
    it('should pass empty string to resolveDomains when hostname is invalid', async () => {
      // extractDomain returns undefined for empty hostname → hostname ?? '' gives '' on line 220.
      const resolveDomains = jest.fn().mockReturnValue(['.example.com'])
      const options = {
        ...makeOptions('cookie'),
        cookies: {
          ...makeOptions('cookie').cookies,
          resolveDomains
        }
      }

      const service = await buildServiceWithOptions(options as never)
      const res = makeRes()
      const req = makeReq({ hostname: '' }) // invalid → extractDomain returns undefined

      service.deliverAuthResponse(res as Response, AUTH_RESULT, req as Request)

      // resolveDomains must be called with '' (the ?? '' fallback for undefined hostname).
      expect(resolveDomains).toHaveBeenCalledWith('')
    })
  })

  // ---------------------------------------------------------------------------
  // deliverPlatformAuthResponse
  // ---------------------------------------------------------------------------

  describe('deliverPlatformAuthResponse', () => {
    const SAFE_ADMIN = {
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

    const PLATFORM_RESULT = {
      admin: SAFE_ADMIN,
      accessToken: 'platform.access.jwt',
      rawRefreshToken: 'raw-platform-refresh-uuid'
    }

    // Verifies that deliverPlatformAuthResponse returns admin, accessToken, and refreshToken
    // where refreshToken is the renamed rawRefreshToken.
    it('should return { admin, accessToken, refreshToken } with refreshToken equal to rawRefreshToken', async () => {
      const service = await buildService('cookie')

      const result = service.deliverPlatformAuthResponse(PLATFORM_RESULT)

      expect(result).toEqual({
        admin: SAFE_ADMIN,
        accessToken: 'platform.access.jwt',
        refreshToken: 'raw-platform-refresh-uuid'
      })
      expect(result.refreshToken).toBe(PLATFORM_RESULT.rawRefreshToken)
    })

    // Verifies that deliverPlatformAuthResponse does NOT set any cookies — it takes no res parameter.
    it('should not set any cookies — the method accepts no res parameter', async () => {
      // deliverPlatformAuthResponse has no res parameter so there is no mechanism to call res.cookie().
      // This test ensures the signature stays that way — if a res parameter were accidentally added
      // and used, the mock res would record those calls.
      const service = await buildService('cookie')
      const res = makeRes()

      // Call the method; res is intentionally NOT passed.
      service.deliverPlatformAuthResponse(PLATFORM_RESULT)

      // No cookie should have been set.
      expect(res.cookie).not.toHaveBeenCalled()
    })

    // Verifies that the result does NOT contain a 'rawRefreshToken' key — the internal naming
    // convention must not leak into the serialised HTTP response.
    it('should expose refreshToken in the response (not rawRefreshToken)', async () => {
      const service = await buildService('bearer')

      const result = service.deliverPlatformAuthResponse(PLATFORM_RESULT)

      expect(result).toHaveProperty('refreshToken')
      expect(result).not.toHaveProperty('rawRefreshToken')
    })

    // Verifies behaviour is the same regardless of the configured tokenDelivery mode.
    it('should always return bearer body regardless of the module tokenDelivery mode', async () => {
      const cookieService = await buildService('cookie')
      const bearerService = await buildService('bearer')
      const bothService = await buildService('both')

      const cookieResult = cookieService.deliverPlatformAuthResponse(PLATFORM_RESULT)
      const bearerResult = bearerService.deliverPlatformAuthResponse(PLATFORM_RESULT)
      const bothResult = bothService.deliverPlatformAuthResponse(PLATFORM_RESULT)

      const expected = {
        admin: SAFE_ADMIN,
        accessToken: 'platform.access.jwt',
        refreshToken: 'raw-platform-refresh-uuid'
      }
      expect(cookieResult).toEqual(expected)
      expect(bearerResult).toEqual(expected)
      expect(bothResult).toEqual(expected)
    })
  })

  // ---------------------------------------------------------------------------
  // extractPlatformRefreshToken
  // ---------------------------------------------------------------------------

  describe('extractPlatformRefreshToken', () => {
    // Returns the refresh token string from req.body.refreshToken when present.
    it('should return req.body.refreshToken when it is a string', async () => {
      const service = await buildService('cookie') // mode does not matter
      const req = makeReq({ body: { refreshToken: 'platform-rt-value' } })

      expect(service.extractPlatformRefreshToken(req as Request)).toBe('platform-rt-value')
    })

    // Returns undefined when the body contains no refreshToken key.
    it('should return undefined when body has no refreshToken property', async () => {
      const service = await buildService('bearer')
      const req = makeReq({ body: {} })

      expect(service.extractPlatformRefreshToken(req as Request)).toBeUndefined()
    })

    // Returns undefined when req.body is absent entirely.
    it('should return undefined when req.body is absent', async () => {
      const service = await buildService('cookie')
      // Cast through unknown to allow omitting body in the test stub.
      const req = { headers: {}, cookies: {} } as unknown as Request

      expect(service.extractPlatformRefreshToken(req)).toBeUndefined()
    })

    // Non-string body.refreshToken values are rejected — only strings are valid tokens.
    it('should return undefined when body.refreshToken is not a string (e.g. a number)', async () => {
      const service = await buildService('bearer')
      const req = makeReq({ body: { refreshToken: 12345 } })

      expect(service.extractPlatformRefreshToken(req as Request)).toBeUndefined()
    })

    // Always reads from body regardless of the module-level tokenDelivery mode.
    it('should always read from req.body regardless of the configured tokenDelivery mode', async () => {
      const cookieService = await buildService('cookie')
      const bearerService = await buildService('bearer')
      const bothService = await buildService('both')

      const req = makeReq({ body: { refreshToken: 'body-rt' } })

      expect(cookieService.extractPlatformRefreshToken(req as Request)).toBe('body-rt')
      expect(bearerService.extractPlatformRefreshToken(req as Request)).toBe('body-rt')
      expect(bothService.extractPlatformRefreshToken(req as Request)).toBe('body-rt')
    })
  })

  // ---------------------------------------------------------------------------
  // extractPlatformAccessToken
  // ---------------------------------------------------------------------------

  describe('extractPlatformAccessToken', () => {
    // Returns the bearer token from the Authorization header when correctly formatted.
    it('should return the bearer token from Authorization: Bearer <token> header', async () => {
      const service = await buildService('cookie') // mode does not matter
      const req = makeReq({ headers: { authorization: 'Bearer platform-access-jwt' } })

      expect(service.extractPlatformAccessToken(req as Request)).toBe('platform-access-jwt')
    })

    // Returns undefined when there is no Authorization header at all.
    it('should return undefined when the Authorization header is absent', async () => {
      const service = await buildService('bearer')
      const req = makeReq({ headers: {} })

      expect(service.extractPlatformAccessToken(req as Request)).toBeUndefined()
    })

    // Returns undefined when the Authorization header does not use the Bearer scheme.
    it('should return undefined when Authorization header uses a non-Bearer scheme', async () => {
      const service = await buildService('cookie')
      const req = makeReq({ headers: { authorization: 'Basic dXNlcjpwYXNz' } })

      expect(service.extractPlatformAccessToken(req as Request)).toBeUndefined()
    })

    // Always reads from the Authorization header regardless of the module-level tokenDelivery mode.
    it('should always read from the Authorization header regardless of the configured tokenDelivery mode', async () => {
      const cookieService = await buildService('cookie')
      const bearerService = await buildService('bearer')
      const bothService = await buildService('both')

      const req = makeReq({ headers: { authorization: 'Bearer always-bearer' } })

      expect(cookieService.extractPlatformAccessToken(req as Request)).toBe('always-bearer')
      expect(bearerService.extractPlatformAccessToken(req as Request)).toBe('always-bearer')
      expect(bothService.extractPlatformAccessToken(req as Request)).toBe('always-bearer')
    })
  })
})
