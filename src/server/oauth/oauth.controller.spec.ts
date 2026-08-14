/**
 * OAuthController — unit tests
 *
 * Verifies that OAuthController correctly delegates to OAuthService and
 * TokenDeliveryService with properly extracted request metadata.
 *
 * The controller is thin: it reads provider from the route param, validates
 * query DTOs, slices ip/userAgent to the documented limits (64/512 chars),
 * and forwards headers. All business logic lives in OAuthService.
 *
 * Mocking strategy: OAuthService and TokenDeliveryService are plain jest mock
 * objects. The controller is instantiated directly (no full NestJS testing
 * module needed) since there are no DI-resolved decorators that affect the
 * method logic. This keeps the tests fast and focused on the controller's
 * transformations.
 *
 * All tests follow the AAA pattern and use jest.resetAllMocks() in beforeEach.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { OAuthController } from './oauth.controller'
import { OAuthService } from './oauth.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const MOCK_BEARER_RESPONSE = { accessToken: 'at.jwt' }

const mockOAuthService = {
  initiateOAuth: jest.fn(),
  handleCallback: jest.fn()
}

const mockTokenDelivery = {
  deliverAuthResponse: jest.fn()
}

// ---------------------------------------------------------------------------
// OAuthController
// ---------------------------------------------------------------------------

/**
 * Builds a minimal `ResolvedOptions` shape sufficient for the controller. The
 * controller reads `oauth.{successRedirectUrl,mfaRedirectUrl,errorRedirectUrl}`,
 * `routePrefix`, `secureCookies`, `cookies.sameSite`, and
 * `cookies.mfaTempCookiePath` — the rest of the shape is intentionally left
 * as `unknown` via the cast so the fixture does not need to mirror the full
 * options tree.
 */
function buildOptions(oauth?: ResolvedOptions['oauth']): ResolvedOptions {
  return {
    oauth,
    routePrefix: 'auth',
    secureCookies: false,
    cookies: { sameSite: 'lax', mfaTempCookiePath: '/auth/mfa' }
  } as unknown as ResolvedOptions
}

describe('OAuthController', () => {
  let controller: OAuthController

  /**
   * Compiles the controller with the supplied OAuth options block. Tests
   * exercising the redirect path call this with `{ successRedirectUrl: ... }`;
   * the default `buildOptions()` produces an empty options object so the
   * controller falls through to returning the JSON body (legacy contract).
   */
  async function bootstrap(oauth?: ResolvedOptions['oauth']): Promise<void> {
    const module = await Test.createTestingModule({
      controllers: [OAuthController],
      providers: [
        { provide: OAuthService, useValue: mockOAuthService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery },
        { provide: BYMAX_AUTH_OPTIONS, useValue: buildOptions(oauth) }
      ]
    })
      .overrideGuard(TrustedOriginGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AuthRateLimitGuard)
      .useValue({ canActivate: () => true })
      .compile()

    controller = module.get(OAuthController)
  }

  beforeEach(async () => {
    jest.resetAllMocks()
    await bootstrap()
  })

  // ---------------------------------------------------------------------------
  // initiate()
  // ---------------------------------------------------------------------------

  describe('initiate()', () => {
    // Verifies the happy path: initiateOAuth is called with the correct provider, the tenantId
    // from the query DTO, the request (which the configured resolver reads, and which decides
    // the tenant when there is one), and the response object.
    it('should call oauthService.initiateOAuth with provider, tenantId, req and res', async () => {
      mockOAuthService.initiateOAuth.mockResolvedValue(undefined)
      const mockRes = { redirect: jest.fn() } as unknown as Response
      const mockReq = { headers: {} } as unknown as Request
      const query = { tenantId: 'tenant-abc' }

      await controller.initiate('google', query as never, mockReq, mockRes)

      expect(mockOAuthService.initiateOAuth).toHaveBeenCalledWith(
        'google',
        'tenant-abc',
        mockReq,
        mockRes
      )
    })

    // Verifies that initiate() returns void (undefined) — the redirect is performed
    // inside the service via the response object, not via a return value.
    it('should return undefined (void)', async () => {
      mockOAuthService.initiateOAuth.mockResolvedValue(undefined)
      const mockRes = { redirect: jest.fn() } as unknown as Response
      const query = { tenantId: 'tenant-1' }

      const result = await controller.initiate(
        'google',
        query as never,
        { headers: {} } as unknown as Request,
        mockRes
      )

      expect(result).toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // callback()
  // ---------------------------------------------------------------------------

  describe('callback()', () => {
    const makeReq = (
      ip = '1.2.3.4',
      userAgent = 'TestBrowser/1.0',
      extraHeaders: Record<string, string> = {},
      cookies: Record<string, unknown> = { oauth_state: 'csrf-state-abc' }
    ) =>
      ({
        ip,
        headers: { 'user-agent': userAgent, ...extraHeaders },
        cookies
      }) as unknown as Request

    // Verifies the happy path: handleCallback is called with all correct arguments,
    // and the return value of deliverAuthResponse is returned to the caller.
    it('should call handleCallback with correct args and return deliverAuthResponse result', async () => {
      const mockReq = makeReq()
      const mockRes = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'auth-code-xyz', state: 'csrf-state-abc' }

      mockOAuthService.handleCallback.mockResolvedValue({ accessToken: 'at' })
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue(MOCK_BEARER_RESPONSE)

      const result = await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockOAuthService.handleCallback).toHaveBeenCalledWith(
        'google',
        'auth-code-xyz',
        'csrf-state-abc',
        'csrf-state-abc',
        '1.2.3.4',
        'TestBrowser/1.0',
        mockReq.headers
      )
      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        { accessToken: 'at' },
        mockReq
      )
      expect(result).toBe(MOCK_BEARER_RESPONSE)
    })

    // Verifies that a long IP address is truncated to 64 characters before being
    // passed to handleCallback — prevents unbounded string storage in tokens.
    it('should truncate ip to 64 characters', async () => {
      const longIp = 'a'.repeat(90)
      const mockReq = makeReq(longIp)
      const mockRes = { clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const ipArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[4]
      expect(typeof ipArg).toBe('string')
      expect((ipArg as string).length).toBe(64)
      expect(ipArg).toBe(longIp.slice(0, 64))
    })

    // Verifies that a long User-Agent string is truncated to 512 characters —
    // prevents malformed UA strings from exceeding storage limits.
    it('should truncate userAgent to 512 characters', async () => {
      const longUA = 'B'.repeat(600)
      const mockReq = makeReq('1.2.3.4', longUA)
      const mockRes = { clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const uaArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[5]
      expect(typeof uaArg).toBe('string')
      expect((uaArg as string).length).toBe(512)
      expect(uaArg).toBe(longUA.slice(0, 512))
    })

    // Verifies that when req.ip is undefined (some reverse-proxy setups), the ip
    // argument falls back to an empty string rather than the literal 'undefined'.
    it('should fall back to empty string when req.ip is undefined', async () => {
      const mockReq = {
        ip: undefined,
        headers: { 'user-agent': 'UA' },
        cookies: {}
      } as unknown as Request
      const mockRes = { clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const ipArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[4]
      expect(ipArg).toBe('')
    })

    // A provider that refuses before minting a code (RFC 6749 §4.1.2.1) — the response Google
    // sends when the user clicks "Cancel". It carries `error` and no `code`, which the
    // ValidationPipe used to 400 for the missing required field: a user who simply changed
    // their mind saw a raw validation envelope instead of the configured error redirect.
    it('should route a provider error callback to the error redirect', async () => {
      const mockReq = makeReq()
      const mockRes = { clearCookie: jest.fn(), redirect: jest.fn() } as unknown as Response
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      const result = await controller.callback(
        'google',
        { state: 'csrf-state-abc', error: 'access_denied' } as never,
        mockReq,
        mockRes
      )

      expect(result).toBeUndefined()
      expect(mockRes.redirect).toHaveBeenCalledWith('/auth/error?error=oauth_failed')
      // The provider never reaches the exchange: there is no code to exchange, and calling
      // the service would burn the state on a flow that is already over.
      expect(mockOAuthService.handleCallback).not.toHaveBeenCalled()
      // The single-use state cookie is spent either way.
      expect(mockRes.clearCookie).toHaveBeenCalledWith('oauth_state', expect.anything())
    })

    // Neither value may reach the log verbatim. `error` is a query parameter with only a
    // length bound and `provider` is a percent-decoded path segment logged before the plugin
    // shape check runs, so a newline in either forges whole log records — a fabricated "login
    // success userId=admin" line sitting in the operator's SIEM.
    it.each([
      ['a newline in the provider error', { error: 'a\nFAKE LOG LINE' }],
      ['a carriage return in the provider error', { error: 'a\rFAKE' }],
      ['an uppercase value', { error: 'ACCESS_DENIED' }],
      ['an over-long value', { error: 'a'.repeat(65) }]
    ])('should not let %s reach the log verbatim', async (_label, extra) => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      const mockReq = makeReq()
      const mockRes = { clearCookie: jest.fn(), redirect: jest.fn() } as unknown as Response
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      await controller.callback(
        'google',
        { state: 'csrf-state-abc', ...extra } as never,
        mockReq,
        mockRes
      )

      const logged = warn.mock.calls.map((call) => String(call[0])).join('\n')
      expect(logged).toContain('<malformed>')
      expect(logged).not.toContain('FAKE')
      expect(logged).not.toContain('ACCESS_DENIED')
      warn.mockRestore()
    })

    // A recognisable code is logged as-is — the point is to keep the useful signal, not to
    // blank every value.
    it('should log a well-formed provider error code verbatim', async () => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      const mockReq = makeReq()
      const mockRes = { clearCookie: jest.fn(), redirect: jest.fn() } as unknown as Response
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      await controller.callback(
        'google',
        { state: 'csrf-state-abc', error: 'access_denied' } as never,
        mockReq,
        mockRes
      )

      expect(warn.mock.calls.map((call) => String(call[0])).join('\n')).toContain('access_denied')
      warn.mockRestore()
    })

    // The provider's own string never reaches the redirect. It is provider-chosen text landing
    // in a URL the browser follows, and `oauth_failed` already tells the caller everything the
    // library is willing to vouch for.
    it('should not echo the provider error code into the redirect', async () => {
      const mockReq = makeReq()
      const mockRes = { clearCookie: jest.fn(), redirect: jest.fn() } as unknown as Response
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      await controller.callback(
        'google',
        {
          state: 'csrf-state-abc',
          error: 'temporarily_unavailable',
          error_description: 'try later'
        } as never,
        mockReq,
        mockRes
      )

      const redirectTo = (mockRes.redirect as jest.Mock).mock.calls[0]?.[0] as string
      expect(redirectTo).not.toContain('temporarily_unavailable')
      expect(redirectTo).not.toContain('try later')
    })

    // A callback carrying neither `code` nor `error`. The body below is one the pipe really
    // produces now — `code` is optional on the DTO, so this shape arrives at the handler
    // instead of being refused in front of it. What makes the path *reachable* is proven over
    // HTTP in `test/e2e/declared-structures.e2e-spec.ts`; this pins the redirect target, which a unit
    // test can read directly off the mock. Defaulting the missing code to an empty string
    // instead would send it to the provider's token endpoint and surface their error, not ours.
    it('should refuse a callback carrying neither code nor error', async () => {
      const mockReq = makeReq()
      const mockRes = { clearCookie: jest.fn(), redirect: jest.fn() } as unknown as Response
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      await controller.callback('google', { state: 'csrf-state-abc' } as never, mockReq, mockRes)

      expect(mockRes.redirect).toHaveBeenCalledWith('/auth/error?error=oauth_failed')
      expect(mockOAuthService.handleCallback).not.toHaveBeenCalled()
    })

    // With no error redirect configured the refusal propagates as the library's own
    // AuthException — the same shape any other OAuth failure takes on that deployment.
    it('should throw OAUTH_FAILED for a provider error when no error redirect is configured', async () => {
      const { AuthException } = await import('../errors/auth-exception')
      const mockReq = makeReq()
      const mockRes = { clearCookie: jest.fn() } as unknown as Response

      await expect(
        controller.callback(
          'google',
          { state: 'csrf-state-abc', error: 'access_denied' } as never,
          mockReq,
          mockRes
        )
      ).rejects.toThrow(AuthException)
    })

    // Verifies the controller reads the `oauth_state` cookie and hands it to the service —
    // the service does the comparison, but it can only do so if the controller forwards what
    // the browser sent. Pinned separately because a controller that silently forwards
    // `undefined` would leave the service's binding check permanently unsatisfiable.
    it('should forward the oauth_state cookie to handleCallback', async () => {
      const mockReq = makeReq('1.2.3.4', 'UA', {}, { oauth_state: 'cookie-state' })
      const mockRes = { clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const cookieArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[3]
      expect(cookieArg).toBe('cookie-state')
    })

    // A jar without the cookie, a non-string value, and an app that never mounted
    // cookie-parser all reach the service as `undefined` — which it treats as a refusal. The
    // non-string case is the one worth pinning: `req.cookies` is parsed from client input, so
    // a caller can put an array there, and `String(value)` would turn that into a comparison
    // against something that never was a cookie.
    it.each([
      ['an empty jar', {}],
      ['a non-string value', { oauth_state: ['a', 'b'] }],
      ['an empty string', { oauth_state: '' }]
    ])('should forward undefined for %s', async (_label, cookies) => {
      const mockReq = makeReq('1.2.3.4', 'UA', {}, cookies)
      const mockRes = { clearCookie: jest.fn() } as unknown as Response

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback(
        'google',
        { code: 'code', state: 'state' } as never,
        mockReq,
        mockRes
      )

      expect((mockOAuthService.handleCallback.mock.calls[0] as unknown[])[3]).toBeUndefined()
    })

    // An app that never mounted cookie-parser leaves `req.cookies` undefined entirely — a
    // different branch from an empty jar, and one that would throw rather than refuse if the
    // guard were dropped.
    it('should forward undefined when cookie-parser is not mounted', async () => {
      const mockReq = { ip: '1.2.3.4', headers: {} } as unknown as Request
      const mockRes = { clearCookie: jest.fn() } as unknown as Response

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback(
        'google',
        { code: 'code', state: 'state' } as never,
        mockReq,
        mockRes
      )

      expect((mockOAuthService.handleCallback.mock.calls[0] as unknown[])[3]).toBeUndefined()
    })

    // The cookie is single-use and must be cleared whatever the callback's outcome; a stale
    // one left behind would never match the next flow's freshly minted state, turning one
    // failed login into a permanently broken one. The clear attributes must match the plant
    // attributes or the browser keeps the original cookie.
    it('should clear the oauth_state cookie on the callback', async () => {
      const mockReq = makeReq()
      const mockRes = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback(
        'google',
        { code: 'code', state: 'csrf-state-abc' } as never,
        mockReq,
        mockRes
      )

      expect(mockRes.clearCookie).toHaveBeenCalledWith('oauth_state', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/'
      })
    })

    // The clear only fires when the browser actually sent the cookie. This route is a GET, so
    // `SameSite=Lax` withholds the cookie from a cross-site subresource — an `<img
    // src=…/callback>` on any page the victim loads carries none — but a `Set-Cookie` deleting
    // it would take effect anyway. Clearing unconditionally let any page kill an OAuth login
    // that was still at the consent screen, repeatably, from anywhere.
    it('should not clear the state cookie when the request did not carry one', async () => {
      const mockReq = makeReq('1.2.3.4', 'UA', {}, {})
      const mockRes = { clearCookie: jest.fn(), redirect: jest.fn() } as unknown as Response
      await bootstrap({ errorRedirectUrl: '/auth/error' })
      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback(
        'google',
        { code: 'code', state: 'csrf-state-abc' } as never,
        mockReq,
        mockRes
      )

      expect(mockRes.clearCookie).not.toHaveBeenCalled()
    })

    // Same clearing on the failure path: a callback that the service refused must not leave
    // the cookie behind either, or the user's retry inherits a cookie from the attempt that
    // just failed.
    it('should clear the oauth_state cookie even when handleCallback throws', async () => {
      const { AuthException } = await import('../errors/auth-exception')
      const { AUTH_ERROR_CODES } = await import('../errors/auth-error-codes')

      const mockReq = makeReq()
      const mockRes = { clearCookie: jest.fn(), redirect: jest.fn() } as unknown as Response

      mockOAuthService.handleCallback.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
      )

      // No `errorRedirectUrl` on the default fixture, so the refusal propagates — the point
      // is that the cookie was already gone by then.
      await expect(
        controller.callback(
          'google',
          { code: 'code', state: 'csrf-state-abc' } as never,
          mockReq,
          mockRes
        )
      ).rejects.toThrow(AuthException)

      expect(mockRes.clearCookie).toHaveBeenCalledWith('oauth_state', expect.anything())
    })

    // Verifies that when the user-agent header is absent, the userAgent falls back
    // to an empty string rather than the literal 'undefined'.
    it('should fall back to empty string when user-agent header is absent', async () => {
      const mockReq = {
        ip: '1.2.3.4',
        headers: {},
        cookies: {}
      } as unknown as Request
      const mockRes = { clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const uaArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[5]
      expect(uaArg).toBe('')
    })

    // Verifies that the full req.headers object is forwarded as the 6th argument to
    // handleCallback so that OAuthService can pass sanitized headers to the hook context.
    it('should forward req.headers as the 6th argument to handleCallback', async () => {
      const headers = { 'user-agent': 'UA', 'x-request-id': 'req-001' }
      const mockReq = { ip: '1.2.3.4', headers, cookies: {} } as unknown as Request
      const mockRes = { clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const headersArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[6]
      expect(headersArg).toBe(headers)
    })

    // Verifies that TokenDeliveryService.deliverAuthResponse is called with the
    // correct response object (res) as the first argument so cookie delivery works.
    it('should call deliverAuthResponse with (res, result, req) in the correct order', async () => {
      const mockReq = makeReq()
      const mockRes = { cookie: jest.fn(), clearCookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }
      const authResult = { accessToken: 'tok', user: {} }

      mockOAuthService.handleCallback.mockResolvedValue(authResult)
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({ accessToken: 'tok' })

      await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        authResult,
        mockReq
      )
    })

    // ─── successRedirectUrl branch ────────────────────────────────────────────

    /**
     * Verifies that with no `oauth.successRedirectUrl` configured, the controller
     * preserves the legacy contract: it returns the body produced by
     * `deliverAuthResponse` and never touches `res.redirect`. This is the
     * default path for API/SPA consumers that XHR-fetch the callback URL.
     */
    it('should NOT redirect when oauth.successRedirectUrl is not configured', async () => {
      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue(MOCK_BEARER_RESPONSE)

      const result = await controller.callback('google', query as never, mockReq, mockRes)

      expect((mockRes.redirect as jest.Mock).mock.calls).toHaveLength(0)
      expect(result).toBe(MOCK_BEARER_RESPONSE)
    })

    /**
     * Verifies the browser-OAuth UX path: when `oauth.successRedirectUrl` is
     * configured, the controller still delegates token delivery to
     * `TokenDeliveryService` (cookies must be set on the SAME response that
     * carries the 302), then issues `res.redirect(url)` and returns `undefined`
     * so Nest does not serialise a JSON body over the redirect headers.
     */
    it('should redirect to oauth.successRedirectUrl after delivering tokens', async () => {
      await bootstrap({ successRedirectUrl: '/dashboard' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({ accessToken: 'tok' })
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({ accessToken: 'tok' })

      const result = await controller.callback('google', query as never, mockReq, mockRes)

      // Cookies are still set — token delivery runs BEFORE the redirect so the
      // Set-Cookie headers and the 302 share the same HTTP response.
      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledTimes(1)
      expect(mockRes.redirect).toHaveBeenCalledTimes(1)
      expect(mockRes.redirect).toHaveBeenCalledWith('/dashboard')
      // Returning undefined signals to Nest's passthrough mode that no body
      // should accompany the redirect.
      expect(result).toBeUndefined()
    })

    /**
     * Verifies that an absolute HTTPS URL is forwarded verbatim — the
     * controller does not perform any URL canonicalisation. Validation of
     * scheme + production HTTPS happens at boot time in `resolveOptions`,
     * not on every callback request.
     */
    it('should redirect to an absolute https successRedirectUrl when configured', async () => {
      await bootstrap({ successRedirectUrl: 'https://app.example.com/welcome' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockRes.redirect).toHaveBeenCalledWith('https://app.example.com/welcome')
    })

    // ─── MFA challenge branch (1.0.7) ──────────────────────────────────────

    /**
     * Verifies the OAuth + MFA cookie + JSON path (no `mfaRedirectUrl` set).
     * The service returns the challenge discriminator, the controller plants
     * the `mfa_temp_token` HttpOnly cookie path-scoped to the MFA challenge
     * route, and surfaces the same token in the JSON body for SPA consumers.
     * Session cookies and the 302 path must NOT fire on this branch.
     */
    it('should set mfa_temp_token cookie and return JSON body when handleCallback signals MFA required', async () => {
      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({
        mfaRequired: true,
        mfaTempToken: 'mfa.temp.jwt'
      })

      const result = await controller.callback('google', query as never, mockReq, mockRes)

      // Cookie was planted with the right shape. The Max-Age must equal
      // `MFA_TEMP_COOKIE_MAX_AGE_SECONDS * 1000` = 300_000 ms (5 min) —
      // pinned exactly to match the underlying MFA temp JWT TTL.
      expect(mockRes.cookie).toHaveBeenCalledWith('mfa_temp_token', 'mfa.temp.jwt', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/auth/mfa',
        maxAge: 300_000
      })
      // No session delivery on the MFA branch.
      expect(mockTokenDelivery.deliverAuthResponse).not.toHaveBeenCalled()
      // No redirect when mfaRedirectUrl is unset — caller returns JSON.
      expect((mockRes.redirect as jest.Mock).mock.calls).toHaveLength(0)
      expect(result).toEqual({ mfaRequired: true, mfaTempToken: 'mfa.temp.jwt' })
    })

    /**
     * Verifies the OAuth + MFA redirect path. With `oauth.mfaRedirectUrl`
     * configured, the cookie is still planted (so the destination page can
     * call `/auth/mfa/challenge` with the cookie attached) AND a 302 is
     * issued instead of returning JSON. The handler returns `undefined` so
     * Nest does not serialise a body over the redirect headers.
     */
    it('should redirect to mfaRedirectUrl when configured for the MFA branch', async () => {
      await bootstrap({ mfaRedirectUrl: '/auth/mfa-challenge' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({
        mfaRequired: true,
        mfaTempToken: 'mfa.temp.jwt'
      })

      const result = await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockRes.cookie).toHaveBeenCalledTimes(1)
      expect(mockRes.redirect).toHaveBeenCalledTimes(1)
      expect(mockRes.redirect).toHaveBeenCalledWith('/auth/mfa-challenge')
      expect(result).toBeUndefined()
    })

    /**
     * Pins the path attribute under a custom `cookies.mfaTempCookiePath`:
     * the cookie must be scoped exactly to the value the consumer set so
     * apps using `app.setGlobalPrefix(...)` can prefix-match the real
     * challenge URL (e.g. `/api/auth/mfa/challenge`).
     */
    it('should scope the mfa_temp_token cookie path to cookies.mfaTempCookiePath', async () => {
      const module = await Test.createTestingModule({
        controllers: [OAuthController],
        providers: [
          { provide: OAuthService, useValue: mockOAuthService },
          { provide: TokenDeliveryService, useValue: mockTokenDelivery },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: {
              oauth: {},
              routePrefix: 'auth',
              secureCookies: true,
              cookies: { sameSite: 'strict', mfaTempCookiePath: '/api/auth/mfa' }
            } as unknown as ResolvedOptions
          }
        ]
      })
        .overrideGuard(TrustedOriginGuard)
        .useValue({ canActivate: () => true })
        .overrideGuard(AuthRateLimitGuard)
        .useValue({ canActivate: () => true })
        .compile()
      controller = module.get(OAuthController)

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({
        mfaRequired: true,
        mfaTempToken: 'mfa.temp.jwt'
      })

      await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockRes.cookie).toHaveBeenCalledWith(
        'mfa_temp_token',
        'mfa.temp.jwt',
        expect.objectContaining({
          path: '/api/auth/mfa',
          secure: true,
          sameSite: 'strict'
        })
      )
    })

    // ─── error redirect branch (1.0.7) ─────────────────────────────────────

    /**
     * Verifies the error-redirect happy path. An `AuthException` thrown from
     * `handleCallback` is converted into a `302` to the configured
     * `errorRedirectUrl` with `?error=oauth_failed` appended. The handler
     * returns `undefined` so Nest does not serialise an error body alongside
     * the redirect headers.
     */
    it('should redirect to errorRedirectUrl with ?error code when handleCallback throws AuthException', async () => {
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      const { AuthException } = await import('../errors/auth-exception')
      const { AUTH_ERROR_CODES } = await import('../errors/auth-error-codes')

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
      )

      const result = await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockRes.redirect).toHaveBeenCalledWith('/auth/error?error=oauth_failed')
      expect(result).toBeUndefined()
    })

    /**
     * The code that reaches the query string is read out of the exception's
     * envelope, and every step of that read has a fallback. None of them is
     * reachable through `AuthException`'s own constructor — a thrown value can
     * carry any shape once a custom filter or a future subclass is in play — so
     * they are driven directly here. The fallback is what keeps a malformed
     * envelope from putting `undefined` (or an internal message) in a URL the
     * user's browser follows.
     */
    it.each([
      ['a non-object envelope', 'just a string', 'oauth_failed'],
      ['a null envelope', null, 'oauth_failed'],
      // The `typeof` half and the `null` half are independent: a callable is the
      // one value that fails `typeof x === 'object'` and can still carry an
      // `error.code`, so without the type check its code would reach the URL.
      [
        'a callable envelope carrying a code',
        Object.assign(() => undefined, { error: { code: 'auth.smuggled' } }),
        'oauth_failed'
      ],
      ['an envelope with no error object', { statusCode: 400 }, 'oauth_failed'],
      ['an envelope whose code is not a string', { error: { code: 42 } }, 'oauth_failed'],
      ['an envelope whose code is empty', { error: { code: '' } }, 'oauth_failed'],
      ['a code with no namespace prefix', { error: { code: 'bare_code' } }, 'bare_code'],
      ['a code that is only a prefix separator', { error: { code: '.suffix' } }, 'suffix']
    ])('should fall back sensibly on %s', async (_label, response, expected) => {
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      const { AuthException } = await import('../errors/auth-exception')
      const { AUTH_ERROR_CODES } = await import('../errors/auth-error-codes')

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response

      const exception = new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
      jest.spyOn(exception, 'getResponse').mockReturnValue(response as never)
      mockOAuthService.handleCallback.mockRejectedValue(exception)

      await controller.callback('google', { code: 'c', state: 's' } as never, mockReq, mockRes)

      expect(mockRes.redirect).toHaveBeenCalledWith(`/auth/error?error=${expected}`)
    })

    /**
     * The MFA branch is chosen by a literal `true`, not by the key's presence.
     * A result that carries the key set to `false` is a completed sign-in, and
     * routing it to the challenge page would strand a user who has already
     * authenticated — with tokens issued and no way back to them.
     */
    it('should treat mfaRequired: false as a completed sign-in', async () => {
      await bootstrap({ successRedirectUrl: '/dashboard', mfaRedirectUrl: '/mfa' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response

      mockOAuthService.handleCallback.mockResolvedValue({
        mfaRequired: false,
        accessToken: 'access',
        refreshToken: 'refresh',
        user: { id: 'u1', email: 'u@e.com' }
      } as never)

      await controller.callback('google', { code: 'c', state: 's' } as never, mockReq, mockRes)

      expect(mockRes.redirect).toHaveBeenCalledWith('/dashboard')
    })

    /**
     * Pins that an absolute URL passes through the WHATWG `URL` constructor:
     * existing query parameters are preserved AND the error code is appended
     * as a new param.
     */
    it('should preserve existing query params on absolute errorRedirectUrl', async () => {
      await bootstrap({ errorRedirectUrl: 'https://app.example.com/login?from=oauth' })

      const { AuthException } = await import('../errors/auth-exception')
      const { AUTH_ERROR_CODES } = await import('../errors/auth-error-codes')

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
      )

      await controller.callback('google', query as never, mockReq, mockRes)

      const target = (mockRes.redirect as jest.Mock).mock.calls[0]?.[0] as string
      // The URL parser may re-order params; assert both keys are present.
      expect(target).toMatch(/^https:\/\/app\.example\.com\/login\?/)
      expect(target).toContain('from=oauth')
      expect(target).toContain('error=oauth_failed')
    })

    /**
     * Verifies the failure-mode without `errorRedirectUrl`: existing
     * behaviour is preserved — the `AuthException` propagates so NestJS's
     * exception filter renders the standard JSON 401/500 response.
     */
    it('should rethrow AuthException when no errorRedirectUrl is configured', async () => {
      const { AuthException } = await import('../errors/auth-exception')
      const { AUTH_ERROR_CODES } = await import('../errors/auth-error-codes')

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockRejectedValue(
        new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED)
      )

      await expect(controller.callback('google', query as never, mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
      expect(mockRes.redirect).not.toHaveBeenCalled()
    })

    /**
     * Pins the policy that non-AuthException errors propagate even when
     * `errorRedirectUrl` is configured. Programmer bugs and infrastructure
     * failures must surface to monitoring tooling rather than be silently
     * converted into a friendly redirect.
     */
    it('should rethrow non-AuthException errors even when errorRedirectUrl is configured', async () => {
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockRejectedValue(new Error('boom — programmer error'))

      await expect(controller.callback('google', query as never, mockReq, mockRes)).rejects.toThrow(
        'boom — programmer error'
      )
      expect(mockRes.redirect).not.toHaveBeenCalled()
    })

    /**
     * Edge case: an `AuthException` whose response shape lacks the standard
     * `error.code` envelope. The controller falls back to `'oauth_failed'`
     * as the URL query value so the redirect still happens with a meaningful
     * code instead of crashing or surfacing `undefined`.
     */
    it('should fall back to oauth_failed when the AuthException has no error.code', async () => {
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      const { AuthException } = await import('../errors/auth-exception')
      // Construct an AuthException-like that returns a non-object response.
      const fakeExc = new AuthException(
        // Cast to satisfy the constructor — only `getResponse()` is exercised.
        'auth.oauth_failed' as never
      )
      // Override getResponse to return a non-object (defence-in-depth path).
      jest.spyOn(fakeExc, 'getResponse').mockReturnValue('not-an-object' as never)
      mockOAuthService.handleCallback.mockRejectedValue(fakeExc)

      await controller.callback('google', query as never, mockReq, mockRes)
      expect(mockRes.redirect).toHaveBeenCalledWith('/auth/error?error=oauth_failed')
    })

    /**
     * Edge case: an `AuthException` whose code is a non-string falls back to
     * `'oauth_failed'`. Pins the `code` extraction guard against malformed
     * future codes or runtime tampering.
     */
    it('should fall back to oauth_failed when the AuthException code is not a string', async () => {
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      const { AuthException } = await import('../errors/auth-exception')
      const fakeExc = new AuthException('auth.oauth_failed' as never)
      jest
        .spyOn(fakeExc, 'getResponse')
        .mockReturnValue({ error: { code: 42 } } as unknown as Record<string, unknown>)
      mockOAuthService.handleCallback.mockRejectedValue(fakeExc)

      await controller.callback('google', query as never, mockReq, mockRes)
      expect(mockRes.redirect).toHaveBeenCalledWith('/auth/error?error=oauth_failed')
    })

    /**
     * Edge case: an `AuthException` whose code lacks the `auth.` prefix is
     * forwarded verbatim. Defence-in-depth so future codes that diverge from
     * the convention still produce a meaningful URL parameter.
     */
    it('should forward the code verbatim when it lacks the auth. prefix', async () => {
      await bootstrap({ errorRedirectUrl: '/auth/error' })

      const mockReq = makeReq()
      const mockRes = {
        cookie: jest.fn(),
        clearCookie: jest.fn(),
        redirect: jest.fn()
      } as unknown as Response
      const query = { code: 'code', state: 'state' }

      const { AuthException } = await import('../errors/auth-exception')
      const fakeExc = new AuthException('auth.oauth_failed' as never)
      jest
        .spyOn(fakeExc, 'getResponse')
        .mockReturnValue({ error: { code: 'custom_code' } } as unknown as Record<string, unknown>)
      mockOAuthService.handleCallback.mockRejectedValue(fakeExc)

      await controller.callback('google', query as never, mockReq, mockRes)
      expect(mockRes.redirect).toHaveBeenCalledWith('/auth/error?error=custom_code')
    })
  })
})
