/**
 * OAuth 2.0 controller for @bymax-one/nest-auth.
 *
 * Exposes two endpoints per provider:
 *  - `GET /oauth/:provider?tenantId=xxx` — initiates the flow (302 redirect to provider).
 *  - `GET /oauth/:provider/callback?code=xxx&state=xxx` — handles the provider callback.
 *
 * Route prefix (`oauth`) is relative — the consuming application applies a global prefix
 * (e.g. `/auth`) via `RouterModule` or `setGlobalPrefix`, producing final routes such as
 * `/auth/oauth/google` and `/auth/oauth/google/callback`.
 *
 * Both endpoints are `@Public()` — the OAuth flow is unauthenticated by design.
 * `@SkipMfa()` prevents `MfaRequiredGuard` from blocking the callback route when
 * it is applied globally.
 *
 * @layer Controller
 */

import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Query,
  Req,
  Res,
  UsePipes,
  ValidationPipe
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request, Response } from 'express'

import { OAuthService } from './oauth.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { MFA_TEMP_COOKIE_MAX_AGE_SECONDS, MFA_TEMP_COOKIE_NAME } from '../constants/mfa-temp-cookie'
import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { Public } from '../decorators/public.decorator'
import { SkipMfa } from '../decorators/skip-mfa.decorator'
import { OAuthCallbackQueryDto } from '../dto/oauth-callback-query.dto'
import { OAuthInitiateQueryDto } from '../dto/oauth-initiate-query.dto'
import { AuthException } from '../errors/auth-exception'
import type { AuthResult, OAuthMfaChallengeResult } from '../interfaces/auth-result.interface'
import type {
  BearerAuthResponse,
  BothAuthResponse,
  CookieAuthResponse
} from '../services/token-delivery.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Narrows the `OAuthService.handleCallback` return value to its MFA challenge
 * branch using the literal `mfaRequired: true` discriminant.
 */
function isOAuthMfaChallenge(
  result: AuthResult | OAuthMfaChallengeResult
): result is OAuthMfaChallengeResult {
  return 'mfaRequired' in result && result.mfaRequired === true
}

/**
 * Extracts the short error code suffix from an `AuthException` code string.
 *
 * `AuthException` codes follow the `auth.<code>` convention (e.g.
 * `auth.oauth_failed`). For URL query parameters we surface just the suffix
 * (`oauth_failed`) so consumers can build user-facing pages without exposing
 * the internal `auth.` namespace prefix. Codes without a dot are returned
 * verbatim as a defence-in-depth fallback.
 */
function extractErrorCode(exception: AuthException): string {
  const response = exception.getResponse()
  if (typeof response !== 'object' || response === null) {
    return 'oauth_failed'
  }
  const envelope = response as { error?: { code?: unknown } }
  const code = envelope.error?.code
  if (typeof code !== 'string' || code.length === 0) {
    return 'oauth_failed'
  }
  const dotIndex = code.indexOf('.')
  return dotIndex >= 0 ? code.slice(dotIndex + 1) : code
}

/**
 * Appends an `error` query parameter to a redirect URL while preserving any
 * existing query string. Uses the WHATWG `URL` constructor for absolute URLs
 * (`http(s)://...`) and a placeholder base for same-origin relative paths
 * (`/dashboard?foo=bar`), since `URL` rejects bare paths without a base.
 */
function appendErrorQueryParam(url: string, errorCode: string): string {
  if (url.startsWith('/')) {
    const dummyBase = 'http://placeholder.invalid'
    const parsed = new URL(url, dummyBase)
    parsed.searchParams.set('error', errorCode)
    return parsed.pathname + parsed.search + parsed.hash
  }
  const parsed = new URL(url)
  parsed.searchParams.set('error', errorCode)
  return parsed.toString()
}

// ---------------------------------------------------------------------------
// OAuthController
// ---------------------------------------------------------------------------

/**
 * Handles the provider-agnostic OAuth 2.0 Authorization Code flow.
 *
 * Both routes delegate all business logic to {@link OAuthService}. This controller
 * is thin — it validates query parameters, extracts request metadata (IP, UA), and
 * delivers the auth response via {@link TokenDeliveryService}.
 */
@Public()
@SkipMfa()
@Controller('oauth')
@UsePipes(
  new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, forbidUnknownValues: true })
)
export class OAuthController {
  constructor(
    private readonly oauthService: OAuthService,
    private readonly tokenDelivery: TokenDeliveryService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  // ---------------------------------------------------------------------------
  // GET /oauth/:provider
  // ---------------------------------------------------------------------------

  /**
   * Initiates the OAuth 2.0 flow for the given provider.
   *
   * Generates a CSRF state nonce, stores it in Redis, and redirects the user to
   * the provider's authorization URL. The `tenantId` query parameter is validated
   * via {@link OAuthInitiateQueryDto} — an empty or oversized value is rejected
   * before reaching the service layer.
   *
   * @param provider - Provider name (e.g. `'google'`). Must match a registered plugin.
   * @param query - Validated query parameters (contains `tenantId`).
   * @param res - Express response object (used to issue the 302 redirect).
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.oauthInitiate)
  @Get(':provider')
  async initiate(
    @Param('provider') provider: string,
    @Query() query: OAuthInitiateQueryDto,
    @Res({ passthrough: true }) res: Response
  ): Promise<void> {
    await this.oauthService.initiateOAuth(provider, query.tenantId, res)
  }

  // ---------------------------------------------------------------------------
  // GET /oauth/:provider/callback
  // ---------------------------------------------------------------------------

  /**
   * Handles the OAuth provider callback and issues auth tokens.
   *
   * Validates the CSRF `state` nonce, exchanges the `code` for an access token,
   * fetches the user profile, runs the `onOAuthLogin` hook, and delivers the
   * auth response using the configured token delivery mode (cookie or bearer).
   *
   * Both `code` and `state` are validated via {@link OAuthCallbackQueryDto} — empty
   * or oversized values are rejected before reaching the service layer or the
   * token-exchange HTTP call.
   *
   * If `oauth.successRedirectUrl` is configured, the response is a `302` redirect
   * to that URL with cookies already set in the same response. This is the
   * standard browser OAuth flow — without it the browser lands on the JSON
   * payload returned to API consumers. The redirect is issued by calling
   * `res.redirect()` and returning `undefined`, which Nest passes through
   * unchanged (passthrough mode is active).
   *
   * If the resolved user has MFA enabled, the controller plants a short-lived
   * HttpOnly `mfa_temp_token` cookie (path-scoped to `/auth/mfa`) and either
   * redirects to `oauth.mfaRedirectUrl` (when configured) or returns the temp
   * token in the JSON body. The user completes the MFA challenge via
   * `POST /auth/mfa/challenge` to obtain real session tokens.
   *
   * On `AuthException` errors, redirects to `oauth.errorRedirectUrl` (when
   * configured) with `?error=<code>` instead of propagating the exception.
   * Non-`AuthException` errors propagate so they surface to monitoring.
   *
   * @param provider - Provider name from the URL path (e.g. `'google'`).
   * @param query - Validated query parameters (contains `code` and `state`).
   * @param req - Incoming request (IP, User-Agent, and cookie context for token delivery).
   * @param res - Express response in passthrough mode (used for cookie delivery and the optional redirect).
   * @returns The auth response shaped by `tokenDelivery`, the MFA challenge
   *   payload, or `undefined` when a redirect was issued.
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.oauthCallback)
  @HttpCode(HttpStatus.OK)
  @Get(':provider/callback')
  async callback(
    @Param('provider') provider: string,
    @Query() query: OAuthCallbackQueryDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<
    CookieAuthResponse | BearerAuthResponse | BothAuthResponse | OAuthMfaChallengeResult | undefined
  > {
    // Truncate to match the limits applied in all other auth controllers:
    // 64 chars for IP (longest IPv6 address is 39 chars; 64 gives ample headroom).
    // 512 chars for User-Agent (stored in the Redis session record; prevents key bloat).
    const ip = (req.ip ?? '').slice(0, 64)
    const userAgent = String(req.headers['user-agent'] ?? '').slice(0, 512)

    let result: AuthResult | OAuthMfaChallengeResult
    try {
      result = await this.oauthService.handleCallback(
        provider,
        query.code,
        query.state,
        ip,
        userAgent,
        req.headers as Record<string, string | string[] | undefined>
      )
    } catch (err) {
      // Only AuthException is converted to a redirect — programmer/infra errors
      // propagate so monitoring tooling can surface them. Without this guard the
      // error redirect would swallow real bugs.
      if (err instanceof AuthException && this.options.oauth?.errorRedirectUrl !== undefined) {
        const errorCode = extractErrorCode(err)
        const redirectTo = appendErrorQueryParam(this.options.oauth.errorRedirectUrl, errorCode)
        res.redirect(redirectTo)
        return undefined
      }
      throw err
    }

    // MFA branch — issue the temp token cookie and either redirect or return JSON.
    if (isOAuthMfaChallenge(result)) {
      this.setMfaTempCookie(res, result.mfaTempToken)

      const mfaRedirectUrl = this.options.oauth?.mfaRedirectUrl
      if (mfaRedirectUrl !== undefined) {
        res.redirect(mfaRedirectUrl)
        return undefined
      }
      // SPA path: return the temp token in the body so the client can drive
      // the challenge flow client-side (e.g. read it back from the cookie or
      // pass it through sessionStorage to the MFA challenge form).
      return { mfaRequired: true, mfaTempToken: result.mfaTempToken }
    }

    const body = this.tokenDelivery.deliverAuthResponse(res, result, req)

    // When successRedirectUrl is configured, follow up the cookie-setting
    // response with a 302 to that URL. Returning undefined keeps Nest from
    // serialising a body — the redirect headers carry the full response.
    const redirectUrl = this.options.oauth?.successRedirectUrl
    if (redirectUrl !== undefined) {
      res.redirect(redirectUrl)
      return undefined
    }

    return body
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Plants the short-lived `mfa_temp_token` HttpOnly cookie on the response.
   *
   * Cookie attributes:
   * - `HttpOnly`: not readable from JavaScript. The cookie is consumed by the
   *   server-side challenge route, not by any client code.
   * - `Secure`: derived from `secureCookies` (true in production by default).
   * - `SameSite`: derived from `cookies.sameSite` (defaults to `'lax'`).
   * - `Path`: `cookies.mfaTempCookiePath` (default `/auth/mfa`). Consumers
   *   that call `app.setGlobalPrefix(...)` MUST override this — the lib
   *   cannot observe the global prefix at module construction time, and
   *   a mismatched path makes the browser silently drop the cookie per
   *   RFC 6265 prefix-match.
   * - `Max-Age`: 300 seconds — exactly matches the underlying MFA temp JWT
   *   TTL (`MFA_TEMP_TOKEN_TTL_SECONDS` in `token-manager.service.ts`).
   *   Keeping the two TTLs identical avoids the failure mode where the
   *   cookie survives the JWT and the user sees `MFA_TEMP_TOKEN_INVALID`
   *   on a request that otherwise looked legitimate.
   */
  private setMfaTempCookie(res: Response, mfaTempToken: string): void {
    res.cookie(MFA_TEMP_COOKIE_NAME, mfaTempToken, {
      httpOnly: true,
      secure: this.options.secureCookies,
      sameSite: this.options.cookies.sameSite,
      path: this.options.cookies.mfaTempCookiePath,
      maxAge: MFA_TEMP_COOKIE_MAX_AGE_SECONDS * 1_000
    })
  }
}
