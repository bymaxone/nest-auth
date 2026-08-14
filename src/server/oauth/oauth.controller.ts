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
  Logger,
  Param,
  Query,
  Req,
  Res,
  UsePipes,
  UseGuards,
  UseInterceptors
} from '@nestjs/common'
import { Throttle } from '@nestjs/throttler'
import type { Request, Response } from 'express'

import { OAuthService } from './oauth.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { MFA_TEMP_COOKIE_MAX_AGE_SECONDS, MFA_TEMP_COOKIE_NAME } from '../constants/mfa-temp-cookie'
import {
  OAUTH_STATE_COOKIE_NAME,
  OAUTH_STATE_COOKIE_SAME_SITE
} from '../constants/oauth-state-cookie'
import { AUTH_THROTTLE_CONFIGS } from '../constants/throttle-configs'
import { AuthRateLimit } from '../decorators/auth-rate-limit.decorator'
import { Public } from '../decorators/public.decorator'
import { SkipMfa } from '../decorators/skip-mfa.decorator'
import { OAuthCallbackQueryDto } from '../dto/oauth-callback-query.dto'
import { OAuthInitiateQueryDto } from '../dto/oauth-initiate-query.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { NoStoreInterceptor } from '../interceptors/no-store.interceptor'
import type { AuthResult, OAuthMfaChallengeResult } from '../interfaces/auth-result.interface'
import { createAuthValidationPipe } from '../pipes/auth-validation.pipe'
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

/**
 * Reads the `oauth_state` cookie planted by {@link OAuthService.initiateOAuth}.
 *
 * Returns `undefined` when the browser sent no cookie, when `cookie-parser` is not mounted,
 * or when the value is absent or empty. The service treats all of those the same as a
 * mismatch — a callback that cannot prove it belongs to this browser is refused.
 */
function readOAuthStateCookie(req: Request): string | undefined {
  const cookies = req.cookies as { oauth_state?: unknown } | undefined
  if (cookies === undefined) return undefined
  const { oauth_state: value } = cookies
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

/**
 * Renders an untrusted value for a log line, or `<malformed>` when it is not a plain code.
 *
 * Anything that reaches a log must not be able to end the record. The allowed shape —
 * lowercase letters, digits, `_` and `-`, up to 64 characters — covers every code RFC 6749
 * §4.1.2.1 defines and every provider name this library accepts, and admits no newline,
 * carriage return, or control character. A value outside it is replaced wholesale rather than
 * escaped: an operator reading `<malformed>` learns the useful thing, which is that the
 * provider sent something this library does not recognise.
 */
function logSafe(value: string): string {
  return /^[a-z0-9_-]{1,64}$/.test(value) ? value : '<malformed>'
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
@UseInterceptors(NoStoreInterceptor)
@Controller('oauth')
@UseGuards(TrustedOriginGuard, AuthRateLimitGuard)
@UsePipes(createAuthValidationPipe({ forbidUnknownValues: true }))
export class OAuthController {
  /** Records provider-side refusals; never carries a token, a code, or the state. */
  private readonly logger = new Logger(OAuthController.name)

  constructor(
    @Inject(OAuthService) private readonly oauthService: OAuthService,
    @Inject(TokenDeliveryService) private readonly tokenDelivery: TokenDeliveryService,
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
   * @param req - Incoming Express request — the configured `tenantIdResolver` reads it.
   * @param res - Express response object (used to issue the 302 redirect).
   */
  @Throttle(AUTH_THROTTLE_CONFIGS.oauthInitiate)
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.oauthInitiate)
  @Get(':provider')
  async initiate(
    @Param('provider') provider: string,
    @Query() query: OAuthInitiateQueryDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response
  ): Promise<void> {
    await this.oauthService.initiateOAuth(provider, query.tenantId, req, res)
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
  @AuthRateLimit(AUTH_THROTTLE_CONFIGS.oauthCallback)
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

    const stateCookie = readOAuthStateCookie(req)

    // The state cookie is single-use: it is spent the moment the callback is handled, whatever
    // the outcome. Clearing it up front keeps a failed attempt from leaving a stale cookie
    // behind for the next flow, whose freshly minted state would then never match.
    //
    // Only when the browser actually sent it, though. This route is a `GET`, so `SameSite=Lax`
    // withholds the cookie from a cross-site *subresource* — an `<img src=…/callback>` on any
    // page the victim loads carries no cookie — but a `Set-Cookie` deleting it would take
    // effect all the same. Clearing unconditionally therefore let any page kill an OAuth login
    // that was still at the consent screen, repeatably, from anywhere.
    if (stateCookie !== undefined) {
      this.clearOAuthStateCookie(res)
    }

    // The provider refused before it ever minted a code (RFC 6749 §4.1.2.1) — most often
    // because the user clicked "Cancel" at the consent screen. That is a normal outcome of a
    // normal flow, and it used to answer a raw `ValidationPipe` 400 for the missing `code`
    // instead of the configured error redirect. The provider's value is logged and never
    // echoed back: it would otherwise be provider-chosen text landing in a URL the browser
    // follows, and the caller learns nothing from it that `oauth_failed` does not already say.
    if (query.error !== undefined) {
      // Both values are attacker-controlled and reach the log verbatim otherwise: `error` is a
      // query parameter with only a length bound, and `provider` is a path segment Express has
      // already percent-decoded, logged here before `resolvePlugin` ever applies its
      // `^[a-z0-9-]{1,64}$` shape check. A newline in either forges whole log records — a
      // fabricated "login success userId=admin" line sitting in the operator's SIEM. So the
      // log carries the value only when it is recognisably a code, and says so when it is not.
      // `error_description` is free-form prose by definition and is never logged at all.
      this.logger.warn(
        `callback: provider ${logSafe(provider)} returned error=${logSafe(query.error)}`
      )
      return this.handleCallbackFailure(res, new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED))
    }

    // A callback carrying neither `code` nor `error`. Reachable: the DTO no longer requires
    // `code`, so the pipe hands this request straight here and the refusal is the handler's —
    // `auth.oauth_failed`, the same answer rust-auth gives, rather than the `auth.validation`
    // the pipe used to produce. A codeless callback is a failed authorization, not a malformed
    // request, and the two libraries now say so in the same words.
    //
    // Refusing outright beats defaulting to an empty string, which would travel to the
    // provider's token endpoint and come back as their error rather than ours.
    if (query.code === undefined) {
      return this.handleCallbackFailure(res, new AuthException(AUTH_ERROR_CODES.OAUTH_FAILED))
    }

    let result: AuthResult | OAuthMfaChallengeResult
    try {
      result = await this.oauthService.handleCallback(
        provider,
        query.code,
        query.state,
        stateCookie,
        ip,
        userAgent,
        req.headers as Record<string, string | string[] | undefined>
      )
    } catch (err) {
      return this.handleCallbackFailure(res, err)
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
   * Routes a failed callback to the configured error redirect, or rethrows.
   *
   * Only an `AuthException` becomes a redirect — a programmer or infrastructure error
   * propagates so monitoring tooling surfaces it. Without that guard the error redirect would
   * swallow real bugs behind a tidy `?error=oauth_failed`.
   *
   * Shared by the two ways a callback fails: the provider's own error response, and an
   * exception out of `handleCallback`. One path means one policy — the redirect, the status,
   * and the code cannot drift between them.
   */
  private handleCallbackFailure(res: Response, err: unknown): undefined {
    if (err instanceof AuthException && this.options.oauth?.errorRedirectUrl !== undefined) {
      const errorCode = extractErrorCode(err)
      const redirectTo = appendErrorQueryParam(this.options.oauth.errorRedirectUrl, errorCode)
      res.redirect(redirectTo)
      return undefined
    }
    throw err
  }

  /**
   * Clears the `oauth_state` cookie once its callback has been handled.
   *
   * The attributes must match those used to plant it in
   * {@link OAuthService.initiateOAuth} — a browser matches a deletion against name, domain,
   * and path, so a `path` of anything but `/` would leave the original cookie in place and
   * the next flow would arrive carrying a state that can no longer match.
   */
  private clearOAuthStateCookie(res: Response): void {
    res.clearCookie(OAUTH_STATE_COOKIE_NAME, {
      httpOnly: true,
      secure: this.options.secureCookies,
      sameSite: OAUTH_STATE_COOKIE_SAME_SITE,
      path: '/'
    })
  }

  /**
   * Plants the short-lived `mfa_temp_token` cookie after an MFA-gated OAuth callback.
   *
   * Cookie attributes:
   * - `httpOnly`: always — the token is a bearer credential for the challenge route.
   * - `secure`: mirrors `options.secureCookies`.
   * - `sameSite`: the deployment's configured value.
   * - `path`: `options.cookies.mfaTempCookiePath`, so the browser only sends it
   *   on the challenge route. Trailing-slash semantics follow the standard
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
