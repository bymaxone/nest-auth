import { Inject, Injectable } from '@nestjs/common'
import type { Request, Response } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { AuthResult } from '../interfaces/auth-result.interface'

/** Hostname validation — allows only alphanumeric, dots, and hyphens. */
const HOSTNAME_RE = /^[a-z0-9.-]+$/i

/**
 * Auth response for cookie mode — tokens delivered via HttpOnly cookies.
 * The response body contains only the user object.
 */
export interface CookieAuthResponse {
  user: AuthResult['user']
}

/**
 * Auth response for bearer mode — tokens delivered in the response body.
 */
export interface BearerAuthResponse {
  user: AuthResult['user']
  accessToken: string
  refreshToken: string
}

/**
 * Auth response for both mode — tokens in body AND cookies.
 */
export interface BothAuthResponse extends BearerAuthResponse {}

/**
 * Manages token delivery and extraction for all three delivery modes.
 *
 * @remarks
 * The library supports three token delivery modes (configured via
 * `tokenDelivery` in module options):
 *
 * - `'cookie'`: Tokens are set as HttpOnly cookies. The response body contains
 *   only the user object. This is the default and recommended mode.
 * - `'bearer'`: Tokens are returned in the JSON response body. No cookies are
 *   set. Use this for mobile/native clients or SPA with cross-origin APIs.
 * - `'both'`: Tokens are set as cookies AND returned in the response body.
 *
 * Cookie security: HttpOnly, Secure (production), SameSite=Strict.
 * Refresh cookies use the configured `cookies.refreshCookiePath`.
 */
@Injectable()
export class TokenDeliveryService {
  constructor(@Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions) {}

  // ---------------------------------------------------------------------------
  // Deliver
  // ---------------------------------------------------------------------------

  /**
   * Delivers an auth response (tokens + user) based on the configured mode.
   *
   * @param res - Express response object (passthrough mode — do not call `res.json()`).
   * @param authResult - Tokens and user from a successful login or token issuance.
   * @param req - Incoming request (used to resolve cookie domain when `resolveDomains` is configured).
   * @returns The response body to be returned by the controller.
   */
  deliverAuthResponse(
    res: Response,
    authResult: AuthResult,
    req?: Request
  ): CookieAuthResponse | BearerAuthResponse | BothAuthResponse {
    const { user, accessToken, rawRefreshToken } = authResult
    const mode = this.options.tokenDelivery

    if (mode === 'cookie' || mode === 'both') {
      const domains = this.resolveCookieDomains(req)
      for (const domain of domains) {
        this.setAuthCookies(res, accessToken, rawRefreshToken, domain)
      }
      if (domains.length === 0) {
        this.setAuthCookies(res, accessToken, rawRefreshToken, undefined)
      }
    }

    if (mode === 'bearer') {
      return { user, accessToken, refreshToken: rawRefreshToken }
    }

    if (mode === 'both') {
      return { user, accessToken, refreshToken: rawRefreshToken }
    }

    return { user }
  }

  /**
   * Delivers a token-refresh response based on the configured mode.
   *
   * Delegates to {@link deliverAuthResponse} — refresh responses use the same
   * cookie-setting and body-construction logic as login responses. The separation
   * exists to provide a semantically distinct call site in refresh controllers,
   * making it clear whether a request is an initial login or a token rotation.
   *
   * @param res - Express response object.
   * @param authResult - New tokens from a successful refresh operation.
   * @param req - Incoming request (used to resolve cookie domain).
   * @returns The response body to be returned by the controller.
   */
  deliverRefreshResponse(
    res: Response,
    authResult: AuthResult,
    req?: Request
  ): CookieAuthResponse | BearerAuthResponse | BothAuthResponse {
    return this.deliverAuthResponse(res, authResult, req)
  }

  // ---------------------------------------------------------------------------
  // Extract
  // ---------------------------------------------------------------------------

  /**
   * Extracts the access token from an incoming request.
   *
   * - `'cookie'`: reads access token cookie (name from `cookies.accessTokenName`)
   * - `'bearer'`: reads `Authorization: Bearer <token>` header
   * - `'both'`: cookie first, then Authorization header
   *
   * @param req - Incoming Express request.
   * @returns The raw access token string, or `undefined` if not found.
   */
  extractAccessToken(req: Request): string | undefined {
    const mode = this.options.tokenDelivery
    const cookieName = this.options.cookies.accessTokenName

    if (mode === 'cookie') {
      return this.readCookie(req, cookieName)
    }

    if (mode === 'bearer') {
      return this.readBearerHeader(req)
    }

    // both — cookie first, then header
    return this.readCookie(req, cookieName) ?? this.readBearerHeader(req)
  }

  /**
   * Extracts the refresh token from an incoming request.
   *
   * - `'cookie'`: reads refresh token cookie (name from `cookies.refreshTokenName`)
   * - `'bearer'`: reads `req.body.refreshToken`
   * - `'both'`: cookie first, then body
   *
   * @param req - Incoming Express request.
   * @returns The raw refresh token string, or `undefined` if not found.
   */
  extractRefreshToken(req: Request): string | undefined {
    const mode = this.options.tokenDelivery
    const cookieName = this.options.cookies.refreshTokenName

    if (mode === 'cookie') {
      return this.readCookie(req, cookieName)
    }

    if (mode === 'bearer') {
      return this.readBodyRefresh(req)
    }

    // both — cookie first, then body
    return this.readCookie(req, cookieName) ?? this.readBodyRefresh(req)
  }

  // ---------------------------------------------------------------------------
  // Clear session
  // ---------------------------------------------------------------------------

  /**
   * Clears all auth cookies on the resolved domains.
   *
   * In `'bearer'` mode this is a no-op — no cookies were set.
   *
   * @param res - Express response object.
   * @param req - Incoming request (used to resolve cookie domain).
   */
  clearAuthSession(res: Response, req?: Request): void {
    if (this.options.tokenDelivery === 'bearer') return

    const domains = this.resolveCookieDomains(req)
    const clearOn = domains.length > 0 ? domains : [undefined as string | undefined]

    for (const domain of clearOn) {
      const cookieOpts = this.baseCookieOptions(domain)
      res.clearCookie(this.options.cookies.accessTokenName, cookieOpts)
      res.clearCookie(this.options.cookies.refreshTokenName, {
        ...cookieOpts,
        path: this.options.cookies.refreshCookiePath
      })
      res.clearCookie(this.options.cookies.sessionSignalName, {
        ...cookieOpts,
        httpOnly: false
      })
    }
  }

  // ---------------------------------------------------------------------------
  // Domain resolution
  // ---------------------------------------------------------------------------

  /**
   * Resolves cookie domains for the current request.
   *
   * If `cookies.resolveDomains` is configured, delegates to that function
   * (passing the validated hostname). Otherwise falls back to an array
   * containing `extractDomain(req)`, or an empty array if req is absent.
   *
   * @param req - Incoming request (may be undefined in non-HTTP contexts).
   * @returns Array of domain strings for cookie attributes. Empty array means
   *   "use no explicit domain attribute".
   */
  resolveCookieDomains(req?: Request): string[] {
    if (this.options.cookies.resolveDomains && req) {
      const hostname = this.extractDomain(req) ?? ''
      return this.options.cookies.resolveDomains(hostname)
    }
    const domain = req ? this.extractDomain(req) : undefined
    return domain ? [domain] : []
  }

  /**
   * Extracts a safe cookie domain from the request hostname.
   *
   * Validates the hostname against `HOSTNAME_RE` to reject injection attempts
   * (e.g. `Host: evil.com; Path=/`). Returns `undefined` when the hostname is
   * invalid or absent.
   *
   * @param req - Incoming Express request.
   * @returns Validated hostname string, or `undefined` if invalid.
   */
  extractDomain(req: Request): string | undefined {
    const hostname = req.hostname
    if (hostname && HOSTNAME_RE.test(hostname)) {
      return hostname
    }
    return undefined
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private setAuthCookies(
    res: Response,
    accessToken: string,
    rawRefreshToken: string,
    domain: string | undefined
  ): void {
    const base = this.baseCookieOptions(domain)
    const isProd = this.options.secureCookies
    const accessMaxAge = this.options.jwt.accessCookieMaxAgeMs

    res.cookie(this.options.cookies.accessTokenName, accessToken, {
      ...base,
      httpOnly: true,
      secure: isProd,
      maxAge: accessMaxAge
    })

    res.cookie(this.options.cookies.refreshTokenName, rawRefreshToken, {
      ...base,
      httpOnly: true,
      secure: isProd,
      path: this.options.cookies.refreshCookiePath,
      maxAge: this.options.jwt.refreshExpiresInDays * 86_400 * 1_000
    })

    // Non-HttpOnly signal cookie: readable by client JS to detect active session.
    res.cookie(this.options.cookies.sessionSignalName, '1', {
      ...base,
      httpOnly: false,
      secure: isProd,
      maxAge: accessMaxAge
    })
  }

  private baseCookieOptions(domain: string | undefined): { sameSite: 'strict'; domain?: string } {
    return {
      sameSite: 'strict',
      ...(domain ? { domain } : {})
    }
  }

  private readCookie(req: Request, name: string): string | undefined {
    // eslint-disable-next-line security/detect-object-injection
    const value = (req.cookies as Record<string, unknown> | undefined)?.[name]
    return typeof value === 'string' ? value : undefined
  }

  private readBearerHeader(req: Request): string | undefined {
    const auth = req.headers['authorization']
    if (typeof auth !== 'string') return undefined
    // trim() + split(/\s+/) handles extra surrounding whitespace and multi-space separators
    // (e.g. "Bearer  token" with two spaces) that would cause split(' ') to produce 3 parts.
    const parts = auth.trim().split(/\s+/)
    if (parts.length !== 2 || parts[0]?.toLowerCase() !== 'bearer') return undefined
    return parts[1]
  }

  private readBodyRefresh(req: Request): string | undefined {
    const body = req.body as Record<string, unknown> | undefined
    const value = body?.['refreshToken']
    return typeof value === 'string' ? value : undefined
  }
}
