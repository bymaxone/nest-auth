/**
 * @fileoverview Rejects state-changing requests that ride the session cookie in from an
 * origin the deployment does not trust.
 *
 * @layer Guard
 */
import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * Methods that cannot change state, so they are never a CSRF target.
 *
 * `HEAD` and `OPTIONS` are here for completeness; the preflight in particular must pass
 * untouched or every cross-origin call would fail before the real request is made.
 */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/**
 * `Sec-Fetch-Site` values that prove the request did not come from another site.
 *
 * `same-origin` is the app calling itself; `none` is a user-initiated navigation (typing a
 * URL, a bookmark), which no attacker page can cause.
 */
const SAFE_FETCH_SITES = new Set(['same-origin', 'none'])

/**
 * Blocks a cross-site request that would otherwise be authenticated by the browser's ambient
 * session cookie.
 *
 * @remarks
 * `SameSite` carries this on its own for `lax` and `strict` — the browser simply does not send
 * the cookie. It does **not** carry it for `SameSite=None`, which the module allows (embedded
 * widgets, iframes, cross-domain SPAs) and which sends the cookie on every cross-site request.
 * That is the configuration this guard exists for, and it is the only one where the library has
 * a CSRF exposure at all.
 *
 * The decision uses only headers a page cannot forge:
 *
 * 1. A safe method changes nothing — allowed.
 * 2. A request carrying none of the module's auth cookies has no ambient credential to abuse,
 *    so a bearer-token client is never affected — allowed.
 * 3. `Sec-Fetch-Site: same-origin` / `none` proves the request is not cross-site — allowed.
 * 4. An `Origin` present must be in `cookies.trustedOrigins` — allowed only then.
 * 5. `Sec-Fetch-Site` present and cross-site, with no `Origin`: a browser that sends one header
 *    sends the other on a state-changing request, so this shape is refused.
 * 6. Neither header at all — a non-browser client (curl, a server-to-server call). Allowed:
 *    an attacker's page cannot make a browser *omit* `Origin` on a cross-site request, so the
 *    absence is evidence there is no browser involved, not a way around the check.
 *
 * The request's own origin is never reconstructed from `Host` or `X-Forwarded-Proto` — both are
 * client-controlled, and a check that trusts them is not a check. Same-origin requests are
 * recognised by `Sec-Fetch-Site` alone.
 *
 * @example
 * ```typescript
 * // Cross-domain SPA: the API is on api.example.com, the app on app.example.com.
 * BymaxAuthModule.registerAsync({
 *   useFactory: () => ({
 *     cookies: { sameSite: 'none', trustedOrigins: ['https://app.example.com'] },
 *     secureCookies: true
 *   })
 * })
 * ```
 *
 * @layer Guard
 */
@Injectable()
export class TrustedOriginGuard implements CanActivate {
  constructor(@Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>()

    if (SAFE_METHODS.has(request.method)) return true
    if (!this.carriesAuthCookie(request)) return true

    const fetchSite = request.headers['sec-fetch-site']
    if (typeof fetchSite === 'string' && SAFE_FETCH_SITES.has(fetchSite)) return true

    const origin = request.headers['origin']
    if (typeof origin === 'string') {
      if (this.options.cookies.trustedOrigins.includes(origin)) return true
      throw new AuthException(AUTH_ERROR_CODES.UNTRUSTED_ORIGIN, 403)
    }

    // A browser that sent `Sec-Fetch-Site` would also have sent `Origin` here.
    if (typeof fetchSite === 'string') {
      throw new AuthException(AUTH_ERROR_CODES.UNTRUSTED_ORIGIN, 403)
    }

    return true
  }

  /**
   * Whether the request carries one of the module's own auth cookies.
   *
   * Only the credential-bearing cookies count. The `has_session` signal cookie is readable by
   * JavaScript by design and authenticates nothing, so a request carrying only that one has no
   * ambient credential for an attacker page to spend.
   *
   * The names come from the resolved options, never from the shipped defaults. Reading the
   * defaults meant that a deployment renaming its cookies — the `cookies.accessTokenName` /
   * `refreshTokenName` options — carried a credential this method could not see, so the guard
   * concluded "no ambient credential" and allowed the cross-site request. That failed open on
   * exactly the configuration the guard exists for: `SameSite=None`, where the browser does
   * attach the renamed cookie.
   *
   * An unreadable `request.cookies` (the `cookie-parser` middleware not mounted) is treated as
   * "credential present" rather than "absent": the guard cannot prove the request is safe, and
   * the safe direction is to demand a trusted `Origin` rather than wave it through.
   *
   * @param request - The incoming request.
   * @returns `true` when an access or refresh cookie is present, or when the cookies cannot
   *   be read at all.
   */
  private carriesAuthCookie(request: Request): boolean {
    const cookies: unknown = request.cookies
    if (typeof cookies !== 'object' || cookies === null) return true
    const jar = cookies as Record<string, unknown>
    const { accessTokenName, refreshTokenName } = this.options.cookies
    return typeof jar[accessTokenName] === 'string' || typeof jar[refreshTokenName] === 'string'
  }
}
