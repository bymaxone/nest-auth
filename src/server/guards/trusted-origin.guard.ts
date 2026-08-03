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
 * 2. `Sec-Fetch-Site: same-origin` / `none` proves the request is not cross-site — allowed.
 * 3. `Sec-Fetch-Site` present with any other value (`cross-site`, `same-site`) is the browser
 *    stating the request came from somewhere else. Allowed only if `Origin` is listed in
 *    `cookies.trustedOrigins`; refused otherwise, **including when the list is empty** — an
 *    empty list means no other origin is authorized, not that every one is.
 * 4. `Sec-Fetch-Site` absent and `Origin` present: allowed if listed. Otherwise refused when a
 *    list is configured, and allowed when it is empty — see the ambiguity below.
 * 5. Neither header at all — a non-browser client (curl, a server-to-server call). Allowed:
 *    an attacker's page cannot make a browser *omit* `Origin` on a cross-site request, so the
 *    absence is evidence there is no browser involved, not a way around the check.
 *
 * **The check does not depend on the request already being authenticated.** It used to: a
 * request carrying none of the module's cookies skipped straight to allowed, on the reasoning
 * that there was no ambient credential to abuse. The reasoning missed the requests that MINT
 * one. `POST /auth/login` and `/auth/register` carry no cookie and answer with a session, so an
 * attacker's page could log a victim's browser into the ATTACKER's account and then read
 * whatever the victim did there believing it was theirs.
 *
 * **Nor does it depend on the allowlist being populated.** It did, and that was the same bug
 * one level up. An empty list short-circuited to allowed on the reasoning that `SameSite`
 * withholds the cookie cross-site anyway — true, and irrelevant to a login CSRF, where the
 * credentials are in the attacker's own request body and no cookie needs to be sent at all. The
 * response's `Set-Cookie` lands first-party because a form POST is a top-level navigation, so
 * third-party cookie policy does not help either. Since the default configuration ships an
 * empty list, that short-circuit meant the guard was inert in the deployment shape most
 * consumers run, while its own documentation claimed the class was closed.
 *
 * **The one case that stays permissive, and why.** A same-origin POST from a browser that sends
 * `Origin` and omits `Sec-Fetch-Site` is indistinguishable from a cross-site one: this module
 * never learns its own origin (reconstructing it from `Host` or `X-Forwarded-Proto` would trust
 * a client-controlled header, and a check that trusts them is not a check). `Sec-Fetch-Site`
 * resolves that ambiguity whenever it is present — Chrome 76, Firefox 90 and Safari 16.4 all
 * send it — so the residual gap is a browser old enough to send `Origin` without it. A
 * deployment that wants that gap closed too lists its own origin in `cookies.trustedOrigins`,
 * which is accepted under every `sameSite` value for exactly this reason.
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

    const fetchSite = request.headers['sec-fetch-site']
    const sawFetchSite = typeof fetchSite === 'string'
    if (sawFetchSite && SAFE_FETCH_SITES.has(fetchSite)) return true

    const origin = request.headers['origin']
    if (typeof origin === 'string') {
      if (this.options.cookies.trustedOrigins.includes(origin)) return true
      // Refused whenever the browser has told us the request is not our own — `Sec-Fetch-Site`
      // present and not safe — and whenever a list exists to be checked against. The remaining
      // combination (no `Sec-Fetch-Site`, empty list) is the one this guard cannot decide: it
      // has no way to know whether `origin` is its own. Allowing it is the deliberate choice
      // documented on the class; the alternative refuses every same-origin POST from those
      // browsers, which is a broken deployment rather than a hardened one.
      if (sawFetchSite || this.options.cookies.trustedOrigins.length > 0) {
        throw new AuthException(AUTH_ERROR_CODES.UNTRUSTED_ORIGIN, 403)
      }
      return true
    }

    // A browser that sent `Sec-Fetch-Site` would also have sent `Origin` here.
    if (sawFetchSite) {
      throw new AuthException(AUTH_ERROR_CODES.UNTRUSTED_ORIGIN, 403)
    }

    return true
  }
}
