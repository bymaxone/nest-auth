/**
 * `createLogoutHandler` — factory for the POST
 * `/api/auth/logout` route handler.
 *
 * The handler forwards the incoming cookies to the upstream NestJS
 * `POST /auth/logout` endpoint (which revokes the refresh token
 * server-side) and, regardless of whether the upstream responds with
 * success or failure, clears the three auth cookies on the browser.
 * A user who pressed "logout" MUST end up logged out of the browser
 * session even if the upstream is unreachable — otherwise a network
 * glitch leaves them with cookies they thought they had invalidated.
 *
 * Two response modes are supported, expressed as a discriminated
 * union on {@link LogoutHandlerConfig}:
 *
 *   - `mode: 'redirect'`: 302 to `loginPath`. Appropriate when the
 *     handler is invoked from a full-page form POST.
 *   - `mode: 'status'` (default): 200 empty body. Appropriate when
 *     the handler is invoked from client-side JavaScript that
 *     manages its own navigation.
 *
 * @remarks
 * HOST-HEADER TRUST — in `'redirect'` mode the destination is emitted
 * as a RELATIVE `Location` and the response never reads
 * `request.nextUrl.origin`, so the browser resolves it against the
 * URL it actually requested. A forged `Host` has nothing to influence
 * here, and this handler needs no vetting of that header to be safe.
 * That is a property of this response only — it says nothing about
 * the rest of an application, where `Host` may still reach a URL.
 *
 * Edge-Runtime-safe.
 */

import type { NextRequest } from 'next/server'

import { AUTH_DASHBOARD_ROUTES, AUTH_PROXY_ROUTES } from '@bymax-one/nest-auth/shared'

import { assertValidApiBase, assertValidUpstreamPath } from './helpers/buildRefreshUrl'
import {
  assertSafeCookieName,
  assertSafeCookiePath,
  isCrossSiteRequest,
  isSafeSameOriginPath,
  serializeClearCookie,
  trimTrailingSlash
} from './helpers/routeHandlerUtils'
import { redirectToPath } from './internal/redirectToPath'

/** Default upstream logout endpoint, matching the NestJS module defaults. */
const DEFAULT_LOGOUT_PATH = `/auth/${AUTH_DASHBOARD_ROUTES.logout}`

/** Default cookie path used when clearing the refresh-token cookie. */
const DEFAULT_REFRESH_COOKIE_PATH = '/api/auth'

/**
 * Cookie names + path used by every logout response to clear the
 * browser's auth state. Shared by both config variants of the
 * discriminated union.
 */
interface LogoutCookieConfig {
  readonly cookieNames: {
    readonly access: string
    readonly refresh: string
    readonly hasSession: string
  }
  /**
   * Path attribute for the refresh-cookie clear. Defaults to `/api/auth`.
   *
   * **This is not the server's default**, which is `/auth`. It is the value the *proxy*
   * topology needs: the browser addresses the Next.js route, so the cookie must be scoped to
   * the Next.js path, which means the upstream module has to be configured with
   * `cookies.refreshCookiePath: '/api/auth'` to plant it there in the first place — the proxy
   * forwards `Set-Cookie` verbatim and never rewrites `Path`. A deployment that leaves the
   * server on `/auth` must set this to `/auth` too: a browser matches a deletion on name,
   * domain and path, so a mismatch means the clear silently does nothing and the refresh
   * cookie outlives the logout (the session itself is revoked server-side either way).
   */
  readonly refreshCookiePath?: string

  /**
   * The cookie `Domain` the NestJS server planted the session with, when
   * `cookies.resolveDomains` is configured there. Leave unset for the
   * host-only default.
   *
   * A browser matches a deletion on **name, domain AND path** (RFC 6265 §5.3),
   * so a clear that omits `Domain` cannot remove a cookie that carries one — it
   * plants a new host-only cookie and the originals survive.
   */
  readonly cookieDomain?: string
}

/**
 * Logout response mode = `'redirect'`. `loginPath` is required and
 * MUST be a same-origin pathname.
 */
export interface LogoutHandlerRedirectConfig extends LogoutCookieConfig {
  readonly mode: 'redirect'
  readonly loginPath: string
  readonly apiBase: string
  readonly logoutPath?: string
}

/**
 * Logout response mode = `'status'` (default). Emits a 200 with
 * cookies cleared; no redirect destination needed.
 */
export interface LogoutHandlerStatusConfig extends LogoutCookieConfig {
  readonly mode?: 'status'
  readonly apiBase: string
  readonly logoutPath?: string
}

/**
 * Configuration contract for {@link createLogoutHandler}. A
 * discriminated union on `mode` so the compiler enforces that
 * `loginPath` is present whenever redirect mode is selected.
 */
export type LogoutHandlerConfig = LogoutHandlerRedirectConfig | LogoutHandlerStatusConfig

/** Signature of the POST handler returned by the factory. */
export type LogoutHandler = (request: NextRequest) => Promise<Response>

/**
 * Create a POST handler for `/api/auth/logout`.
 *
 * @throws {Error} When `apiBase` is not absolute HTTP(S), or when
 *                 `loginPath`/`logoutPath` / cookie names / cookie
 *                 paths fail their validation checks.
 */
export function createLogoutHandler(config: LogoutHandlerConfig): LogoutHandler {
  const refreshCookiePath = validateLogoutConfig(config)
  const logoutUrl = `${trimTrailingSlash(config.apiBase)}${config.logoutPath ?? DEFAULT_LOGOUT_PATH}`

  return async function logoutHandler(request: NextRequest): Promise<Response> {
    if (request.method !== 'POST') {
      // Method error — not a user logout attempt, so no cookie
      // clearing is needed. The 405 response only tells the client
      // which verb is supported.
      return new Response(null, {
        status: 405,
        headers: { Allow: 'POST', 'Cache-Control': 'no-store, no-cache' }
      })
    }

    // A cross-site caller gets nothing, and gets it before any cookie is written. The verb
    // check alone did not cover this: a form POST from an attacker's page IS a POST, sends no
    // session cookie under `Lax` so the upstream revocation no-ops, and used to be answered
    // with the three `Max-Age=0` cookies anyway — applied first-party, because a form POST is a
    // top-level navigation. Any page on the internet could sign a visitor out, repeatably.
    if (isCrossSiteRequest(request)) {
      return new Response(null, { status: 403, headers: { 'Cache-Control': 'no-store, no-cache' } })
    }

    // Best-effort upstream logout. We intentionally ignore the
    // response: whether the upstream succeeds or fails, the browser
    // cookies MUST be cleared so the user is locally logged out.
    //
    // Forward both `cookie` (cookie-mode tokenDelivery) and `authorization`
    // (bearer-mode tokenDelivery). Without forwarding `authorization`, the
    // upstream JwtAuthGuard rejects the request and the access-token JTI is
    // never added to the revocation list — leaving the bearer token valid
    // until natural expiry on every bearer-mode logout.
    const upstreamHeaders: Record<string, string> = {
      cookie: request.headers.get('cookie') ?? '',
      accept: 'application/json'
    }
    const incomingAuth = request.headers.get('authorization')
    if (incomingAuth) upstreamHeaders.authorization = incomingAuth

    try {
      await fetch(logoutUrl, {
        method: 'POST',
        headers: upstreamHeaders,
        redirect: 'manual'
      })
    } catch {
      // Swallow — clearing cookies locally is the user-visible
      // guarantee.
    }

    return buildLogoutResponse(request, config, refreshCookiePath)
  }
}

/**
 * Validate the full config at factory-call time. Returns the
 * effective `refreshCookiePath` so the factory doesn't have to
 * re-apply the default. Throws on any shape we reject.
 */
function validateLogoutConfig(config: LogoutHandlerConfig): string {
  assertValidApiBase(config.apiBase, 'createLogoutHandler')
  assertValidUpstreamPath(config.logoutPath, 'createLogoutHandler', 'logoutPath')
  assertSafeCookieName(config.cookieNames.access, 'createLogoutHandler', 'cookieNames.access')
  assertSafeCookieName(config.cookieNames.refresh, 'createLogoutHandler', 'cookieNames.refresh')
  assertSafeCookieName(
    config.cookieNames.hasSession,
    'createLogoutHandler',
    'cookieNames.hasSession'
  )
  const refreshCookiePath = config.refreshCookiePath ?? DEFAULT_REFRESH_COOKIE_PATH
  assertSafeCookiePath(refreshCookiePath, 'createLogoutHandler', 'refreshCookiePath')

  if (config.mode === 'redirect' && !isSafeSameOriginPath(config.loginPath)) {
    throw new Error(
      `createLogoutHandler: loginPath "${config.loginPath}" must be a same-origin pathname starting with "/" (not "//") and must not contain CR/LF/NUL/backslash characters.`
    )
  }

  return refreshCookiePath
}

/**
 * Build the final response — either a 302 to `loginPath` or a 200
 * empty body, depending on the configured `mode`. In both cases the
 * three auth cookies are cleared.
 */
function buildLogoutResponse(
  request: NextRequest,
  config: LogoutHandlerConfig,
  refreshCookiePath: string
): Response {
  if (config.mode === 'redirect') {
    // Relative `Location`, so a forged `Host` has nothing to change — see `redirectToPath`.
    const response = redirectToPath(config.loginPath)
    attachClearCookies(response, config, refreshCookiePath)
    response.headers.set('Cache-Control', 'no-store, no-cache')
    return response
  }

  const response = new Response(null, {
    status: 200,
    headers: { 'Cache-Control': 'no-store, no-cache' }
  })
  attachClearCookies(response, config, refreshCookiePath)
  return response
}

/**
 * Appends `Set-Cookie: Max-Age=0` directives for all configured auth cookies to the response.
 *
 * Cookie names are pre-validated at factory time — this function trusts them as safe.
 *
 * @param response - The `Response` to mutate.
 * @param config - Proxy configuration containing the cookie names and paths to clear.
 * @param refreshCookiePath - The validated path attribute for the refresh-token cookie.
 */
function attachClearCookies(
  response: Response,
  config: LogoutCookieConfig,
  refreshCookiePath: string
): void {
  const clearCookies = [
    serializeClearCookie(config.cookieNames.access, '/', config.cookieDomain),
    serializeClearCookie(config.cookieNames.refresh, refreshCookiePath, config.cookieDomain),
    serializeClearCookie(config.cookieNames.hasSession, '/', config.cookieDomain)
  ]
  for (const cookie of clearCookies) {
    response.headers.append('set-cookie', cookie)
  }
}

/**
 * Canonical Next.js proxy-side path this handler is expected to be
 * mounted at.
 */
export const LOGOUT_ROUTE = AUTH_PROXY_ROUTES.logout
