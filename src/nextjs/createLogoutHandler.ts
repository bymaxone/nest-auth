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
 * HOST-HEADER TRUST — in `'redirect'` mode the destination URL is
 * built with `new URL(loginPath, request.nextUrl.origin)`. Self-
 * hosted Next.js deployments behind a reverse proxy MUST ensure the
 * proxy forwards only vetted `Host` values; otherwise an attacker
 * who controls the `Host` header can redirect the browser to an
 * off-site origin after logout.
 *
 * Edge-Runtime-safe.
 */

import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

import { AUTH_DASHBOARD_ROUTES, AUTH_PROXY_ROUTES } from '@bymax-one/nest-auth/shared'

import { assertValidApiBase, assertValidUpstreamPath } from './helpers/buildRefreshUrl'
import {
  assertSafeCookieName,
  assertSafeCookiePath,
  isSafeSameOriginPath,
  serializeClearCookie,
  trimTrailingSlash
} from './helpers/routeHandlerUtils'

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
    const loginUrl = new URL(config.loginPath, request.nextUrl.origin)
    const response = NextResponse.redirect(loginUrl)
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
    serializeClearCookie(config.cookieNames.access, '/'),
    serializeClearCookie(config.cookieNames.refresh, refreshCookiePath),
    serializeClearCookie(config.cookieNames.hasSession, '/')
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
