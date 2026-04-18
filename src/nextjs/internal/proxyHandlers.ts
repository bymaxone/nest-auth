/**
 * Route-handler bodies for `createAuthProxy`.
 *
 * Three public handlers (`handlePublicRoute`, `handleProtectedRoute`,
 * `buildAuthorisedResponse`) plus one helper (`redirectToLogin`).
 * The proxy factory picks the right handler based on the output of
 * {@link classifyRoute} and hands it the sanitised headers produced
 * by {@link buildSanitizedRequestHeaders}.
 */

import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

import type { ProtectedRoutePattern, ResolvedAuthProxyConfig } from '../createAuthProxy'
import { REASON_EXPIRED, REASON_PARAM, REFRESH_ATTEMPT_PARAM } from './constants'
import {
  asString,
  buildRefreshDestination,
  isReasonExpired,
  readRefreshAttemptCounter,
  safeRelativePath,
  setOrDeleteHeader
} from './proxyUtils'
import { matchesPublicRoute } from './routeClassifier'
import type { TokenState } from './tokenState'
import { buildSilentRefreshUrl } from '../helpers/buildSilentRefreshUrl'
import type { DecodedToken } from '../helpers/jwt'

/**
 * Handle a request that fell through the classifier as a public
 * route (or `unmatched`, treated the same). Implements the two
 * anti-redirect-loop guards:
 *
 *   1. `_r` counter < `maxRefreshAttempts`
 *   2. `reason !== 'expired'`
 *
 * Both are defence-in-depth: the first stops the loop when the
 * proxy itself keeps issuing refresh redirects; the second stops
 * the loop when the silent-refresh handler has already determined
 * the session is irrecoverable. EITHER guard alone is NOT
 * sufficient — both MUST be checked.
 */
export function handlePublicRoute(
  request: NextRequest,
  pathname: string,
  tokenState: TokenState,
  config: ResolvedAuthProxyConfig,
  sanitizedHeaders: Headers
): NextResponse {
  const refreshAttempts = readRefreshAttemptCounter(request, config.maxRefreshAttempts)
  const shouldBreakForReason = isReasonExpired(request)
  const shouldBreakForCounter = refreshAttempts >= config.maxRefreshAttempts

  if (tokenState.authenticated) {
    return handleAuthenticatedOnPublic(request, pathname, tokenState, config, sanitizedHeaders)
  }

  // Unauthenticated from here on. All `NextResponse.next()` returns
  // forward the sanitised headers so the client cannot spoof
  // identity headers on public routes either.
  const hasSessionCookie = request.cookies.get(config.cookieNames.hasSession)?.value
  const hasSession = hasSessionCookie !== undefined && hasSessionCookie.length > 0

  // Defence-in-depth: check the counter FIRST so we never redirect
  // when the counter is already maxed out, even if other conditions
  // would have otherwise triggered a silent-refresh.
  if (shouldBreakForCounter || shouldBreakForReason) {
    return NextResponse.next({ request: { headers: sanitizedHeaders } })
  }

  // Cookie says "you had a session recently" AND neither guard has
  // fired — try a silent refresh. The incremented `_r` rides on the
  // DESTINATION so the handler's redirect-back preserves the
  // counter.
  if (hasSession) {
    const destination = buildRefreshDestination(
      pathname,
      request.nextUrl.searchParams,
      refreshAttempts + 1
    )
    const silentRefreshUrl = new URL(buildSilentRefreshUrl(request, destination))
    return NextResponse.redirect(silentRefreshUrl)
  }

  // No session cookie — nothing to refresh. Render the public page.
  return NextResponse.next({ request: { headers: sanitizedHeaders } })
}

/**
 * Sub-branch of {@link handlePublicRoute} taken when the user is
 * authenticated. An authenticated user visiting a
 * `publicRoutesRedirectIfAuthenticated` route is sent to their
 * dashboard — EXCEPT when the URL carries any `reason=` signal.
 * That exception prevents the blocked-user ping-pong between
 * `/dashboard` (blocked → redirected to /login?reason=banned) and
 * `/login` (authenticated → redirected to /dashboard).
 */
function handleAuthenticatedOnPublic(
  request: NextRequest,
  pathname: string,
  tokenState: TokenState,
  config: ResolvedAuthProxyConfig,
  sanitizedHeaders: Headers
): NextResponse {
  /* istanbul ignore next -- `authenticated` implies token is defined; optional chain is defensive */
  const role = tokenState.token?.role ?? ''
  const reasonPresent = request.nextUrl.searchParams.has(REASON_PARAM)
  const isRedirectIfAuth = config.publicRoutesRedirectIfAuthenticated.some((route) =>
    matchesPublicRoute(pathname, route)
  )

  if (isRedirectIfAuth && !reasonPresent) {
    const destination = safeRelativePath(config.getDefaultDashboard(role), '/')
    return NextResponse.redirect(new URL(destination, request.nextUrl.origin))
  }

  return NextResponse.next({ request: { headers: sanitizedHeaders } })
}

/**
 * Handle a request classified as `protected`. Branches:
 *
 *   1. No cookie + no `has_session` → redirect to `loginPath`.
 *   2. No cookie / invalid token + `has_session` + counter < max →
 *      silent-refresh attempt.
 *   3. Valid token with blocked `status` → `loginPath?reason=<status>`
 *      (case-insensitive against `blockedUserStatuses`).
 *   4. Valid token + role NOT in `allowedRoles` →
 *      `getDefaultDashboard(role)?error=forbidden`.
 *   5. Valid token + allowed role → authorised response with
 *      identity headers.
 */
export function handleProtectedRoute(
  request: NextRequest,
  pathname: string,
  tokenState: TokenState,
  matched: ProtectedRoutePattern,
  config: ResolvedAuthProxyConfig,
  sanitizedHeaders: Headers
): NextResponse {
  if (!tokenState.authenticated) {
    return handleUnauthenticatedOnProtected(request, pathname, tokenState, config)
  }

  const token = tokenState.token
  const role = token?.role ?? ''
  const status = asString(token?.payload['status'])

  // Status blocking. Comparison uses `toLocaleLowerCase('en-US')` so
  // Turkish/Azeri locale folding (`I` → `ı`) cannot bypass the
  // equivalence the config JSDoc promises. The `reason` value we
  // redirect with comes from the configured allowlist — NEVER the
  // raw JWT claim — so a forged `status` value in decode-only mode
  // cannot smuggle a crafted string onto the login page.
  if (typeof status === 'string' && status.length > 0) {
    const statusLower = status.toLocaleLowerCase('en-US')
    const matchedStatus = config.blockedUserStatuses.find(
      (entry) => entry.toLocaleLowerCase('en-US') === statusLower
    )
    if (matchedStatus !== undefined) {
      return redirectToLogin(request, config, matchedStatus.toLocaleLowerCase('en-US'))
    }
  }

  // RBAC check.
  if (!matched.allowedRoles.includes(role)) {
    const fallback = safeRelativePath(config.getDefaultDashboard(role), '/')
    const destination = matched.redirectPath ?? fallback
    const safeDestination = safeRelativePath(destination, fallback)
    const url = new URL(safeDestination, request.nextUrl.origin)
    url.searchParams.set('error', 'forbidden')
    return NextResponse.redirect(url)
  }

  // Authorised — inject identity headers, strip `_r` from URL.
  return buildAuthorisedResponse(request, token, role, config, sanitizedHeaders)
}

/**
 * Sub-branch of {@link handleProtectedRoute} taken when the user is
 * unauthenticated. Chooses between straight-to-login and
 * silent-refresh based on the `has_session` cookie and the two
 * anti-loop guards.
 */
function handleUnauthenticatedOnProtected(
  request: NextRequest,
  pathname: string,
  tokenState: TokenState,
  config: ResolvedAuthProxyConfig
): NextResponse {
  const refreshAttempts = readRefreshAttemptCounter(request, config.maxRefreshAttempts)
  const shouldBreakForReason = isReasonExpired(request)
  const shouldBreakForCounter = refreshAttempts >= config.maxRefreshAttempts
  const hasSessionCookie = request.cookies.get(config.cookieNames.hasSession)?.value
  const hasSession = hasSessionCookie !== undefined && hasSessionCookie.length > 0

  // Never logged in (or both cookies already cleared) — straight to
  // login. No loop risk.
  if (!tokenState.hasCookie && !hasSession) {
    return redirectToLogin(request, config)
  }

  // Both anti-loop guards must break the refresh chain BEFORE a
  // silent-refresh redirect is issued. We always signal the login
  // page with `reason=expired` so the public-route loop-break guard
  // fires on the next navigation without an extra refresh round-trip.
  if (shouldBreakForCounter || shouldBreakForReason) {
    return redirectToLogin(request, config, REASON_EXPIRED)
  }

  if (hasSession) {
    const destination = buildRefreshDestination(
      pathname,
      request.nextUrl.searchParams,
      refreshAttempts + 1
    )
    const silentRefreshUrl = new URL(buildSilentRefreshUrl(request, destination))
    return NextResponse.redirect(silentRefreshUrl)
  }

  // Cookie was present but invalid AND `has_session` missing —
  // treat the same as "never logged in".
  return redirectToLogin(request, config)
}

/**
 * Produce the success-path response for an authenticated,
 * authorised protected-route request.
 *
 * - Identity headers (`x-user-id`, `x-user-role`, `x-tenant-id`,
 *   `x-tenant-domain`) are attached to the forwarded REQUEST
 *   headers via `NextResponse.next({ request: { headers } })` so
 *   downstream server components read them from the request, not
 *   the response.
 * - The internal `_r` refresh counter is removed from the forwarded
 *   URL via `NextResponse.rewrite()` so server components never
 *   observe it.
 * - `reason=expired` is NOT stripped: a fresh-token user on a URL
 *   that carries it is an unexpected but harmless state, and we
 *   preserve user-visible state.
 */
export function buildAuthorisedResponse(
  request: NextRequest,
  token: DecodedToken | undefined,
  role: string,
  config: ResolvedAuthProxyConfig,
  sanitizedHeaders: Headers
): NextResponse {
  const forwardedHeaders = new Headers(sanitizedHeaders)
  setOrDeleteHeader(forwardedHeaders, config.userHeaders.userId, token?.sub)
  setOrDeleteHeader(forwardedHeaders, config.userHeaders.role, role)
  setOrDeleteHeader(forwardedHeaders, config.userHeaders.tenantId, token?.tenantId)
  setOrDeleteHeader(
    forwardedHeaders,
    config.userHeaders.tenantDomain,
    asString(token?.payload['tenantDomain'])
  )

  const responseInit = { request: { headers: forwardedHeaders } }

  if (!request.nextUrl.searchParams.has(REFRESH_ATTEMPT_PARAM)) {
    // Nothing to strip — fast path (common case).
    return NextResponse.next(responseInit)
  }

  const cleanUrl = new URL(request.nextUrl)
  cleanUrl.searchParams.delete(REFRESH_ATTEMPT_PARAM)
  // `rewrite` keeps the browser URL as-is but feeds the downstream
  // request pipeline the cleaned URL — server components see no `_r`.
  return NextResponse.rewrite(cleanUrl, responseInit)
}

/**
 * Produce a redirect to the configured login path, optionally
 * attaching `reason=<reason>` so the login page can render a
 * contextual message and so the public-route loop-break guard fires
 * on any subsequent navigation.
 */
export function redirectToLogin(
  request: NextRequest,
  config: ResolvedAuthProxyConfig,
  reason?: string
): NextResponse {
  const loginPath = safeRelativePath(config.loginPath, '/')
  const url = new URL(loginPath, request.nextUrl.origin)
  if (reason !== undefined && reason.length > 0) {
    url.searchParams.set(REASON_PARAM, reason)
  }
  return NextResponse.redirect(url)
}
