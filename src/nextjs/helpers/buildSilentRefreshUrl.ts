/**
 * Silent-refresh URL builder for the Next.js auth proxy.
 *
 * When the proxy decides to attempt a transparent token refresh (either
 * on a public route with a stale `has_session` cookie or on a protected
 * route with an expired access token), it redirects the browser to
 * `/api/auth/silent-refresh?redirect=<destination>`. The silent-refresh
 * handler then exchanges the refresh cookie for a new access/refresh
 * pair and redirects the user back to `destination`.
 *
 * This helper builds that URL consistently across the proxy codebase so
 * the query-parameter encoding, leading-slash discipline, and default
 * destination (current pathname) are all centralised in one place.
 *
 * Edge-Runtime-safe: only relies on the standard `URL` constructor.
 *
 * @remarks
 * This builder deliberately does NOT validate whether `redirectTo`
 * points to the same origin. The canonical open-redirect check lives
 * in {@link createSilentRefreshHandler} (NEST-177) where the destination
 * is actually consumed. Callers of `buildSilentRefreshUrl` should only
 * pass relative paths (starting with `/`, not `//`) — passing an
 * absolute URL is not blocked here, but it will be rejected by the
 * handler.
 */

import { AUTH_PROXY_ROUTES } from '@bymax-one/nest-auth/shared'

/**
 * Minimal structural type accepted by {@link buildSilentRefreshUrl}.
 *
 * Matches both `NextRequest` and the standard web `Request` — we only
 * read `url` and `nextUrl.pathname` for the default fallback. The
 * optional `nextUrl` mirrors Next.js' request object; if absent we
 * fall back to parsing `url`.
 */
export interface RequestWithUrl {
  readonly url: string
  readonly nextUrl?: {
    readonly pathname: string
    readonly search?: string
  }
}

/**
 * Builds the absolute silent-refresh URL for the given request.
 *
 * - The `redirect` query parameter is always set so the handler knows
 *   where to return the user after the refresh round-trip.
 * - When `redirectTo` is omitted or empty, the function falls back to
 *   the current pathname (plus search, if available). This preserves
 *   deep-link context when the proxy needs to refresh mid-navigation.
 * - `redirectTo` is always URL-encoded via `URLSearchParams`, so
 *   callers do NOT pre-encode it.
 * - The returned URL is absolute (same origin as the request) because
 *   `NextResponse.redirect` prefers absolute URLs for cross-middleware
 *   consistency.
 *
 * @param request    - Request whose origin and pathname are used.
 * @param redirectTo - Destination path/URL after refresh. Optional; falls
 *                     back to the current pathname (+ search).
 * @returns An absolute URL string pointing to
 *          `{origin}/api/auth/silent-refresh?redirect={encoded-destination}`.
 * @throws  {TypeError} When `request.url` is not a valid HTTP(S) URL.
 */
export function buildSilentRefreshUrl(request: RequestWithUrl, redirectTo?: string): string {
  const requestUrl = new URL(request.url)

  // Guard against non-HTTP schemes leaking into the proxy. In production
  // `NextRequest.url` is always `http:` or `https:`, but because we accept
  // a structural interface for testability we enforce the invariant
  // explicitly rather than trust an unvalidated caller.
  if (requestUrl.protocol !== 'http:' && requestUrl.protocol !== 'https:') {
    throw new TypeError(`buildSilentRefreshUrl: unsupported URL protocol "${requestUrl.protocol}"`)
  }

  const silentRefreshUrl = new URL(AUTH_PROXY_ROUTES.silentRefresh, requestUrl.origin)

  const destination = resolveDestination(request, requestUrl, redirectTo)
  // `URLSearchParams.set` performs application/x-www-form-urlencoded
  // encoding — callers must NOT pre-encode.
  silentRefreshUrl.searchParams.set('redirect', destination)

  return silentRefreshUrl.toString()
}

function resolveDestination(
  request: RequestWithUrl,
  requestUrl: URL,
  redirectTo: string | undefined
): string {
  if (typeof redirectTo === 'string' && redirectTo.length > 0) {
    return redirectTo
  }

  // Prefer `nextUrl` when available — it reflects the effective path
  // after Next.js rewrites/basePath, which is what the user expects to
  // return to. Fall back to parsing the raw `url`.
  //
  // `hasOwnProperty` guards against a (contrived) prototype-pollution
  // scenario where `search` is set on `Object.prototype`: under the
  // structural interface we cannot assume `nextUrl` is a real
  // `NextURL` instance.
  if (request.nextUrl !== undefined) {
    const hasOwnSearch = Object.prototype.hasOwnProperty.call(request.nextUrl, 'search')
    const search = hasOwnSearch ? (request.nextUrl.search ?? '') : ''
    return `${request.nextUrl.pathname}${search}`
  }

  return `${requestUrl.pathname}${requestUrl.search}`
}
