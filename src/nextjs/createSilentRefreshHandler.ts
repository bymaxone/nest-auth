/**
 * `createSilentRefreshHandler` — factory for the GET
 * `/api/auth/silent-refresh` route handler.
 *
 * The proxy sends the browser here when it detects a missing or
 * expired access token but a surviving `has_session` cookie. The
 * handler forwards the incoming cookies to the upstream NestJS
 * `POST /auth/refresh` endpoint and, on success, redirects the
 * browser back to the original destination with the refreshed
 * `Set-Cookie` headers attached. On failure it redirects to the
 * configured `loginPath` with `reason=expired` and clears the three
 * auth cookies so the proxy's next pass sees a fully logged-out
 * state.
 *
 * Critical concerns handled here:
 *
 *   - **Open-redirect defence.** The `redirect` query parameter is
 *     attacker-controlled (it arrives from a URL the browser was
 *     pointed at). The handler rejects values that do not start with
 *     `/`, that begin with `//` (protocol-relative URLs), or that
 *     embed CR/LF/NUL/backslash; it then resolves the value against
 *     the request's origin and rejects anything whose origin drifts.
 *     Everything suspicious falls back to `loginPath`.
 *   - **`Set-Cookie` deduplication.** Multi-domain white-label
 *     deployments may receive multiple `Set-Cookie` headers for the
 *     same cookie name. `dedupeSetCookieHeaders` collapses them by
 *     `(name, domain)` — last writer wins.
 *   - **Legacy runtime support.** `getSetCookieHeaders` transparently
 *     falls back to parsing a single comma-joined `Set-Cookie`
 *     header on Node < 18.14.
 *   - **CDN cache poisoning.** Every response sets
 *     `Cache-Control: no-store, no-cache` so intermediate caches
 *     cannot replay a stale redirect.
 *   - **Empty refresh response.** A 2xx response with no `Set-Cookie`
 *     header is treated as a failure; otherwise the proxy would
 *     redirect back into an identical refresh attempt, producing a
 *     silent retry loop.
 *
 * Consumer obligations documented in the factory JSDoc below:
 *
 *   - **Rate limiting.** The handler makes one upstream `POST` per
 *     inbound `GET`. Apply route-level rate limiting in the consumer
 *     app to prevent DoS amplification.
 *   - **Host-header trust.** `origin` is derived from the request's
 *     `Host`. Self-hosted Next.js deployments must configure the
 *     reverse proxy to forward only trusted `Host` values.
 *   - **`apiBase`.** Always points to your OWN NestJS backend — all
 *     incoming cookies are forwarded there.
 *
 * Edge-Runtime-safe: uses only `fetch`, `URL`, and the standard
 * Headers API.
 */

import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

import { AUTH_PROXY_ROUTES } from '@bymax-one/nest-auth/shared'

import {
  assertValidApiBase,
  assertValidUpstreamPath,
  buildRefreshUrl
} from './helpers/buildRefreshUrl'
import { dedupeSetCookieHeaders, getSetCookieHeaders } from './helpers/dedupeSetCookieHeaders'
import {
  assertSafeCookieName,
  assertSafeCookiePath,
  isSafeSameOriginPath,
  serializeClearCookie
} from './helpers/routeHandlerUtils'

/** Default cookie path used when clearing the refresh-token cookie on failure. */
const DEFAULT_REFRESH_COOKIE_PATH = '/api/auth'

/**
 * Configuration contract for {@link createSilentRefreshHandler}.
 */
export interface SilentRefreshHandlerConfig {
  /**
   * Absolute base URL of the upstream NestJS API (e.g.,
   * `https://api.example.com`). Must NOT include a trailing slash.
   *
   * SECURITY — all cookies on the incoming request are forwarded to
   * this URL. Ensure `apiBase` always points to your OWN NestJS
   * backend; never set it to a third-party host.
   */
  readonly apiBase: string

  /**
   * Pathname of the login page. Used as the fallback destination on
   * refresh failure and on open-redirect rejection. MUST be a
   * same-origin path starting with `/` (not `//`) and MUST NOT
   * contain CR, LF, NUL, or backslash characters.
   */
  readonly loginPath: string

  /**
   * Pathname of the refresh endpoint on the upstream API. Defaults
   * to `/auth/refresh`.
   */
  readonly refreshPath?: string

  /**
   * Cookie names the handler clears on refresh failure. These must
   * match the upstream NestJS auth module's configuration. On
   * failure the handler clears:
   *   - `access` at path `/`
   *   - `refresh` at `refreshCookiePath` (default `/api/auth`)
   *   - `hasSession` at path `/`
   */
  readonly cookieNames: {
    readonly access: string
    readonly refresh: string
    readonly hasSession: string
  }

  /**
   * Path attribute for the refresh cookie clear. Defaults to
   * `/api/auth` — matches the default scope of the NestJS auth
   * module's refresh cookie.
   */
  readonly refreshCookiePath?: string
}

/**
 * Type of the Next.js App Router GET handler returned by the
 * factory. Exported for convenience in tests.
 */
export type SilentRefreshHandler = (request: NextRequest) => Promise<NextResponse>

/**
 * Create a GET handler for `/api/auth/silent-refresh`.
 *
 * The returned handler:
 *   1. Resolves a safe `redirect` destination (see open-redirect
 *      defence above).
 *   2. Forwards the incoming cookies to the upstream refresh endpoint.
 *   3. On 2xx with a non-empty `Set-Cookie` payload: emits a 302 to
 *      the destination and propagates the deduplicated cookies.
 *   4. On non-2xx, fetch failure, or a 2xx with no cookies: emits a
 *      302 to `loginPath?reason=expired` with all three auth cookies
 *      cleared (`Max-Age=0`).
 *
 * @remarks
 * RATE LIMITING — this factory does not rate-limit. Every invocation
 * makes an outbound `POST` to `apiBase`. Apply rate limiting at the
 * Next.js middleware or CDN layer in the consumer app to prevent
 * DoS amplification against the upstream service.
 *
 * @remarks
 * HOST-HEADER TRUST — `request.nextUrl.origin` is derived from the
 * `Host` header. On Vercel this is safe; self-hosted deployments
 * behind a reverse proxy MUST configure `trustHost` / forward only
 * vetted `Host` values, or the open-redirect defence can be bypassed
 * by an attacker who controls the `Host` header.
 *
 * @throws {Error} When `loginPath` is not a same-origin pathname.
 */
export function createSilentRefreshHandler(
  config: SilentRefreshHandlerConfig
): SilentRefreshHandler {
  if (!isSafeSameOriginPath(config.loginPath)) {
    throw new Error(
      `createSilentRefreshHandler: loginPath "${config.loginPath}" must be a same-origin pathname starting with "/" (not "//") and must not contain CR/LF/NUL/backslash characters.`
    )
  }
  assertValidApiBase(config.apiBase, 'createSilentRefreshHandler')
  assertValidUpstreamPath(config.refreshPath, 'createSilentRefreshHandler', 'refreshPath')
  assertSafeCookieName(
    config.cookieNames.access,
    'createSilentRefreshHandler',
    'cookieNames.access'
  )
  assertSafeCookieName(
    config.cookieNames.refresh,
    'createSilentRefreshHandler',
    'cookieNames.refresh'
  )
  assertSafeCookieName(
    config.cookieNames.hasSession,
    'createSilentRefreshHandler',
    'cookieNames.hasSession'
  )
  const refreshCookiePath = config.refreshCookiePath ?? DEFAULT_REFRESH_COOKIE_PATH
  assertSafeCookiePath(refreshCookiePath, 'createSilentRefreshHandler', 'refreshCookiePath')
  const refreshUrl = buildRefreshUrl(config.apiBase, config.refreshPath)

  return async function silentRefreshHandler(request: NextRequest): Promise<NextResponse> {
    const origin = request.nextUrl.origin
    const rawDestination = request.nextUrl.searchParams.get('redirect')
    const destination = resolveSafeDestination(rawDestination, origin, config.loginPath)

    let upstream: Response
    try {
      upstream = await fetch(refreshUrl, {
        method: 'POST',
        headers: {
          cookie: request.headers.get('cookie') ?? '',
          accept: 'application/json'
        },
        // Do not follow redirects automatically — the upstream is
        // expected to respond with the new cookies on 2xx or an
        // auth error on 4xx/5xx; a redirect would indicate
        // misconfiguration and must not be silently followed. Do
        // not change this to `'follow'` without updating the
        // opaque-redirect guard below.
        redirect: 'manual'
      })
    } catch {
      return buildLogoutRedirect(origin, config)
    }

    // Defensive: `fetch(..., { redirect: 'manual' })` yields an
    // opaque-redirect response with `type === 'opaqueredirect'`,
    // `ok === false`, and in some runtimes `status === 0`. The
    // `!upstream.ok` check below already catches this today, but the
    // explicit opaque check is the load-bearing semantics — if a
    // future contributor changes `manual` to `follow`, the `.ok`
    // alone would suddenly accept an upstream auth-redirect as
    // success.
    if (upstream.type === 'opaqueredirect') {
      return buildLogoutRedirect(origin, config)
    }

    if (!upstream.ok) {
      return buildLogoutRedirect(origin, config)
    }

    const rawSetCookies = getSetCookieHeaders(upstream.headers)
    if (rawSetCookies.length === 0) {
      // A 2xx with no cookies cannot succeed — the browser would
      // retain the stale access cookie and the proxy would redirect
      // the user right back here. Treat as a failure.
      return buildLogoutRedirect(origin, config)
    }

    return buildSuccessRedirect(origin, destination, rawSetCookies)
  }
}

/**
 * Resolve the attacker-controlled `redirect` parameter to a safe
 * same-origin pathname. The function is exported so unit tests can
 * exercise it directly — its correctness is the main defence against
 * open-redirect attacks on this handler.
 *
 * Rules:
 *   1. Missing or empty value → `loginPath`.
 *   2. Does not start with `/` → `loginPath` (would be an absolute
 *      URL or a scheme-relative reference).
 *   3. Starts with `//` → `loginPath` (protocol-relative URL that
 *      would escape the origin).
 *   4. Contains `\\` / `\r` / `\n` / NUL → `loginPath` (defence in
 *      depth against runtime-specific normalisation quirks).
 *   5. After `new URL(candidate, origin)` resolution, the resulting
 *      origin MUST equal the request origin → otherwise `loginPath`.
 *
 * @example
 * ```ts
 * resolveSafeDestination('/dashboard', 'https://app.com', '/login')
 * //  → '/dashboard'
 *
 * resolveSafeDestination('//evil.com', 'https://app.com', '/login')
 * //  → '/login'
 *
 * resolveSafeDestination(null, 'https://app.com', '/login')
 * //  → '/login'
 * ```
 */
export function resolveSafeDestination(
  raw: string | null,
  origin: string,
  loginPath: string
): string {
  if (raw === null || raw.length === 0) return loginPath
  if (!raw.startsWith('/')) return loginPath
  if (raw.startsWith('//')) return loginPath
  if (/[\\\r\n\0]/.test(raw)) return loginPath

  let resolved: URL
  try {
    resolved = new URL(raw, origin)
  } catch {
    return loginPath
  }

  if (resolved.origin !== origin) return loginPath
  // Return the relative form — `pathname + search + hash` — so the
  // subsequent `NextResponse.redirect(new URL(path, origin))` call
  // cannot accidentally alter the origin even if the caller rebuilds
  // the destination against a different base.
  return `${resolved.pathname}${resolved.search}${resolved.hash}`
}

/**
 * Construct the success redirect response with propagated
 * `Set-Cookie` headers. Cookies are deduplicated by
 * `(name, domain)`; the last writer wins.
 */
function buildSuccessRedirect(
  origin: string,
  destination: string,
  rawSetCookies: readonly string[]
): NextResponse {
  const destinationUrl = new URL(destination, origin)
  const response = NextResponse.redirect(destinationUrl)
  response.headers.set('Cache-Control', 'no-store, no-cache')

  const deduped = dedupeSetCookieHeaders(rawSetCookies)
  for (const cookie of deduped) {
    response.headers.append('set-cookie', cookie)
  }

  return response
}

/**
 * Construct the logout fallback redirect response. Clears the three
 * auth cookies (access, refresh, hasSession) by setting them to
 * empty values with `Max-Age=0` on the appropriate path, then
 * redirects to `loginPath?reason=expired`.
 *
 * The `reason=expired` param is load-bearing: it is the signal that
 * breaks the proxy's anti-redirect-loop guard on public routes
 * (see NEST-174). Without it a user who lost their session could
 * ping-pong between the proxy and this handler forever.
 */
function buildLogoutRedirect(origin: string, config: SilentRefreshHandlerConfig): NextResponse {
  const loginUrl = new URL(config.loginPath, origin)
  loginUrl.searchParams.set('reason', 'expired')
  const response = NextResponse.redirect(loginUrl)
  response.headers.set('Cache-Control', 'no-store, no-cache')

  const clearCookies = [
    serializeClearCookie(config.cookieNames.access, '/'),
    serializeClearCookie(
      config.cookieNames.refresh,
      config.refreshCookiePath ?? DEFAULT_REFRESH_COOKIE_PATH
    ),
    serializeClearCookie(config.cookieNames.hasSession, '/')
  ]
  for (const cookie of clearCookies) {
    response.headers.append('set-cookie', cookie)
  }
  return response
}

/**
 * Re-exports the canonical path for the silent-refresh endpoint so
 * consumers who mount this factory can use the same constant the
 * proxy does, keeping the two aligned.
 */
export const SILENT_REFRESH_ROUTE = AUTH_PROXY_ROUTES.silentRefresh
