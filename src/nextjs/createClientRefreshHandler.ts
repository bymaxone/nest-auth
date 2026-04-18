/**
 * `createClientRefreshHandler` — factory for the POST
 * `/api/auth/client-refresh` route handler.
 *
 * While `createSilentRefreshHandler` (NEST-177) is invoked by the
 * proxy during server-side navigation, this handler is the
 * same-origin bridge the browser uses when a client-side `fetch`
 * receives a 401 and wants to refresh its access token without a
 * full-page redirect. Because it is invoked from JavaScript via
 * `fetch(..., { credentials: 'include' })`, the browser sends the
 * auth cookies automatically and the handler simply forwards them
 * to the upstream NestJS `POST /auth/refresh`, translating the
 * response into a bare 200/401 the calling code can branch on.
 *
 * Concretely the handler contract is:
 *
 *   - `fetch('/api/auth/client-refresh', { method: 'POST', credentials: 'include' })`
 *   - 200 OK + new `Set-Cookie` headers on success — the browser
 *     installs the new cookies before the caller retries the
 *     original request.
 *   - 401 Unauthorized with an empty body on failure — the caller
 *     should transition to logged-out UI.
 *   - 405 Method Not Allowed for non-POST methods. Keeps the handler
 *     robust against misconfigured Next.js route files that would
 *     otherwise let a `GET <img src>` cross-origin attack forward
 *     cookies to the backend.
 *
 * Every response carries `Cache-Control: no-store, no-cache` so
 * intermediate caches cannot replay old 200s (which would install
 * someone else's cookies on a different user) or 401s (which would
 * break legitimate sign-ins after a CDN flush).
 *
 * CSRF posture: same-origin cookie policy (`SameSite=Lax`/`Strict`)
 * on the upstream NestJS auth module is the primary defence. The
 * method guard here provides a second line against verb-confusion
 * variants. Consumers deploying on a separate domain from the API
 * MUST additionally ensure CORS is configured on the upstream to
 * reject cross-origin browser requests.
 *
 * Edge-Runtime-safe: uses only `fetch`, `Response`, and the Headers
 * API.
 */

import type { NextRequest } from 'next/server'

import { AUTH_PROXY_ROUTES } from '@bymax-one/nest-auth/shared'

import { assertValidApiBase, buildRefreshUrl } from './helpers/buildRefreshUrl'
import { dedupeSetCookieHeaders, getSetCookieHeaders } from './helpers/dedupeSetCookieHeaders'

/**
 * Configuration contract for {@link createClientRefreshHandler}.
 */
export interface ClientRefreshHandlerConfig {
  /**
   * Absolute base URL of the upstream NestJS API (e.g.,
   * `https://api.example.com`). Must start with `http://` or
   * `https://`. Trailing slashes are trimmed.
   *
   * SECURITY — all cookies on the incoming request are forwarded to
   * this URL. Ensure `apiBase` always points to your OWN NestJS
   * backend.
   */
  readonly apiBase: string

  /**
   * Pathname of the refresh endpoint on the upstream API. Defaults
   * to `/auth/refresh`.
   */
  readonly refreshPath?: string
}

/**
 * Signature of the POST handler returned by the factory.
 */
export type ClientRefreshHandler = (request: NextRequest) => Promise<Response>

/**
 * Create a POST handler for `/api/auth/client-refresh`.
 *
 * The handler:
 *   1. Rejects any non-POST request with `405 Method Not Allowed`.
 *   2. Forwards incoming cookies to the upstream refresh endpoint.
 *   3. Returns `200` with the refreshed `Set-Cookie` headers on
 *      success. Cookies are deduplicated via
 *      `dedupeSetCookieHeaders` to guard multi-domain white-label
 *      deployments.
 *   4. Returns `401` with an empty body on ANY failure mode (fetch
 *      error, non-2xx upstream, a 2xx upstream that failed to emit
 *      cookies, or an upstream 3xx that `fetch` exposed as an
 *      opaque redirect). Never leaks upstream error bodies to the
 *      browser.
 *
 * @remarks
 * RATE LIMITING — this factory does not rate-limit. Every invocation
 * makes one outbound `POST` to `apiBase`. Apply rate limiting at the
 * Next.js middleware or CDN layer in the consumer app.
 *
 * @throws {Error} When `apiBase` is not an absolute HTTP(S) URL.
 */
export function createClientRefreshHandler(
  config: ClientRefreshHandlerConfig
): ClientRefreshHandler {
  assertValidApiBase(config.apiBase, 'createClientRefreshHandler')
  const refreshUrl = buildRefreshUrl(config.apiBase, config.refreshPath)

  return async function clientRefreshHandler(request: NextRequest): Promise<Response> {
    if (request.method !== 'POST') {
      return new Response(null, {
        status: 405,
        headers: { Allow: 'POST', 'Cache-Control': 'no-store, no-cache' }
      })
    }

    let upstream: Response
    try {
      upstream = await fetch(refreshUrl, {
        method: 'POST',
        headers: {
          cookie: request.headers.get('cookie') ?? '',
          accept: 'application/json'
        },
        // Manual — a 3xx from the upstream should never be followed
        // silently. See NEST-177 for the rationale.
        redirect: 'manual'
      })
    } catch {
      return buildUnauthorisedResponse()
    }

    if (upstream.type === 'opaqueredirect' || !upstream.ok) {
      return buildUnauthorisedResponse()
    }

    const rawSetCookies = getSetCookieHeaders(upstream.headers)
    if (rawSetCookies.length === 0) {
      // A 2xx with no cookies cannot succeed — the client would
      // retry with the same stale access token. Treat as 401 so the
      // caller transitions to logged-out UI instead of looping.
      return buildUnauthorisedResponse()
    }

    const responseHeaders = new Headers({ 'Cache-Control': 'no-store, no-cache' })
    for (const cookie of dedupeSetCookieHeaders(rawSetCookies)) {
      responseHeaders.append('set-cookie', cookie)
    }
    return new Response(null, { status: 200, headers: responseHeaders })
  }
}

function buildUnauthorisedResponse(): Response {
  return new Response(null, {
    status: 401,
    headers: { 'Cache-Control': 'no-store, no-cache' }
  })
}

/**
 * Canonical Next.js proxy-side path this handler is expected to be
 * mounted at. Exported so consumers can keep the route registration
 * and the factory in sync.
 */
export const CLIENT_REFRESH_ROUTE = AUTH_PROXY_ROUTES.clientRefresh
