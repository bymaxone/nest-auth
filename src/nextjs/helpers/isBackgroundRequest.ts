/**
 * Background-request detection for the Next.js App Router.
 *
 * Next.js 13+ issues several classes of "background" HTTP requests that
 * look like ordinary navigations to the proxy but must NOT be treated
 * as user-initiated traffic:
 *
 *   - `RSC: 1` — a React Server Component fetch triggered by client-side
 *     navigation. The browser is still showing the previous page; returning
 *     a redirect here causes the client router to follow the redirect and
 *     then perform a second navigation, producing visible flicker or a
 *     redirect loop.
 *   - `Next-Router-Prefetch: 1` — a speculative prefetch for a `<Link>`
 *     that the user has not yet clicked. A redirect response is useless
 *     (there is no page to navigate) and noisy in logs.
 *   - `Next-Router-State-Tree` — the router's state-tree fetch during
 *     partial rendering. Same concern as RSC: the main document is
 *     already rendered, so redirects misbehave.
 *
 * When the proxy detects an unauthenticated background request it must
 * respond with `401` instead of a redirect. The client router interprets
 * the 401 as "this navigation is not authorized" and falls through to a
 * normal full-page navigation, where a redirect IS appropriate.
 *
 * This helper is pure, synchronous, and Edge-Runtime-safe (no Node-only
 * APIs).
 */

/**
 * Minimal structural type accepted by {@link isBackgroundRequest}.
 *
 * Both `Request` (Web Fetch API) and `NextRequest` expose `.headers` with
 * a `get(name)` method that performs a case-insensitive lookup. This
 * helper relies on that contract — any custom implementation passed in
 * unit tests or consumer code MUST normalise header names the same way,
 * otherwise background-request detection silently fails and the proxy
 * reintroduces the redirect loop this helper was built to prevent.
 *
 * Accepting a structural type keeps the helper trivially mockable and
 * avoids a hard import of `next/server`.
 */
export interface RequestWithHeaders {
  readonly headers: {
    /**
     * Case-insensitive header lookup. Must return `null` when the
     * header is absent and the raw value (possibly empty string) when
     * it is present.
     */
    get(name: string): string | null
  }
}

/**
 * Returns `true` when the request is a Next.js background request
 * (RSC fetch, router prefetch, or router state-tree fetch).
 *
 * Callers in the proxy use the result to choose between `401` (for
 * background requests) and a redirect (for top-level navigations) when
 * the user is not authenticated. See the module JSDoc for the rationale.
 *
 * Header names are passed lowercased so the guard remains robust against
 * non-standard `Headers` implementations that skip the RFC-mandated
 * case-insensitive comparison.
 *
 * @param request - Any value whose `headers.get(name)` returns the header
 *                  value or `null`. `NextRequest` and the standard
 *                  `Request` both satisfy this contract.
 * @returns `true` if at least one of `RSC`, `Next-Router-Prefetch`, or
 *          `Next-Router-State-Tree` headers is present with a non-empty
 *          value on the request.
 */
export function isBackgroundRequest(request: RequestWithHeaders): boolean {
  const { headers } = request
  return (
    isNonEmptyHeader(headers.get('rsc')) ||
    isNonEmptyHeader(headers.get('next-router-prefetch')) ||
    isNonEmptyHeader(headers.get('next-router-state-tree'))
  )
}

function isNonEmptyHeader(value: string | null): boolean {
  return value !== null && value.length > 0
}
