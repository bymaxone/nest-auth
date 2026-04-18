/**
 * Route classification for {@link createAuthProxy}.
 *
 * Exposes {@link classifyRoute} (consumed by the proxy body) and
 * {@link matchesPublicRoute} (consumed by `proxyHandlers` when
 * deciding whether an authenticated user is on a
 * "redirect if authenticated" route).
 */

import type { ProtectedRoutePattern, ResolvedAuthProxyConfig } from '../createAuthProxy'

/**
 * Classification of a normalised request pathname. Encoded as a
 * discriminated union so TypeScript narrows `matched` to
 * `ProtectedRoutePattern` when `kind === 'protected'`.
 */
export type ClassifiedRoute =
  | { readonly kind: 'api' | 'public' | 'unmatched'; readonly matched: undefined }
  | { readonly kind: 'protected'; readonly matched: ProtectedRoutePattern }

/**
 * Classify a normalised request pathname against the configured
 * route lists.
 *
 * Resolution order:
 *   1. Paths beginning with `/api/auth/` are classified as `api` —
 *      those routes are served by the silent-refresh,
 *      client-refresh, and logout handlers rather than by the proxy
 *      itself.
 *   2. Paths matching any protected-route pattern classify as
 *      `protected`.
 *   3. Paths in the public-routes list classify as `public`.
 *   4. Otherwise `unmatched` — the proxy treats these as public by
 *      default so the app's own routing can take over.
 *
 * PRECONDITION: `pathname` must already have been run through
 * {@link normalizePath} so `//` and `/./` segments cannot bypass the
 * `/api/auth/` prefix check.
 */
export function classifyRoute(pathname: string, config: ResolvedAuthProxyConfig): ClassifiedRoute {
  if (pathname.startsWith('/api/auth/')) {
    return { kind: 'api', matched: undefined }
  }

  for (const route of config.protectedRoutes) {
    if (matchesRoutePattern(pathname, route.pattern)) {
      return { kind: 'protected', matched: route }
    }
  }

  for (const route of config.publicRoutes) {
    if (matchesPublicRoute(pathname, route)) {
      return { kind: 'public', matched: undefined }
    }
  }

  return { kind: 'unmatched', matched: undefined }
}

/**
 * Whether a public-route configuration string matches a pathname.
 *
 * A public route string matches when the pathname is exactly equal
 * to it OR starts with `<route>/`. We deliberately do NOT accept a
 * bare prefix match (e.g., `/login` should not match
 * `/loginWithOAuth`).
 */
export function matchesPublicRoute(pathname: string, route: string): boolean {
  if (pathname === route) return true
  if (route.endsWith('/')) return pathname.startsWith(route)
  return pathname.startsWith(`${route}/`)
}

/**
 * Minimal pattern matcher for protected routes.
 *
 * Supported forms:
 *   - Exact string: `/dashboard` matches only `/dashboard`.
 *   - Trailing wildcard: `/dashboard/*` and `/dashboard/:path*`
 *     match `/dashboard`, `/dashboard/a`, `/dashboard/a/b`, …
 *     (zero-or-more trailing segments — mirrors Next.js `:path*`
 *     semantics).
 *   - Single-segment placeholder: `/tenants/:id/users` matches
 *     `/tenants/abc/users` but NOT `/tenants/abc/users/extra`.
 *
 * Wildcards are permitted ONLY as the LAST segment; mid-pattern
 * wildcards are rejected at factory time by `validateConfig`.
 */
export function matchesRoutePattern(pathname: string, pattern: string): boolean {
  if (pattern === pathname) return true

  const patternSegments = pattern.split('/').filter((segment) => segment.length > 0)
  const pathSegments = pathname.split('/').filter((segment) => segment.length > 0)

  for (let i = 0; i < patternSegments.length; i += 1) {
    /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable within the loop bounds */
    // eslint-disable-next-line security/detect-object-injection -- i is a bounded numeric loop counter.
    const patternSegment = patternSegments[i] ?? ''
    const isTrailingGlob =
      i === patternSegments.length - 1 && (patternSegment === '*' || patternSegment.endsWith('*'))

    if (isTrailingGlob) {
      // Zero-or-more remaining segments: match regardless of how
      // many path segments remain (including zero).
      return true
    }

    if (i >= pathSegments.length) {
      // Path shorter than pattern and no trailing glob to absorb the
      // gap — no match.
      return false
    }

    /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable within the loop bounds */
    // eslint-disable-next-line security/detect-object-injection -- i is a bounded numeric loop counter.
    const pathSegment = pathSegments[i] ?? ''

    if (patternSegment.startsWith(':')) {
      // Single-segment param placeholder — any non-empty segment is
      // accepted. (`i` advances via the loop counter.)
      continue
    }

    if (patternSegment !== pathSegment) return false
  }

  // All pattern segments matched and the path has no extra segments.
  return pathSegments.length === patternSegments.length
}

/**
 * Normalise a pathname so that `//`, `/./`, and `/../` sequences
 * cannot bypass the classifier's `/api/auth/` prefix check.
 *
 * Constructs a `URL` with a dummy base so we reuse the browser/Edge
 * URL parser's built-in normalisation. Returns `/` for any input
 * that fails to parse — the safest classification.
 */
export function normalizePath(pathname: string): string {
  try {
    return new URL(pathname, 'http://placeholder.invalid').pathname
  } catch {
    return '/'
  }
}
