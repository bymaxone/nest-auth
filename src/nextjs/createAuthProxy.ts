/**
 * `createAuthProxy` — factory that produces a Next.js 16 proxy
 * function.
 *
 * The Next.js App Router looks for a `proxy.ts` file at the project
 * root that exports a `proxy` function. This factory makes it
 * straightforward to configure authentication, route guards, RBAC,
 * and the anti-redirect-loop invariant in one place:
 *
 * ```ts
 * // proxy.ts
 * import { createAuthProxy } from '@bymax-one/nest-auth/nextjs'
 *
 * export const { proxy } = createAuthProxy({
 *   publicRoutes: ['/', '/auth/login'],
 *   publicRoutesRedirectIfAuthenticated: ['/auth/login'],
 *   protectedRoutes: [
 *     { pattern: '/dashboard/:path*', allowedRoles: ['admin', 'member'] }
 *   ],
 *   loginPath: '/auth/login',
 *   getDefaultDashboard: (role) => role === 'admin' ? '/dashboard/admin' : '/dashboard',
 *   apiBase: process.env.API_BASE_URL ?? 'http://localhost:3001',
 *   jwtSecret: process.env.JWT_SECRET,
 *   cookieNames: { access: 'access_token', refresh: 'refresh_token', hasSession: 'has_session' },
 *   userHeaders: { userId: 'x-user-id', role: 'x-user-role', tenantId: 'x-tenant-id', tenantDomain: 'x-tenant-domain' },
 *   blockedUserStatuses: ['BANNED', 'INACTIVE', 'EXPIRED']
 * })
 *
 * export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] }
 * ```
 *
 * The returned `proxy` runs under the Next.js Edge Runtime, so this
 * module MUST stay Web-API-only. Internal pipeline modules live
 * under `src/nextjs/internal/`; this file is the public surface
 * (types + factory) only.
 */

import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

import { isBackgroundRequest } from './helpers/isBackgroundRequest'
import {
  resolveConfig,
  validateConfig,
  warnOnInsecureConfiguration
} from './internal/configValidation'
import { handleProtectedRoute, handlePublicRoute } from './internal/proxyHandlers'
import { buildSanitizedRequestHeaders } from './internal/proxyUtils'
import { classifyRoute, normalizePath } from './internal/routeClassifier'
import { readTokenState } from './internal/tokenState'

/**
 * Pattern specification for a protected route.
 *
 * - `pattern` matches the request pathname. Use a leading `/` for
 *   absolute matches. Three forms are supported: an exact path
 *   (`/dashboard`), a trailing wildcard (`/dashboard/*` or
 *   `/dashboard/:path*`) that matches the base path AND any subpath,
 *   and single-segment `:name` placeholders (`/tenants/:id/users`)
 *   that match exactly one path segment.
 * - `allowedRoles` is consulted by the protected-route handler.
 *   Roles are compared case-sensitively against the token's `role`
 *   claim.
 * - `redirectPath` is the destination when the route matches but
 *   the user lacks the required role. When omitted the proxy falls
 *   back to `config.getDefaultDashboard(role)`.
 *
 * Wildcards are only permitted as the LAST segment of the pattern.
 * The factory throws at configuration time if a wildcard appears
 * elsewhere — this avoids ambiguous middle-of-path globs that
 * would otherwise silently widen the protected surface.
 */
export interface ProtectedRoutePattern {
  readonly pattern: string
  readonly allowedRoles: readonly string[]
  readonly redirectPath?: string
}

/**
 * Configuration contract for {@link createAuthProxy}.
 *
 * Every field is required unless marked optional. The authors of
 * each downstream app are expected to populate this object from
 * their own environment; the library intentionally ships no
 * defaults that would hide a misconfiguration.
 */
export interface AuthProxyConfig {
  /**
   * Pathnames that can be accessed without authentication. Match
   * is an exact equality or a prefix check with a trailing `/`.
   */
  readonly publicRoutes: readonly string[]

  /**
   * Subset of {@link publicRoutes} that must redirect AUTHENTICATED
   * users away (e.g., a signed-in user visiting `/auth/login` gets
   * redirected to their dashboard via {@link getDefaultDashboard}).
   */
  readonly publicRoutesRedirectIfAuthenticated: readonly string[]

  /**
   * Pattern-based protected route specifications. The first
   * matching pattern wins, so order them from most-specific to
   * least-specific. Catch-all patterns (`*` / `:name*`) at segment
   * 0 are rejected at factory time.
   */
  readonly protectedRoutes: readonly ProtectedRoutePattern[]

  /**
   * Pathname of the login page. MUST be a same-origin path
   * starting with `/` and MUST NOT contain CR / LF / NUL /
   * backslash characters.
   */
  readonly loginPath: string

  /**
   * Function that resolves the default dashboard path for a given
   * role. MUST return a same-origin path starting with `/` (not
   * `//`). Call sites guard the return value against open-redirect
   * attempts.
   */
  readonly getDefaultDashboard: (role: string) => string

  /**
   * Absolute base URL of the upstream NestJS API (e.g.,
   * `https://api.example.com`). Used by the silent-refresh and
   * logout handlers; not used directly by the proxy.
   */
  readonly apiBase: string

  /**
   * HS256 secret used to verify access tokens inside the Edge
   * proxy. When omitted the proxy falls back to decode-only mode
   * and logs a `console.warn` at factory time — in decode-only
   * mode signature verification MUST be performed upstream.
   */
  readonly jwtSecret?: string

  /**
   * Maximum number of consecutive silent-refresh redirects the
   * proxy will chain before giving up and rendering the page
   * as-is. Two is the documented default.
   */
  readonly maxRefreshAttempts?: number

  /**
   * Cookie names the proxy reads and clears. These must match the
   * names configured in the upstream NestJS auth module.
   */
  readonly cookieNames: {
    readonly access: string
    readonly refresh: string
    readonly hasSession: string
  }

  /**
   * Header names used to propagate decoded JWT claims to
   * downstream server components and route handlers after
   * successful authentication.
   */
  readonly userHeaders: {
    readonly userId: string
    readonly role: string
    readonly tenantId: string
    readonly tenantDomain: string
  }

  /**
   * Token `status` claim values that should BLOCK a user even if
   * their token is cryptographically valid (e.g., BANNED,
   * INACTIVE, EXPIRED). Comparison is case-insensitive: both the
   * incoming claim value and the configured entries are lowercased
   * before equality is tested.
   */
  readonly blockedUserStatuses: readonly string[]
}

/**
 * Return shape of {@link createAuthProxy}.
 */
export interface AuthProxyInstance {
  /**
   * The Next.js 16 proxy function. Destructure and re-export:
   *
   * ```ts
   * export const { proxy } = createAuthProxy({ ... })
   * ```
   */
  readonly proxy: (request: NextRequest) => Promise<NextResponse>

  /**
   * The resolved configuration — exposed for debugging and tests.
   */
  readonly config: ResolvedAuthProxyConfig
}

/**
 * Config after defaulting. Exposed separately so downstream
 * helpers (silent-refresh, logout) can depend on the defaulted
 * values without every caller having to re-apply the defaults.
 */
export interface ResolvedAuthProxyConfig extends AuthProxyConfig {
  readonly maxRefreshAttempts: number
}

/**
 * Create a Next.js proxy function wired to the given configuration.
 *
 * The returned `proxy` is async because signature verification via
 * Web Crypto returns a promise.
 *
 * @throws {Error} When the configuration contains an invalid
 *                 protected-route pattern (mid-pattern wildcard or
 *                 catch-all at segment 0), or when `loginPath` /
 *                 `redirectPath` are not same-origin pathnames.
 */
export function createAuthProxy(config: AuthProxyConfig): AuthProxyInstance {
  validateConfig(config)
  const resolved = resolveConfig(config)
  warnOnInsecureConfiguration(resolved)
  return { proxy: (request) => runProxy(request, resolved), config: resolved }
}

/**
 * Body of the proxy function. Extracted from the factory so the
 * factory itself stays a short initialisation-and-return block.
 *
 * Steps:
 *   1. Normalise the pathname and classify the route.
 *   2. `/api/auth/*` passes straight through.
 *   3. Read token state and build a sanitised header set (strips
 *      every identity-header slot so a client-forged header cannot
 *      reach server components).
 *   4. Background requests (RSC, prefetch, state-tree) for
 *      unauthenticated users short-circuit with 401.
 *   5. Dispatch to protected / public handler.
 */
async function runProxy(
  request: NextRequest,
  resolved: ResolvedAuthProxyConfig
): Promise<NextResponse> {
  const pathname = normalizePath(request.nextUrl.pathname)
  const classification = classifyRoute(pathname, resolved)

  if (classification.kind === 'api') {
    // Internal `/api/auth/*` endpoints are owned by the dedicated
    // route handlers; the proxy just passes them through.
    return NextResponse.next()
  }

  const tokenState = await readTokenState(request, resolved)
  const sanitizedHeaders = buildSanitizedRequestHeaders(request, resolved)

  if (isBackgroundRequest(request) && !tokenState.authenticated) {
    // RSC/prefetch/state-tree fetches cannot tolerate a redirect
    // without producing a visible loop; return a bare 401 instead.
    // `Cache-Control: no-store, no-cache` prevents CDNs from
    // caching this 401 and replaying it for subsequent
    // authenticated users.
    return new NextResponse(null, {
      status: 401,
      headers: { 'Cache-Control': 'no-store, no-cache' }
    })
  }

  if (classification.kind === 'protected') {
    // Narrowed by the discriminated union — `classification.matched`
    // is `ProtectedRoutePattern`.
    return handleProtectedRoute(
      request,
      pathname,
      tokenState,
      classification.matched,
      resolved,
      sanitizedHeaders
    )
  }

  // `public` / `unmatched` → public handler.
  return handlePublicRoute(request, pathname, tokenState, resolved, sanitizedHeaders)
}
