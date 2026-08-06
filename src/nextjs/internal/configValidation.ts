/**
 * Factory-time configuration validation for
 * {@link createAuthProxy}.
 *
 * Exports:
 *   - {@link validateConfig}: throws on misconfigurations that would
 *     otherwise manifest as silent runtime behaviour.
 *   - {@link resolveConfig}: fills in defaults.
 *   - {@link assertJwtSecretConfigured}: refuses to build a proxy
 *     that has no `jwtSecret` and therefore cannot verify a
 *     signature, in every environment.
 */

import type { AuthProxyConfig, ResolvedAuthProxyConfig } from '../createAuthProxy'
import { DEFAULT_MAX_REFRESH_ATTEMPTS } from './constants'
import { isSafeSameOriginPath } from '../helpers/routeHandlerUtils'

/**
 * Throw when the caller's configuration contains a shape we reject:
 *
 *   - Catch-all first segments / mid-pattern wildcards on
 *     `protectedRoutes` — both silently widen the protected surface.
 *   - `loginPath` or `ProtectedRoutePattern.redirectPath` that is not
 *     a same-origin pathname. These values flow into
 *     `NextResponse.redirect` and must be validated at startup so a
 *     misconfiguration surfaces loudly rather than as a silent
 *     fallback to `/` at runtime.
 */
export function validateConfig(config: AuthProxyConfig): void {
  // `isSafeSameOriginPath` from `routeHandlerUtils` is also used by
  // the route-handler factories — sharing the same validator keeps
  // the strictness surface consistent across the subpath and blocks
  // CR / LF / NUL / backslash in the configured paths as defence-
  // in-depth against header-injection traps in future downstream
  // URL builders.
  if (!isSafeSameOriginPath(config.loginPath)) {
    throw new Error(
      `createAuthProxy: loginPath "${config.loginPath}" must be a same-origin pathname starting with "/" (not "//") and must not contain CR/LF/NUL/backslash characters.`
    )
  }

  for (const route of config.protectedRoutes) {
    validateProtectedRoutePattern(route.pattern)
    if (route.redirectPath !== undefined && !isSafeSameOriginPath(route.redirectPath)) {
      throw new Error(
        `createAuthProxy: redirectPath "${route.redirectPath}" in pattern "${route.pattern}" must be a same-origin pathname starting with "/" (not "//") and must not contain CR/LF/NUL/backslash characters.`
      )
    }
  }
}

/**
 * Validate a single `protectedRoutes` pattern string. Extracted so
 * {@link validateConfig} stays flat and each error case reads as
 * one statement.
 */
function validateProtectedRoutePattern(pattern: string): void {
  const segments = pattern.split('/').filter((segment) => segment.length > 0)
  // Stryker disable next-line EqualityOperator: loop bound off-by-one visits an out-of-range (undefined) segment that is not a glob, leaving the validation result unchanged
  for (let i = 0; i < segments.length; i += 1) {
    /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable within the loop bounds */

    // Stryker disable next-line StringLiteral: unreachable within the loop bounds — the fallback's value can never be read
    const segment = segments[i] ?? ''
    // Stryker disable next-line ConditionalExpression,StringLiteral: `segment === '*'` is fully subsumed by `segment.endsWith('*')`, so dropping it or comparing against '' cannot change isGlob
    const isGlob = segment === '*' || segment.endsWith('*')
    if (!isGlob) continue

    const isLast = i === segments.length - 1
    if (!isLast) {
      throw new Error(
        `createAuthProxy: protected route pattern "${pattern}" contains a wildcard in a non-trailing position. Wildcards are only permitted as the last segment.`
      )
    }

    if (i === 0) {
      throw new Error(
        `createAuthProxy: protected route pattern "${pattern}" begins with a catch-all wildcard, which would promote every route to protected status. Use a concrete prefix segment.`
      )
    }
  }
}

/**
 * Resolve user-provided config into a fully-defaulted object.
 *
 * Currently only {@link AuthProxyConfig.maxRefreshAttempts} has a
 * default.
 */
export function resolveConfig(config: AuthProxyConfig): ResolvedAuthProxyConfig {
  return {
    ...config,
    maxRefreshAttempts: config.maxRefreshAttempts ?? DEFAULT_MAX_REFRESH_ATTEMPTS
  }
}

/**
 * Refuse to build a proxy that cannot verify a signature.
 *
 * Without a `jwtSecret` there is no way to tell a token this system issued from one an
 * attacker wrote. Every decision downstream — route gating, role checks, status blocking, and
 * the `x-user-id`/`x-user-role`/`x-tenant-id` headers injected into every server component —
 * reads the token's contents, so a crafted token carrying a future `exp` becomes whatever
 * identity it claims. That is not a degraded mode; it is an open door with a proxy in front of
 * it.
 *
 * This used to throw only when `NODE_ENV === 'production'` and merely warn elsewhere, which
 * left preview and staging deployments accepting forged identities — environments that hold
 * real data and are reachable from the internet at least as often as they are not. It also
 * staked the whole trust boundary on one unvalidated string: `NODE_ENV` unset, `staging`,
 * `prod`, or `production ` with a trailing space all took the warning branch. A secret is
 * either configured or it is not, and that question does not depend on an environment
 * variable, so the check no longer consults one.
 *
 * Consumers that terminate signature verification at an upstream gateway still supply the
 * secret here: it costs nothing, and it keeps the proxy's own decisions self-supporting rather
 * than contingent on a component this code cannot see.
 */
export function assertJwtSecretConfigured(config: ResolvedAuthProxyConfig): void {
  if (config.jwtSecret !== undefined && config.jwtSecret.length > 0) return

  throw new Error(
    'createAuthProxy: jwtSecret is required. Without it no JWT signature can be verified, ' +
      'so route gating, role checks, status blocking and the identity headers injected into ' +
      'server components would all trust unverified token contents — a crafted token with a ' +
      'future `exp` can impersonate any role. Provide `jwtSecret`; supply it even when an ' +
      'upstream gateway also verifies signatures.'
  )
}
