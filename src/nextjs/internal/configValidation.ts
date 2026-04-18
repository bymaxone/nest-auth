/**
 * Factory-time configuration validation for
 * {@link createAuthProxy}.
 *
 * Exports:
 *   - {@link validateConfig}: throws on misconfigurations that would
 *     otherwise manifest as silent runtime behaviour.
 *   - {@link resolveConfig}: fills in defaults.
 *   - {@link warnOnInsecureConfiguration}: surfaces the decode-only
 *     trust-boundary decision via `console.warn` so an accidental
 *     deploy without a `jwtSecret` is visible at startup.
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
  for (let i = 0; i < segments.length; i += 1) {
    /* istanbul ignore next -- defensive `noUncheckedIndexedAccess` fallback, unreachable within the loop bounds */
    // eslint-disable-next-line security/detect-object-injection -- i is a bounded numeric loop counter.
    const segment = segments[i] ?? ''
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
 * Enforce the trust-boundary choice for the proxy's `jwtSecret`.
 *
 * When `jwtSecret` is absent, `readTokenState` falls back to
 * `decodeJwtToken`, which performs NO signature verification — the
 * JWT is trusted on expiry alone. Every RBAC and status-blocking
 * decision then trusts the raw token contents, and an attacker with
 * a crafted token carrying a future `exp` can impersonate any role.
 *
 * **Production behaviour** (`NODE_ENV === 'production'`): absence of
 * `jwtSecret` is a hard error. Silent decode-only mode in production
 * is almost always unintended and an easy deployment mistake (e.g. a
 * missing env var), so the factory refuses to construct.
 *
 * **Non-production behaviour**: warn via `console.warn` so local
 * development and preview environments continue to work while the
 * decision is still visible to the developer. The warning is a
 * best-effort side effect; we guard against environments that do not
 * expose `console` (some minimal Edge sandboxes) so the factory
 * never throws because of telemetry alone.
 */
export function warnOnInsecureConfiguration(config: ResolvedAuthProxyConfig): void {
  if (config.jwtSecret !== undefined && config.jwtSecret.length > 0) return

  if (isProductionEnv()) {
    throw new Error(
      'createAuthProxy: jwtSecret is required in production. ' +
        'Without it the proxy runs in decode-only mode where RBAC and status-blocking ' +
        'trust unverified tokens — a crafted token with a future `exp` can impersonate ' +
        'any role. Provide `jwtSecret` or move signature verification to an upstream ' +
        'gateway and explicitly opt out by running outside of a production environment.'
    )
  }

  /* istanbul ignore next -- defensive guard for minimal Edge sandboxes without a `console`; unreachable under jsdom/node */
  if (typeof console === 'undefined' || typeof console.warn !== 'function') return

  console.warn(
    '[@bymax-one/nest-auth] createAuthProxy: jwtSecret is not configured. ' +
      'The proxy is running in decode-only mode — JWT signatures are NOT verified. ' +
      'Every RBAC and status-blocking decision trusts the raw token contents, ' +
      'and forged tokens with a future `exp` can impersonate any role. ' +
      'Ensure an upstream gateway verifies signatures before requests reach downstream ' +
      'server components that read the injected identity headers. ' +
      'In production this condition throws instead of warning.'
  )
}

/**
 * Returns `true` when the current process is running in a production
 * environment. Read once per call rather than captured at module load
 * so tests can toggle `process.env['NODE_ENV']` per case.
 */
function isProductionEnv(): boolean {
  return process.env['NODE_ENV'] === 'production'
}
