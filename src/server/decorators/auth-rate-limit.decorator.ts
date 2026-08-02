/**
 * @fileoverview Declares the per-IP limit a route is served under.
 *
 * @layer Decorator
 */
import { SetMetadata } from '@nestjs/common'

/** Metadata key carrying the route's rate limit. */
export const AUTH_RATE_LIMIT_KEY = 'bymax:auth:rate-limit'

/** One route's limit: `limit` requests per `ttl` milliseconds, per client IP. */
export interface AuthRateLimitWindow {
  /** Requests allowed inside the window. */
  limit: number
  /** Window length in milliseconds. */
  ttl: number
}

/**
 * Declares the per-IP limit `AuthRateLimitGuard` enforces for a route.
 *
 * @remarks
 * The values come from `AUTH_THROTTLE_CONFIGS`, so a route is described once and both the
 * library's own guard and a host-side `@Throttle()` read the same numbers.
 *
 * @param config - The named entry from `AUTH_THROTTLE_CONFIGS`.
 * @returns The method decorator.
 *
 * @example
 * ```typescript
 * @AuthRateLimit(AUTH_THROTTLE_CONFIGS.login)
 * @Post('login')
 * login() { ... }
 * ```
 *
 * @layer Decorator
 */
export function AuthRateLimit(config: { default: AuthRateLimitWindow }): MethodDecorator {
  return SetMetadata(AUTH_RATE_LIMIT_KEY, config.default)
}
