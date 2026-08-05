/**
 * @fileoverview Enforces the per-IP limits the auth routes declare, backed by Redis.
 *
 * @layer Guard
 */
import { HttpStatus, Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import type { Request, Response } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { hmacSha256 } from '../crypto/secure-token'
import {
  AUTH_RATE_LIMIT_KEY,
  type AuthRateLimitWindow
} from '../decorators/auth-rate-limit.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'

/** Milliseconds in one second, for the window and `Retry-After` conversions. */
const MS_PER_SECOND = 1_000

/**
 * Enforces the per-IP limit a route declares with `@AuthRateLimit`.
 *
 * @remarks
 * The library has always shipped `AUTH_THROTTLE_CONFIGS`, but as **recommendations**: the
 * numbers only took effect if the host wired `ThrottlerModule` and registered its guard. A
 * deployment that did not — and nothing told it — ran every auth route with no per-IP limit at
 * all. This guard makes the same numbers real without any host wiring.
 *
 * The counter is the fixed-window primitive already used for the brute-force lockout: `INCR`
 * plus an `EXPIRE` applied only on the 0→1 transition, so the window starts at the first
 * request and does not slide forward under a steady trickle. Being in Redis rather than in
 * process memory also means the limit holds across instances, which an in-memory limiter
 * cannot do.
 *
 * The IP is keyed through the identifier HMAC rather than stored raw: a rate-limit keyspace is
 * still a record of who called what, and the rest of the keyspace already treats client-derived
 * identifiers that way (§24 invariant 9).
 *
 * A route with no `@AuthRateLimit` is not limited here — the decorator is the declaration.
 * Setting `rateLimit.enabled: false` disables the guard entirely, for a deployment that
 * already enforces the same limits at its edge and does not want to count twice.
 *
 * @layer Guard
 */
/**
 * The bucket requests with no readable address share. A constant, not a per-request value: an
 * unreadable address must not mean an unlimited budget.
 */
const UNKNOWN_CLIENT = 'unknown'

@Injectable()
export class AuthRateLimitGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.options.rateLimit.enabled) return true

    const limit = this.reflector.get<AuthRateLimitWindow | undefined>(
      AUTH_RATE_LIMIT_KEY,
      context.getHandler()
    )
    if (limit === undefined) return true

    const request = context.switchToHttp().getRequest<Request>()
    const windowSeconds = Math.max(1, Math.ceil(limit.ttl / MS_PER_SECOND))
    const key = this.counterKey(request, context)

    const hits = await this.redis.incrWithFixedTtl(key, windowSeconds)
    if (hits <= limit.limit) return true

    // `Retry-After` is the window length, not the remaining time: the remaining time would
    // tell a caller exactly when the window opened, which is one bit more than it needs.
    context.switchToHttp().getResponse<Response>().setHeader('Retry-After', windowSeconds)
    throw new AuthException(AUTH_ERROR_CODES.TOO_MANY_REQUESTS, HttpStatus.TOO_MANY_REQUESTS)
  }

  /**
   * The counter key for one caller on one route.
   *
   * Scoped per route so a burst of logins cannot exhaust the budget for password resets, and
   * keyed by the HMAC of the IP so the keyspace holds no raw client address.
   *
   * @param request - The incoming request.
   * @param context - The execution context, for the handler's name.
   * @returns The un-namespaced Redis key.
   */
  private counterKey(request: Request, context: ExecutionContext): string {
    const route = `${context.getClass().name}.${context.getHandler().name}`
    return `rl:${route}:${hmacSha256(this.clientIp(request), this.options.hmacKey)}`
  }

  /**
   * The address this request is counted against.
   *
   * `'peer'` — the default — reads the socket directly, so `X-Forwarded-For` cannot influence
   * it. `'trusted-proxy'` uses `req.ip`, which honours the app's `trust proxy` setting and the
   * forwarding headers it admits.
   *
   * The default is the strict one because the two failure modes are not symmetric: keying on
   * the peer address behind a proxy over-counts, which is visible and recoverable, while
   * trusting a header the caller controls means the limiter reports success and enforces
   * nothing. An address that cannot be read at all falls back to a constant, so those requests
   * share one bucket rather than each getting an unlimited one.
   *
   * @param request - The incoming request.
   * @returns The address to key on.
   */
  private clientIp(request: Request): string {
    if (this.options.rateLimit.clientIpSource === 'trusted-proxy') {
      return typeof request.ip === 'string' && request.ip !== '' ? request.ip : UNKNOWN_CLIENT
    }
    const peer = request.socket?.remoteAddress
    return typeof peer === 'string' && peer !== '' ? peer : UNKNOWN_CLIENT
  }
}
