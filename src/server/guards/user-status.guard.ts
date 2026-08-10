import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'

/**
 * Verifies that the authenticated user's account status is not blocked.
 *
 * On each request, the user's current status is resolved from a Redis cache
 * (`us:{tenantId}:{userId}`) to avoid a database round-trip on every request. A cache
 * miss triggers a tenant-scoped repository lookup, and the result is cached for
 * `userStatusCacheTtlSeconds` (default: 60 s). The tenant is part of the key because a
 * repository id is unique only within a tenant.
 *
 * Status-specific errors allow the client to display the correct message:
 * - `BANNED`    → `ACCOUNT_BANNED` (403)
 * - `INACTIVE`  → `ACCOUNT_INACTIVE` (403)
 * - `SUSPENDED` → `ACCOUNT_SUSPENDED` (403)
 * - `PENDING`   → `PENDING_APPROVAL` (403)
 *
 * When `emailVerification.required` is enabled (the default), this guard also
 * refuses an account whose email is not yet verified, with `EMAIL_NOT_VERIFIED`.
 * This is what makes verification a gate on API access and not only on `login`:
 * registration issues a session before verification, and without this check that
 * session would reach every route this guard protects for the access token's
 * lifetime. The verified flag is cached alongside the status under
 * `uev:{tenantId}:{userId}`, on the same miss and the same TTL, so the check costs no
 * extra round-trip.
 *
 * Routes without an authenticated user (`request.user` absent) are passed
 * through — this guard is designed to be composed after {@link JwtAuthGuard}.
 *
 * @example
 * ```typescript
 * @UseGuards(JwtAuthGuard, UserStatusGuard)
 * @Get('/dashboard')
 * dashboard() { ... }
 * ```
 *
 * @layer Guard
 */
@Injectable()
export class UserStatusGuard implements CanActivate {
  constructor(
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: DashboardJwtPayload }>()
    const user = request.user

    // Public routes (no user populated) pass through.
    if (!user) return true

    const userId = user.sub
    const tenantId = user.tenantId
    // Keys and the repository read are tenant-scoped. A repository id is only unique WITHIN a
    // tenant, so a status or verified flag cached under a bare id could authorize a colliding id in
    // another tenant; the JWT's own `tenantId` binds every cache entry and the miss-path lookup to
    // the caller's tenant.
    const statusKey = `us:${tenantId}:${userId}`
    const verifiedKey = `uev:${tenantId}:${userId}`
    const cacheTtl = this.options.userStatusCacheTtlSeconds
    const requireVerified = this.options.emailVerification.required

    let status = await this.redis.get(statusKey)
    // Only consulted when verification is enforced; left null otherwise so the cost is a single
    // `get` for the common case.
    let verified = requireVerified ? await this.redis.get(verifiedKey) : null

    if (status === null || (requireVerified && verified === null)) {
      // A miss on either fact resolves both from one repository read, scoped to the JWT's tenant.
      const userRecord = await this.userRepo.findById(userId, tenantId)
      if (!userRecord) {
        // User deleted after JWT was issued.
        throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      }
      status = userRecord.status
      await this.redis.set(statusKey, status, cacheTtl)
      if (requireVerified) {
        verified = userRecord.emailVerified ? '1' : '0'
        await this.redis.set(verifiedKey, verified, cacheTtl)
      }
    }

    // Passed as stored, not normalized here: `assertNotBlocked` canonicalizes both sides itself,
    // so a fold applied first was doing the same work twice and claiming the case rule lived in
    // two places at once.
    //
    // One definition, in `assertNotBlocked`. This guard used to carry its own copy of the
    // status → error-code table as a plain object literal, which the sibling implementation
    // deliberately does NOT use: the status is application-defined data, so an object lookup
    // resolves INHERITED keys, and a configured status of `constructor` or `toString` would
    // yield a truthy prototype member that defeats the `??` fallback and reaches `AuthException`
    // as a non-code value. The copy had drifted past that reasoning, which is the failure mode
    // duplicated logic has whether or not the drift is reachable — here it needed a consumer to
    // configure one of those names as a blocked status, so the outcome was a malformed 403 body
    // rather than a bypass. Deleting the copy removes the question.
    assertNotBlocked(status, this.options.blockedStatuses)

    // Email verification is a gate on API access, not only on `login`. Registration mints a
    // session before the address is verified; without this check that session would reach every
    // route the guard protects while `emailVerified` is still false. A blocked status is refused
    // first, so a banned account is told it is banned rather than that it must verify.
    if (requireVerified && verified === '0') {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    }

    return true
  }
}
