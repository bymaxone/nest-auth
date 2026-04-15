import { HttpStatus, Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthErrorCode } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'

/**
 * Maps lowercase blocked status values to specific auth error codes.
 * Always normalize the status to lowercase before lookup.
 */
const STATUS_ERROR_MAP: Record<string, string> = {
  banned: AUTH_ERROR_CODES.ACCOUNT_BANNED,
  inactive: AUTH_ERROR_CODES.ACCOUNT_INACTIVE,
  suspended: AUTH_ERROR_CODES.ACCOUNT_SUSPENDED,
  pending: AUTH_ERROR_CODES.PENDING_APPROVAL,
  pending_approval: AUTH_ERROR_CODES.PENDING_APPROVAL
}

/**
 * Verifies that the authenticated user's account status is not blocked.
 *
 * On each request, the user's current status is resolved from a Redis cache
 * (`us:{userId}`) to avoid a database round-trip on every request. A cache miss
 * triggers a repository lookup, and the result is cached for
 * `userStatusCacheTtlSeconds` (default: 60 s).
 *
 * Status-specific errors allow the client to display the correct message:
 * - `BANNED`    → `ACCOUNT_BANNED` (403)
 * - `INACTIVE`  → `ACCOUNT_INACTIVE` (403)
 * - `SUSPENDED` → `ACCOUNT_SUSPENDED` (403)
 * - `PENDING`   → `PENDING_APPROVAL` (403)
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
 */
@Injectable()
export class UserStatusGuard implements CanActivate {
  constructor(
    private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: DashboardJwtPayload }>()
    const user = request.user

    // Public routes (no user populated) pass through.
    if (!user) return true

    const userId = user.sub
    const cacheKey = `us:${userId}`
    const cacheTtl = this.options.userStatusCacheTtlSeconds

    let status = await this.redis.get(cacheKey)

    if (status === null) {
      // Cache miss — fetch from repository and cache the result.
      const userRecord = await this.userRepo.findById(userId)
      if (!userRecord) {
        // User deleted after JWT was issued.
        throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
      }
      status = userRecord.status
      await this.redis.set(cacheKey, status, cacheTtl)
    }

    const normalizedStatus = status.toLowerCase()
    const blockedStatuses = this.options.blockedStatuses.map((s) => s.toLowerCase())
    if (blockedStatuses.includes(normalizedStatus)) {
      // eslint-disable-next-line security/detect-object-injection -- normalizedStatus is lowercased DB value
      const errorCode = (STATUS_ERROR_MAP[normalizedStatus] ??
        AUTH_ERROR_CODES.ACCOUNT_INACTIVE) as AuthErrorCode
      throw new AuthException(errorCode, HttpStatus.FORBIDDEN)
    }

    return true
  }
}
