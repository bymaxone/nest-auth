import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import type { Request } from 'express'

import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { AccountStatusService } from '../services/account-status.service'

/**
 * Verifies that the authenticated user's account status is not blocked.
 *
 * The decision itself lives in {@link AccountStatusService}, which resolves the status through a
 * Redis cache and applies the two refusals — a blocked status, and an unverified address where
 * `emailVerification.required` makes verification a gate on API access. This guard is the HTTP
 * adapter over it: it names the account from `request.user` and translates the outcome into a
 * `canActivate` answer.
 *
 * Sharing that service with {@link AuthTokenVerifierService} is what keeps the cache key shape,
 * the miss path and the order of the two refusals identical between a guarded route and a
 * long-lived transport, which have to reach the same verdict about the same account.
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
 *
 * @layer Guard
 */
@Injectable()
export class UserStatusGuard implements CanActivate {
  /**
   * @param accountStatus - The shared account lifecycle gate.
   */
  constructor(@Inject(AccountStatusService) private readonly accountStatus: AccountStatusService) {}

  /**
   * @param context - The Nest execution context; the request must already carry `user`.
   * @returns `true` when the account is usable, or when no user is populated.
   * @throws {@link AuthException} with the matching `ACCOUNT_*` code, `EMAIL_NOT_VERIFIED`, or
   *   `TOKEN_INVALID` when the account no longer exists.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: DashboardJwtPayload }>()
    const user = request.user

    // Public routes (no user populated) pass through.
    if (!user) return true

    await this.accountStatus.assertDashboardAccountUsable({
      userId: user.sub,
      tenantId: user.tenantId
    })

    return true
  }
}
