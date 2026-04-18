import { Injectable } from '@nestjs/common'
import type { ExecutionContext } from '@nestjs/common'
import type { Request } from 'express'

import { JwtAuthGuard } from './jwt-auth.guard'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
/**
 * Authentication guard that allows unauthenticated access while still
 * validating the token when one is present.
 *
 * Behavior matrix:
 * - No token → `request.user = null`, returns `true` (unauthenticated access allowed).
 * - Token present but invalid (bad signature, expired, wrong type, revoked) →
 *   throws `AuthException`, identical to `JwtAuthGuard`.
 * - Token present and valid → `request.user = payload`, returns `true`.
 *
 * Use this guard on endpoints that serve different content to authenticated vs
 * anonymous visitors (e.g., a public feed that shows personalized data when logged in).
 *
 * @example
 * ```typescript
 * @UseGuards(OptionalAuthGuard)
 * @Get('/feed')
 * feed(@CurrentUser() user: DashboardJwtPayload | null) { ... }
 * ```
 */
@Injectable()
export class OptionalAuthGuard extends JwtAuthGuard {
  override async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user?: DashboardJwtPayload | null }>()

    const token = this.tokenDelivery.extractAccessToken(request)

    // No token: allow the request through as an anonymous user.
    if (!token) {
      request.user = null
      return true
    }

    // Token is present: delegate fully to JwtAuthGuard (validates, checks revocation, sets user).
    return super.canActivate(context)
  }
}
