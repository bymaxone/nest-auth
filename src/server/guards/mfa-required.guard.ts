import { HttpStatus, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import type { Request } from 'express'

import { SKIP_MFA_KEY } from '../decorators/skip-mfa.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload, PlatformJwtPayload } from '../interfaces/jwt-payload.interface'

/**
 * Enforces MFA verification on protected routes.
 *
 * When a user has MFA enabled (`mfaEnabled === true` in the JWT), this guard
 * rejects requests unless the JWT also carries `mfaVerified: true` — a claim
 * only present in tokens issued after a successful MFA challenge.
 *
 * Routes can opt out of MFA enforcement using the `@SkipMfa()` decorator,
 * which is required on the MFA challenge endpoint itself (the user has no
 * verified JWT when submitting the challenge).
 *
 * @remarks
 * **This guard is intentionally synchronous.** All required claims (`mfaEnabled`,
 * `mfaVerified`) are read directly from the already-verified JWT payload set by
 * `JwtAuthGuard`. No I/O is performed.
 *
 * **Guard composition order:** Apply after `JwtAuthGuard` and `UserStatusGuard`
 * so that `request.user` is always populated before this guard runs:
 *
 * ```typescript
 * @UseGuards(JwtAuthGuard, UserStatusGuard, MfaRequiredGuard)
 * ```
 *
 * Unauthenticated requests (`request.user` absent) pass through — `JwtAuthGuard`
 * handles authentication enforcement.
 *
 * @example
 * ```typescript
 * // Protect a sensitive action — requires both a valid JWT and completed MFA
 * @UseGuards(JwtAuthGuard, UserStatusGuard, MfaRequiredGuard)
 * @Get('/account/settings')
 * getSettings() { ... }
 *
 * // Bypass MFA check — the user has no mfaVerified JWT yet at challenge time
 * @SkipMfa()
 * @Post('/mfa/challenge')
 * challenge(@Body() dto: MfaChallengeDto) { ... }
 * ```
 */
@Injectable()
export class MfaRequiredGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Check whether the handler or controller is decorated with @SkipMfa().
    // getAllAndOverride checks handler first, then class — handler takes precedence.
    const skipMfa = this.reflector.getAllAndOverride<boolean>(SKIP_MFA_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (skipMfa) return true

    const request = context
      .switchToHttp()
      .getRequest<Request & { user?: DashboardJwtPayload | PlatformJwtPayload }>()
    const user = request.user

    // Unauthenticated requests pass through — JwtAuthGuard handles those.
    if (!user) return true

    // Runtime type guard: reject tokens that are missing mfaEnabled entirely.
    // This prevents silent pass-through when the guard is used in a non-standard
    // composition where request.user is populated by a custom guard with a
    // different payload shape.
    if (typeof user.mfaEnabled !== 'boolean') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // If MFA is enabled on this account but the current JWT was not issued after
    // a successful MFA challenge, the request must be rejected.
    if (user.mfaEnabled === true && user.mfaVerified !== true) {
      throw new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED, HttpStatus.FORBIDDEN)
    }

    return true
  }
}
