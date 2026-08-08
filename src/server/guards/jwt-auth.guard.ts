import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { IS_PUBLIC_KEY } from '../decorators/public.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { AuthRevocationService } from '../services/auth-revocation.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { verifyWithRotation } from '../utils/verify-with-rotation'
import { assertTokenType, assertValidJti, assertValidSub } from './utils/assert-token-type'

/**
 * Primary authentication guard for dashboard (tenant) routes.
 *
 * Validates HS256-signed JWTs, enforces token type isolation (`type: 'dashboard'`),
 * and checks a Redis revocation list before granting access. Platform tokens and
 * MFA challenge tokens are explicitly rejected.
 *
 * @remarks
 * Algorithm is pinned to `HS256` in the `verify()` call to prevent algorithm-
 * confusion attacks (CVE-2015-9235). An attacker cannot substitute `alg: none`
 * or an asymmetric algorithm to bypass signature verification.
 *
 * Routes decorated with `@Public()` skip all JWT validation.
 *
 * @example
 * ```typescript
 * @UseGuards(JwtAuthGuard)
 * @Get('/profile')
 * profile(@CurrentUser() user: DashboardJwtPayload) { ... }
 * ```
 *
 * @layer Guard
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    @Inject(JwtService) protected readonly jwtService: JwtService,
    @Inject(TokenDeliveryService) protected readonly tokenDelivery: TokenDeliveryService,
    @Inject(AuthRevocationService) protected readonly revocation: AuthRevocationService,
    @Inject(Reflector) protected readonly reflector: Reflector,
    @Inject(BYMAX_AUTH_OPTIONS) protected readonly options: ResolvedOptions
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Public routes bypass token validation entirely.
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass()
    ])
    if (isPublic) return true

    const request = context.switchToHttp().getRequest<Request & { user?: DashboardJwtPayload }>()

    const token = this.tokenDelivery.extractAccessToken(request)
    if (!token) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Verify signature and expiry. Algorithm is pinned from options — rejects alg:none and RS256.
    let payload: DashboardJwtPayload
    try {
      payload = verifyWithRotation<DashboardJwtPayload>(this.jwtService, this.options, token)
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Require jti as a well-formed UUID v4 — used for revocation checks (`rv:{jti}`)
    // and session tracking. Rejecting malformed shapes keeps the Redis key space
    // uniform and matches the symmetric check performed by JwtPlatformGuard.
    assertValidJti(payload.jti)

    // Require sub as a bounded non-empty string — used downstream in Redis keys
    // (`us:{sub}`, `sess:{sub}`) and HMAC-identifier pre-images. Rejecting empty
    // and pathological shapes keeps the key space well-formed.
    assertValidSub(payload.sub)

    // Reject platform tokens and MFA challenge tokens in dashboard context.
    assertTokenType(payload, 'dashboard')

    // Both revocation channels, in one place: the per-token blacklist a logout writes and the
    // per-user epoch a password reset or revoke-all advances. Surfaced as TOKEN_INVALID rather
    // than a distinct revoked code — letting a caller tell "valid but logged out" from "never
    // valid" is a small, unnecessary oracle. `sub` and `jti` were asserted well-formed above, so
    // the keys built from them are uniform.
    if (await this.revocation.isAccessTokenRevoked(payload)) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    request.user = payload
    return true
  }
}
