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
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { assertTokenType } from './utils/assert-token-type'

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
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    protected readonly jwtService: JwtService,
    protected readonly tokenDelivery: TokenDeliveryService,
    protected readonly redis: AuthRedisService,
    protected readonly reflector: Reflector,
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
      payload = this.jwtService.verify<DashboardJwtPayload>(token, {
        algorithms: [this.options.jwt.algorithm]
      })
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Require jti string — needed for revocation checks.
    if (typeof payload.jti !== 'string') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Reject platform tokens and MFA challenge tokens in dashboard context.
    assertTokenType(payload, 'dashboard')

    // Revocation check: rv:{jti} is set on logout with remaining TTL.
    const revoked = await this.redis.get(`rv:${payload.jti}`)
    if (revoked !== null) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_REVOKED)
    }

    request.user = payload
    return true
  }
}
