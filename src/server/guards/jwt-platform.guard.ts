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
import type { PlatformJwtPayload } from '../interfaces/jwt-payload.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { assertValidJti, assertValidSub } from './utils/assert-token-type'

/**
 * Authentication guard for platform administrator routes.
 *
 * Validates HS256-signed JWTs, enforces token type isolation (`type: 'platform'`),
 * and checks a Redis revocation list before granting access. Dashboard tokens and
 * MFA challenge tokens are explicitly rejected with `PLATFORM_AUTH_REQUIRED` to
 * distinguish a wrong-context token from a structurally invalid one.
 *
 * @remarks
 * Algorithm is pinned to the value configured in `options.jwt.algorithm` to prevent
 * algorithm-confusion attacks (CVE-2015-9235). An attacker cannot substitute
 * `alg: none` or an asymmetric algorithm to bypass signature verification.
 *
 * Unlike `JwtAuthGuard`, a wrong token type throws `PLATFORM_AUTH_REQUIRED` (HTTP 401)
 * rather than `TOKEN_INVALID`, giving the consuming application a distinct signal that
 * the caller is authenticated but used the wrong token class for this endpoint.
 *
 * Routes decorated with `@Public()` skip all JWT validation.
 *
 * @example
 * ```typescript
 * @UseGuards(JwtPlatformGuard)
 * @Get('/platform/tenants')
 * listTenants(@CurrentUser() admin: PlatformJwtPayload) { ... }
 * ```
 */
@Injectable()
export class JwtPlatformGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly tokenDelivery: TokenDeliveryService,
    private readonly redis: AuthRedisService,
    private readonly reflector: Reflector,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Public routes bypass token validation entirely.
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass()
    ])
    if (isPublic) return true

    const request = context.switchToHttp().getRequest<Request & { user?: PlatformJwtPayload }>()

    // Platform sessions are always bearer-mode — always read from the Authorization header
    // regardless of the module-level tokenDelivery config (cookie/bearer/both).
    const token = this.tokenDelivery.extractPlatformAccessToken(request)
    if (!token) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Verify signature and expiry. Algorithm is pinned from options — rejects alg:none and RS256.
    let payload: PlatformJwtPayload
    try {
      payload = this.jwtService.verify<PlatformJwtPayload>(token, {
        algorithms: [this.options.jwt.algorithm]
      })
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Require jti as a well-formed UUID v4 — the shared helper keeps this check
    // in lockstep with {@link JwtAuthGuard} so the key space is uniform across
    // platform and dashboard revocation lists.
    assertValidJti(payload.jti)

    // Require sub as a bounded non-empty string — downstream Redis keys and HMAC
    // identifiers depend on a well-formed subject. Same check as dashboard guard.
    assertValidSub(payload.sub)

    // Cannot use assertTokenType() here — we need PLATFORM_AUTH_REQUIRED, not TOKEN_INVALID,
    // so that callers can distinguish a wrong-token-context from a malformed token.
    if (payload.type !== 'platform') {
      throw new AuthException(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    }

    // Revocation check: rv:{jti} is set on logout with remaining TTL.
    const revoked = await this.redis.get(`rv:${payload.jti}`)
    if (revoked !== null) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    request.user = payload
    return true
  }
}
