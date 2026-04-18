import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext, OnModuleInit } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { assertTokenType } from './utils/assert-token-type'

/** Minimal shape of a WebSocket client as seen during the handshake. */
type WsClient = {
  handshake: { headers: Record<string, string | undefined> }
  data: Record<string, unknown>
}

/**
 * WebSocket authentication guard — the WS twin of {@link JwtAuthGuard}.
 *
 * Validates HS256-signed dashboard JWTs carried in the `Authorization` header
 * of the Socket.IO/ws handshake. Token type isolation (`type: 'dashboard'`) and
 * Redis revocation checks mirror the HTTP guard exactly.
 *
 * @remarks
 * **Header-only extraction** — query-string tokens are deliberately unsupported.
 * Tokens passed via query strings are trivially captured in server access logs,
 * browser history, and proxy caches, making them equivalent to transmitting the
 * token in plaintext. The handshake `Authorization: Bearer <token>` header is the
 * only accepted delivery channel.
 *
 * **Algorithm pinning** — `algorithms: [this.options.jwt.algorithm]` is forwarded
 * to `JwtService.verify()` to prevent algorithm-confusion attacks (CVE-2015-9235).
 * An attacker cannot substitute `alg: none` or swap to an asymmetric algorithm.
 *
 * **Soft peer-dependency on `@nestjs/websockets`** — this guard does not import
 * `@nestjs/websockets` at module load time (which would create a hard dependency
 * breaking consumers that never use WebSockets). Instead, a dynamic `import()`
 * inside `onModuleInit` throws a descriptive error if the package is absent,
 * failing fast at application startup.
 *
 * **No `@Public()` support** — the `Reflector`-based public-route bypass used by
 * {@link JwtAuthGuard} has no meaningful equivalent in WebSocket contexts where
 * every gateway handler is implicitly protected. Unauthenticated WS namespaces
 * should simply not apply this guard.
 *
 * @example
 * ```typescript
 * @UseGuards(WsJwtGuard)
 * @SubscribeMessage('message')
 * handleMessage(@ConnectedSocket() client: Socket) { ... }
 * ```
 */
@Injectable()
export class WsJwtGuard implements CanActivate, OnModuleInit {
  constructor(
    private readonly jwtService: JwtService,
    private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {}

  async onModuleInit(): Promise<void> {
    try {
      await import('@nestjs/websockets')
    } catch {
      throw new Error('WsJwtGuard requires @nestjs/websockets to be installed')
    }
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client = context.switchToWs().getClient<WsClient>()

    const authHeader = client.handshake.headers['authorization']
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined
    if (!token) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // Algorithm is pinned from options — rejects alg:none and algorithm-confusion attacks.
    let payload: DashboardJwtPayload
    try {
      payload = this.jwtService.verify<DashboardJwtPayload>(token, {
        algorithms: [this.options.jwt.algorithm]
      })
    } catch {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // jti must be a string — a missing or numeric jti cannot be used as a Redis key.
    if (typeof payload.jti !== 'string') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    assertTokenType(payload, 'dashboard')

    // rv:{jti} is written on logout with the token's remaining TTL as expiry.
    const revoked = await this.redis.get(`rv:${payload.jti}`)
    if (revoked !== null) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_REVOKED)
    }

    client.data.user = payload
    return true
  }
}
