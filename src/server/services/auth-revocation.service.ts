import { Inject, Injectable } from '@nestjs/common'

import { AuthRedisService } from '../redis/auth-redis.service'
import { readStampedEpoch } from '../utils'

/**
 * The claims a revocation check reads off a verified access token. A caller passes the payload it
 * already verified; nothing here re-checks the signature.
 */
export interface RevocableTokenPayload {
  /** The token's unique id, the key of the per-token blacklist (`rv:{jti}`). */
  readonly jti: string
  /** The subject the token authenticates, the key of the per-user token epoch. */
  readonly sub: string
  /** The epoch the token was stamped with, if any; an absent or malformed value reads as 0. */
  readonly epoch?: unknown
  /**
   * The tenant the token was issued for; part of the per-user epoch key on the dashboard plane.
   *
   * Optional because the platform plane has none — its admins are cross-tenant — and the epoch
   * key derivation drops the segment there. A dashboard token always carries it: the guard
   * refuses one that does not, before this is ever read.
   */
  readonly tenantId?: string | undefined
}

/**
 * Answers whether an already-verified access token has been revoked, across both channels the auth
 * module writes to.
 *
 * There are two, and a check that consults only the first is not a revocation check. A single
 * logout writes `rv:{jti}` with the token's remaining TTL — the per-token blacklist. A password
 * reset, an MFA reset or an administrative revoke-all advances the user's token epoch — the bulk
 * channel, which invalidates every access token stamped below it in one write. Both channels this
 * service reads gate access tokens only; a refresh token is opaque and carries no epoch, so a bulk
 * flow revokes it through a separate session invalidation, not through either read here.
 *
 * `JwtAuthGuard`, `WsJwtGuard` and `JwtPlatformGuard` all consult both, and did so through three
 * separate copies of the same two Redis reads. This is that logic in one place — the guards
 * delegate to it, and it is exported so a consumer bridging `@bymax-one/nest-auth` to a realtime
 * transport can consult the same two channels rather than verifying a token's signature and
 * granting a stream that outlives every revocation. Without it, a socket that logs out keeps its
 * stream until the access token expires, while its HTTP requests are refused at once.
 *
 * @layer Service
 */
@Injectable()
export class AuthRevocationService {
  /**
   * @param redis - The auth module's Redis service, holding both revocation channels.
   */
  constructor(@Inject(AuthRedisService) private readonly redis: AuthRedisService) {}

  /**
   * Whether a verified access token has been revoked.
   *
   * @param payload - The verified token's `jti`, `sub` and stamped `epoch`.
   * @param kind - Which plane the token belongs to; selects the epoch namespace, defaulting to the
   *   dashboard plane an ordinary user token uses. The per-token blacklist is shared across planes.
   * @returns `true` when the token is on the blacklist or predates the user's current epoch.
   */
  async isAccessTokenRevoked(
    payload: RevocableTokenPayload,
    kind: 'dashboard' | 'platform' = 'dashboard'
  ): Promise<boolean> {
    if ((await this.redis.get(`rv:${payload.jti}`)) !== null) {
      return true
    }
    const epoch = await this.redis.getUserTokenEpoch(payload.sub, payload.tenantId, kind)
    return readStampedEpoch(payload) < epoch
  }
}
