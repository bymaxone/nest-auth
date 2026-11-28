import { Inject, Injectable, Logger } from '@nestjs/common'

import { sessionId } from '../constants/session-id'
import { logEvent } from '../observability/log-event'
import { AuthRedisService } from '../redis/auth-redis.service'
import { readStampedEpoch } from '../utils'
import { assertRootIsStandard } from '../utils/object-prototype-guard'
import { sessionRevocationKey } from '../utils/session-access'
import { pinned, PinnedAll } from '../utils/settle'

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
   * key derivation drops the segment there. On the DASHBOARD plane it is required, and this
   * service enforces that rather than trusting it: the mounted guards do refuse a dashboard token
   * without a tenant, but this service is exported for callers that never pass through one — a
   * realtime bridge checking a socket, for instance — and an optional field in a public contract
   * is a field somebody will omit.
   */
  readonly tenantId?: string | undefined
  /**
   * The session the token belongs to, the key of the per-session entry (`rvs:{sid}`, `prvs:{sid}`).
   * A payload without a well-formed one is not checked against it, so pass the verified payload
   * whole rather than a copy of some of its claims.
   */
  readonly sid?: unknown
}

/**
 * Answers whether an already-verified access token has been revoked, across the channels the auth
 * module writes to.
 *
 * There are three, and a check that consults only some of them is not a revocation check. A
 * logout writes `rv:{jti}` with the token's remaining TTL — the per-token blacklist. Ending one
 * session (logout, eviction, a replayed refresh token, `SessionService.revokeSession`) writes
 * `rvs:{sid}`, which every access token of that session carries. A password reset, an MFA reset or
 * an administrative revoke-all advances the user's token epoch — the bulk channel, which
 * invalidates every access token stamped below it in one write. All of them gate access tokens
 * only; a refresh token is opaque, and is ended by deleting its session.
 *
 * The guards delegate to this one place, and it is exported so a consumer bridging
 * `@bymax-one/nest-auth` to a realtime transport can consult the same channels rather than
 * verifying a token's signature and granting a stream that outlives every revocation. Without it,
 * a socket that logs out keeps its stream until the access token expires, while its HTTP requests
 * are refused at once.
 *
 * @layer Service
 */
@PinnedAll()
@Injectable()
export class AuthRevocationService {
  private readonly logger = new Logger(AuthRevocationService.name)

  /**
   * @param redis - The auth module's Redis service, holding the revocation channels.
   */
  constructor(@Inject(AuthRedisService) private readonly redis: AuthRedisService) {}

  /**
   * Whether a verified access token has been revoked.
   *
   * @param payload - The verified token's `jti`, `sub`, `sid` and stamped `epoch`.
   * @param kind - Which plane the token belongs to; selects the epoch namespace, defaulting to the
   *   dashboard plane an ordinary user token uses. The per-token blacklist is shared across planes.
   * @returns `true` when the token is on the blacklist, belongs to an ended session, predates the
   *   user's current epoch, or is a dashboard payload carrying no tenant — the last fails closed
   *   without a store read, and warns.
   */
  async isAccessTokenRevoked(
    payload: RevocableTokenPayload,
    kind: 'dashboard' | 'platform' = 'dashboard'
  ): Promise<boolean> {
    assertRootIsStandard()
    // A dashboard payload without a tenant is treated as REVOKED, not as a lookup to attempt.
    //
    // Checked FIRST, before the blacklist read, because it validates the input rather than
    // consulting a channel. Behind the blacklist read it answered the same `true` — the two
    // orders are indistinguishable to a caller — but the warn below then fired only for a token
    // that happened not to be blacklisted, so a bridge calling this wrongly on every request
    // could go on doing so unheard. It also spares a round trip on a request already refused.
    //
    // The epoch key is derived from the tenant-scoped subject, and an absent tenant
    // interpolates as the literal text `undefined`, giving `dashboard:9:undefined:{userId}` — a
    // third keyspace belonging to no tenant, in
    // which nothing has ever been bumped. `getUserTokenEpoch` would answer 0, `stamped < 0` is
    // false for every token, and this method would report a bulk-revoked token as VALID. A
    // revocation check that fails open on a malformed input is worse than no check, because the
    // caller is relying on it precisely when something is wrong.
    if (kind === 'dashboard' && (payload.tenantId === undefined || payload.tenantId === '')) {
      // Warned, because failing closed is silent by construction and the caller has no other
      // signal. The refusal is indistinguishable from a genuinely revoked token: the method
      // answers the same `true`, nothing throws, and a transport that gates a stream on it
      // simply registers nothing. Measured on a consumer's realtime bridge — the caller this
      // branch was written for — it cost twenty minutes reading as a realtime bug rather than
      // an auth one, past a green type-check and a green unit suite that pinned the old shape.
      // No identifier is logged: `sub` and `jti` name an account and a live token, and this
      // says everything the operator needs without either.
      logEvent(this.logger, 'AUTH_TOKEN_REVOCATION_REFUSED', { reason: 'missing_tenant' })
      return true
    }

    if ((await pinned(this.redis.get(`rv:${payload.jti}`))) !== null) {
      return true
    }

    const sid = sessionId(payload.sid)
    if (sid !== undefined) {
      if ((await pinned(this.redis.get(sessionRevocationKey(kind, sid)))) !== null) return true
    }

    const epoch = await pinned(this.redis.getUserTokenEpoch(payload.sub, payload.tenantId, kind))
    assertRootIsStandard()
    return readStampedEpoch(payload) < epoch
  }
}
