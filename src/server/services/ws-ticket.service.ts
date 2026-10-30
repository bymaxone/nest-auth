/**
 * @fileoverview Single-use WebSocket upgrade tickets.
 *
 * The browser `WebSocket` API cannot set handshake headers, so a browser client has no way to
 * present `Authorization: Bearer <token>` at the upgrade. The usual workaround — the access
 * token in the query string — writes a long-lived credential into access logs, browser history
 * and proxy caches. {@link WsJwtGuard} refuses it for exactly that reason, which left browser
 * clients with no supported path at all.
 *
 * A ticket is the other answer: opaque, single-use, ~30 seconds, and worth nothing once
 * redeemed. It is minted only from a session that is already authenticated, in good standing
 * and MFA-satisfied, so the ticket can never carry more authority than the session that asked
 * for it.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'
import { WS_TICKET_TTL_SECONDS } from '../interfaces/ws-ticket.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { readStampedEpoch } from '../utils'
import { AuthRevocationService } from './auth-revocation.service'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { logSafe } from '../utils/log-safe'

@Injectable()
export class WsTicketService {
  private readonly logger = new Logger(WsTicketService.name)

  constructor(
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(AuthRevocationService) private readonly revocation: AuthRevocationService
  ) {}

  /**
   * Mints a ticket from an already-verified access-token payload.
   *
   * The caller is responsible for having run the authentication, status and MFA guards — the
   * payload reaching here is what those guards admitted. Nothing from the token itself is
   * copied into the ticket beyond the identity it proved and the two keys its revocation is read
   * by (`jti`, `epoch`): no expiry, no signature, nothing that could be replayed against the REST
   * surface.
   *
   * A ticket expires no later than the access token that minted it. A logout blacklists the
   * token's `jti` only for the token's remaining life, so a ticket given longer than that would
   * outlive the entry that refuses it and redeem after its session ended. The lifetime is
   * therefore the smaller of {@link WS_TICKET_TTL_SECONDS} and the token's remaining seconds,
   * rounded down so the ticket never outlasts the token, and a token with none left mints nothing.
   *
   * @param payload - The verified dashboard access-token payload.
   * @returns The raw ticket and how long it is valid for, in seconds.
   * @throws {@link AuthException} `auth.token_invalid` when the token has no life left.
   */
  async issue(payload: DashboardJwtPayload): Promise<{ ticket: string; expiresIn: number }> {
    // The second-factor rule, applied here rather than through `MfaRequiredGuard`: that guard
    // is only registered when MFA is configured, and this endpoint has to work on deployments
    // without it. The rule itself is the guard's, unchanged — a malformed `mfaEnabled` is an
    // invalid token, and an enrolled session that has not cleared its challenge cannot mint a
    // ticket that would outlive the challenge it skipped.
    if (typeof payload.mfaEnabled !== 'boolean') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    if (payload.mfaEnabled && payload.mfaVerified !== true) {
      this.logger.warn(`ws-ticket: refused, MFA not satisfied userId=${logSafe(payload.sub)}`)
      throw new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED)
    }

    // Rounded so the remainder can only be short of the real one: `ceil` on the clock leaves the
    // ticket at most as long-lived as the token, never a fraction of a second longer. An absent or
    // non-numeric `exp` is NaN here and fails the comparison, which refuses rather than mints.
    const lifetime = Math.min(WS_TICKET_TTL_SECONDS, payload.exp - Math.ceil(Date.now() / 1000))
    if (!(lifetime > 0)) {
      this.logger.warn(`ws-ticket: refused, token has no life left userId=${logSafe(payload.sub)}`)
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // The snapshot is read from the ACCOUNT, not from the token.
    //
    // A ticket authorizes a socket for that socket's whole lifetime — there is no per-request
    // gate behind it — so the snapshot is the last chance to describe the account correctly.
    // Copying `payload.status` did not: rotation stamps that claim empty by construction, so
    // every ticket minted from a rotated token carried no status at all, and the socket ran
    // with a blank authorization field for as long as it stayed open. Re-reading also closes
    // the window the `us:` cache leaves open on the route in front of this one, and gives the
    // socket the role and tenant the account holds now rather than the ones its login did.
    const user = await this.userRepo.findById({ id: payload.sub, tenantId: payload.tenantId })
    if (!user) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    assertNotBlocked(user.status, this.options.blockedStatuses)

    const snapshot: WsTicketSnapshot = {
      sub: user.id,
      tenantId: user.tenantId,
      role: user.role,
      status: user.status,
      mfaEnabled: payload.mfaEnabled,
      mfaVerified: payload.mfaVerified,
      jti: payload.jti,
      epoch: readStampedEpoch(payload)
    }

    const ticket = await this.redis.mintWsTicket(snapshot, lifetime)
    this.logger.log(
      `ws-ticket: issued userId=${logSafe(payload.sub)} tenantId=${logSafe(payload.tenantId)}`
    )
    return { ticket, expiresIn: lifetime }
  }

  /**
   * Redeems a ticket at the handshake, consuming it.
   *
   * @param ticket - The raw ticket from the upgrade request.
   * @returns The identity the socket is authorized as.
   * @throws {@link AuthException} `auth.token_invalid` when the ticket is unknown, expired,
   *   already redeemed, or minted by a session that has since been revoked — a logout or a bulk
   *   revocation between the mint and the upgrade. These are deliberately indistinguishable to the
   *   caller.
   */
  async redeem(ticket: string): Promise<WsTicketSnapshot> {
    const snapshot = ticket ? await this.redis.redeemWsTicket(ticket) : null
    if (!snapshot) {
      // Worth a line: a ticket that will not redeem is either a replay of a captured upgrade
      // URL or a client that took longer than the window to open its socket, and an operator
      // seeing a run of these is looking at one or the other.
      this.logger.warn('ws-ticket: redemption refused — unknown, expired, or already used')
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    // The ticket outlives the request that minted it, and the socket it opens is authenticated
    // once and never revalidated, so the session behind it is checked here against the same two
    // channels a bearer token is. The platform plane is named for a snapshot with no tenant, the way
    // the epoch key itself is.
    const revoked = await this.revocation.isAccessTokenRevoked(
      { jti: snapshot.jti, sub: snapshot.sub, epoch: snapshot.epoch, tenantId: snapshot.tenantId },
      snapshot.tenantId === undefined ? 'platform' : 'dashboard'
    )
    if (revoked) {
      this.logger.warn('ws-ticket: redemption refused — the session that minted it was revoked')
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    return snapshot
  }
}
