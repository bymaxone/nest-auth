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
import { assertNotBlocked } from '../utils/assert-not-blocked'

@Injectable()
export class WsTicketService {
  private readonly logger = new Logger(WsTicketService.name)

  constructor(
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly userRepo: IUserRepository
  ) {}

  /**
   * Mints a ticket from an already-verified access-token payload.
   *
   * The caller is responsible for having run the authentication, status and MFA guards — the
   * payload reaching here is what those guards admitted. Nothing from the token itself is
   * copied into the ticket beyond the identity it proved: no `jti`, no expiry, nothing that
   * could be replayed against the REST surface.
   *
   * @param payload - The verified dashboard access-token payload.
   * @returns The raw ticket and how long it is valid for.
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
      this.logger.warn(`ws-ticket: refused, MFA not satisfied userId=${payload.sub}`)
      throw new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED)
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
    const user = await this.userRepo.findById(payload.sub)
    if (!user) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    assertNotBlocked(user.status, this.options.blockedStatuses)

    const snapshot: WsTicketSnapshot = {
      sub: user.id,
      tenantId: user.tenantId,
      role: user.role,
      status: user.status,
      mfaEnabled: payload.mfaEnabled,
      mfaVerified: payload.mfaVerified
    }

    const ticket = await this.redis.mintWsTicket(snapshot, WS_TICKET_TTL_SECONDS)
    this.logger.log(`ws-ticket: issued userId=${payload.sub} tenantId=${payload.tenantId}`)
    return { ticket, expiresIn: WS_TICKET_TTL_SECONDS }
  }

  /**
   * Redeems a ticket at the handshake, consuming it.
   *
   * @param ticket - The raw ticket from the upgrade request.
   * @returns The identity the socket is authorized as.
   * @throws {@link AuthException} `auth.token_invalid` when the ticket is unknown, expired or
   *   already redeemed — the three are deliberately indistinguishable to the caller.
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
    return snapshot
  }
}
