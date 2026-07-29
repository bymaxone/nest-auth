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

import { HttpStatus, Injectable, Logger } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'
import { WS_TICKET_TTL_SECONDS } from '../interfaces/ws-ticket.interface'
import { AuthRedisService } from '../redis/auth-redis.service'

@Injectable()
export class WsTicketService {
  private readonly logger = new Logger(WsTicketService.name)

  constructor(private readonly redis: AuthRedisService) {}

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
      throw new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED, HttpStatus.FORBIDDEN)
    }

    const snapshot: WsTicketSnapshot = {
      sub: payload.sub,
      tenantId: payload.tenantId,
      role: payload.role,
      status: payload.status,
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
