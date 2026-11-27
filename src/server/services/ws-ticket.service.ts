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
 * for it. Redemption asks again what can have changed since: the expiry of that token, its
 * revocation and the account's status.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS, GUARDED_USER_REPOSITORY } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { IUserRepository } from '../interfaces/user-repository.interface'
import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'
import { WS_TICKET_TTL_SECONDS } from '../interfaces/ws-ticket.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { readStampedEpoch } from '../utils'
import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import { logEvent } from '../observability/log-event'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { checked, pinned, PinnedAll } from '../utils/settle'

/**
 * Seconds a ticket is kept short of the access token's expiry, to cover the time between reading
 * the clock and Redis applying the write.
 */
const EXPIRY_MARGIN_SECONDS = 1

@PinnedAll()
@Injectable()
export class WsTicketService {
  private readonly logger = new Logger(WsTicketService.name)

  constructor(
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(GUARDED_USER_REPOSITORY) private readonly userRepo: IUserRepository,
    @Inject(AuthRevocationService) private readonly revocation: AuthRevocationService,
    @Inject(AccountStatusService) private readonly accountStatus: AccountStatusService
  ) {}

  /**
   * Mints a ticket from an already-verified access-token payload.
   *
   * The caller is responsible for having run the authentication, status and MFA guards — the
   * payload reaching here is what those guards admitted. Nothing from the token itself is
   * copied into the ticket beyond the identity it proved, the two keys its revocation is read
   * by (`jti`, `epoch`) and its expiry: no signature, nothing that could be replayed against the
   * REST surface.
   *
   * A ticket expires no later than the access token that minted it. A logout blacklists the
   * token's `jti` only for the token's remaining life, so a ticket given longer than that would
   * outlive the entry that refuses it and redeem after its session ended. The lifetime is
   * therefore the smaller of {@link WS_TICKET_TTL_SECONDS} and the token's remaining seconds less
   * a one-second margin, and a token with none left mints nothing.
   *
   * @param payload - The verified dashboard access-token payload.
   * @returns The raw ticket and how long it is valid for, in seconds.
   * @throws {@link AuthException} `auth.token_invalid` when the token has no life left.
   */
  async issue(payload: DashboardJwtPayload): Promise<{ ticket: string; expiresIn: number }> {
    this.assertSecondFactor(payload)

    // Refused before any account read: a token with no life left mints nothing, and the lifetime
    // is measured again below, after the awaits, because that is the one that reaches Redis.
    this.lifetimeFor(payload)

    // The snapshot is read from the ACCOUNT, not from the token.
    //
    // A ticket authorizes a socket for that socket's whole lifetime — there is no per-request
    // gate behind it — so the snapshot is the last chance to describe the account correctly.
    // Copying `payload.status` did not: rotation stamps that claim empty by construction, so
    // every ticket minted from a rotated token carried no status at all, and the socket ran
    // with a blank authorization field for as long as it stayed open. Re-reading also closes
    // the window the `us:` cache leaves open on the route in front of this one, and gives the
    // socket the role and tenant the account holds now rather than the ones its login did.
    const user = await pinned(
      this.userRepo.findById({ id: payload.sub, tenantId: payload.tenantId })
    )
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
      epoch: readStampedEpoch(payload),
      exp: Math.floor(payload.exp)
    }

    // Measured last, after every await above: Redis applies the TTL from the moment it receives
    // the write, so a lifetime read before the account lookup would carry the ticket past the
    // token's expiry by the length of that lookup.
    const lifetime = this.lifetimeFor(payload)
    const ticket = await pinned(this.redis.mintWsTicket(snapshot, lifetime))
    logEvent(this.logger, 'AUTH_WS_TICKET_ISSUED', {
      userId: payload.sub,
      tenantId: payload.tenantId
    })
    return checked({ ticket, expiresIn: lifetime })
  }

  /**
   * Refuses a token whose session has not satisfied the second factor it is enrolled in.
   *
   * Applied here rather than through `MfaRequiredGuard`: that guard is only registered when MFA is
   * configured, and this endpoint has to work on deployments without it. The rule itself is the
   * guard's, unchanged.
   *
   * @param payload - The verified access-token payload.
   * @throws {@link AuthException} `auth.token_invalid` for a malformed `mfaEnabled`, and
   *   `auth.mfa_required` for an enrolled session that has not cleared its challenge.
   */
  private assertSecondFactor(payload: DashboardJwtPayload): void {
    // A malformed `mfaEnabled` is an invalid token, and an enrolled session that has not cleared
    // its challenge cannot mint a ticket that would outlive the challenge it skipped.
    if (typeof payload.mfaEnabled !== 'boolean') {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    if (payload.mfaEnabled && payload.mfaVerified !== true) {
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'mfa_not_satisfied' })
      throw new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED)
    }
  }

  /**
   * The seconds a ticket minted now may live: the smaller of {@link WS_TICKET_TTL_SECONDS} and what
   * the access token has left.
   *
   * Kept short of the token's expiry on purpose. `ceil` on the clock leaves between 0 and 1 second
   * of slack, and one further second is held back, so the ticket still ends no later than the
   * token when the write reaches Redis up to a second after this reading, at every sub-second
   * offset. An absent or non-numeric `exp` is NaN here and fails the comparison, which refuses
   * rather than mints.
   *
   * @param payload - The verified access-token payload the ticket is minted from.
   * @returns A positive whole number of seconds.
   * @throws {@link AuthException} `auth.token_invalid` when the token has no life left.
   */
  private lifetimeFor(payload: DashboardJwtPayload): number {
    const lifetime = Math.min(
      WS_TICKET_TTL_SECONDS,
      payload.exp - Math.ceil(Date.now() / 1000) - EXPIRY_MARGIN_SECONDS
    )
    if (!(lifetime > 0)) {
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'no_life_left' })
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    return lifetime
  }

  /**
   * Redeems a ticket at the handshake, consuming it, and refuses one that no longer holds.
   *
   * A socket is authenticated once and not revalidated by this library, so the minting token's
   * expiry and revocation and the account's status are all asked here. The status is read from
   * the repository for a snapshot with a tenant, not from the status cache, and from the platform
   * account for one without.
   *
   * A refusal consumes the ticket like a success does.
   *
   * @param ticket - The raw ticket from the upgrade request.
   * @param expectedTenantId - The tenant this connection belongs to. A host that calls this
   *   itself must pass it: without it a ticket of any tenant is accepted. {@link WsJwtGuard}
   *   binds the tenant on its own, under `enforceTenantBinding`.
   * @param options - `requireTenant` refuses a snapshot that names no tenant before anything is
   *   read for it. {@link WsJwtGuard} passes it, because the socket it admits is a dashboard one.
   * @returns The identity the socket is authorized as.
   * @throws {@link AuthException} `auth.token_invalid` when the ticket is unknown, already
   *   redeemed or expired, was minted by a session since revoked, names another tenant than the
   *   expected one or none where one is required, or its account is gone — deliberately
   *   indistinguishable to the caller — and the `auth.*` code of the status when the account is
   *   blocked.
   */
  async redeem(
    ticket: string,
    expectedTenantId?: string,
    options?: { requireTenant?: boolean }
  ): Promise<WsTicketSnapshot> {
    const snapshot = ticket ? await pinned(this.redis.redeemWsTicket(ticket)) : null
    if (!snapshot) {
      // Worth a line: a ticket that will not redeem is either a replay of a captured upgrade
      // URL or a client that took longer than the window to open its socket, and an operator
      // seeing a run of these is looking at one or the other.
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'unknown_or_used' })
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    // The record's own lifetime ends before the token does; this holds where another writer of
    // the keyspace, or its clock, did not keep that.
    if (snapshot.exp !== undefined && snapshot.exp * 1000 <= Date.now()) {
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'expired' })
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    if (expectedTenantId !== undefined && snapshot.tenantId !== expectedTenantId) {
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'tenant_mismatch' })
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    // No event: the caller asked for one plane.
    if (options?.requireTenant === true && !snapshot.tenantId) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    await pinned(this.assertSessionStands(snapshot))
    await pinned(this.assertAccountUsable(snapshot))
    return checked(snapshot)
  }

  /**
   * Refuses a snapshot whose minting session has been revoked, through the same two channels a
   * bearer token is held to. The platform plane is named for a snapshot with no tenant, the way
   * the epoch key itself is.
   *
   * @param snapshot - The redeemed snapshot.
   * @throws {@link AuthException} `auth.token_invalid`.
   */
  private async assertSessionStands(snapshot: WsTicketSnapshot): Promise<void> {
    const revoked = await pinned(
      this.revocation.isAccessTokenRevoked(
        {
          jti: snapshot.jti,
          sub: snapshot.sub,
          epoch: snapshot.epoch,
          tenantId: snapshot.tenantId
        },
        snapshot.tenantId === undefined ? 'platform' : 'dashboard'
      )
    )
    if (revoked) {
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'session_revoked' })
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
  }

  /**
   * Refuses a snapshot whose account is gone or blocked now.
   *
   * @param snapshot - The redeemed snapshot.
   * @throws {@link AuthException} as {@link redeem} documents.
   */
  private async assertAccountUsable(snapshot: WsTicketSnapshot): Promise<void> {
    const { sub, tenantId } = snapshot
    if (tenantId === undefined) {
      await pinned(this.accountStatus.assertPlatformAccountUsable(sub))
      return
    }
    const user = await pinned(this.userRepo.findById({ id: sub, tenantId }))
    if (!user) {
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'account_gone' })
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }
    try {
      assertNotBlocked(user.status, this.options.blockedStatuses)
    } catch (error) {
      logEvent(this.logger, 'AUTH_WS_TICKET_REFUSED', { reason: 'account_blocked' })
      throw error
    }
  }
}
