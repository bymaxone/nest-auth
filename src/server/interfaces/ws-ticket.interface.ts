/**
 * @fileoverview The verified-identity snapshot bound to a WebSocket upgrade ticket.
 *
 * @layer Interface
 */

/**
 * Lifetime of a WebSocket upgrade ticket, in seconds.
 *
 * Short on purpose: the ticket only has to survive the round trip between the mint call and
 * the browser opening the socket. Anything longer widens the window in which a ticket captured
 * from a URL — the one place it is unavoidably visible — is still worth replaying.
 *
 * rust-auth pins the identical value (`WS_TICKET_TTL_SECONDS`), so a ticket minted by one
 * backend and redeemed by the other over a shared Redis has the same lifetime either way.
 */
export const WS_TICKET_TTL_SECONDS = 30

/**
 * The identity a redeemed ticket authorizes a socket as.
 *
 * A snapshot, never a token: it is what the access JWT already proved at mint time, frozen for
 * the socket's lifetime. It carries no signature, no expiry of its own, and nothing that can be
 * presented back to the REST surface — a leaked snapshot buys an attacker a socket, not a
 * session.
 *
 * The field names are the wire contract shared with rust-auth
 * (`conformance/wire-contract.json`, `recordEncodings.wsTicket`): both backends read each
 * other's tickets over one Redis.
 */
export interface WsTicketSnapshot {
  /** The subject — the internal user id. */
  sub: string
  /** The tenant scope. Absent for a platform ticket. */
  tenantId?: string
  /** The user's role at mint time. */
  role: string
  /** The account status at mint time. */
  status: string
  /** Whether MFA is enabled on the account. */
  mfaEnabled: boolean
  /** Whether the originating session had already satisfied MFA. */
  mfaVerified: boolean
}
