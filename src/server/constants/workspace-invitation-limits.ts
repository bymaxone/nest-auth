/**
 * @fileoverview The limits on issuing workspace invitations, held identical to
 * `conformance/wire-contract.json`.
 *
 * @layer Constants
 */

/** Seconds an address must wait between two tokens issued for it. */
export const RESEND_COOLDOWN_SECONDS = 60

/** How many times one invitation may be resent. */
export const MAX_RESENDS = 5

/** How many invitations one member may issue in an hour. */
export const INVITATIONS_PER_INVITER_PER_HOUR = 20

/** The window of that limit, in seconds. */
export const INVITER_WINDOW_SECONDS = 3_600
