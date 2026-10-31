/**
 * @fileoverview The clock the service-key feature reads "now" from.
 *
 * @layer Service
 */

/**
 * Source of the current instant for expiry and revocation decisions.
 *
 * Injectable so a test can stand exactly on a boundary instant, which a wall clock cannot do.
 * Supply `BYMAX_AUTH_API_KEY_CLOCK` to replace it; production hosts have no reason to.
 */
export interface ApiKeyClock {
  /** The current instant. */
  now(): Date
}

/** The system wall clock: what the module registers when the host supplies none. */
export class SystemApiKeyClock implements ApiKeyClock {
  /** @returns The current instant. */
  now(): Date {
    return new Date()
  }
}
