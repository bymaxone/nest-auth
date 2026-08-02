/**
 * @fileoverview Contract for checking a password against a breach corpus.
 *
 * @layer Interface
 */

/**
 * Decides whether a password appears in a known-breach corpus.
 *
 * @remarks
 * Supply an implementation via the `BYMAX_AUTH_BREACH_CHECKER` token. The module registers
 * {@link AllowAllBreachChecker} when none is supplied, which approves every password — the
 * check is opt-in, because it is the only part of the credential path that can reach the
 * network and that is a decision a deployment has to make deliberately.
 *
 * A shipped implementation, `HibpBreachChecker`, queries Have I Been Pwned with the
 * k-anonymity range API.
 *
 * **Two rules an implementation must honor.** It must never transmit the password (the point
 * of a range query is that the corpus is searched with a prefix), and it must **fail open** —
 * a corpus that is unreachable, slow, or rate-limiting cannot be allowed to stop a user
 * changing their password, least of all during an incident when changing it is urgent.
 *
 * @example
 * ```typescript
 * class LocalListChecker implements IPasswordBreachChecker {
 *   async isBreached(password: string): Promise<boolean> {
 *     return TOP_100K.has(password)
 *   }
 * }
 * ```
 *
 * @layer Interface
 */
export interface IPasswordBreachChecker {
  /**
   * Whether the password is known to have been breached.
   *
   * @param password - The plaintext password the user is trying to set.
   * @returns `true` when the password appears in the corpus. Return `false` — never throw —
   *   when the corpus cannot be consulted.
   */
  isBreached(password: string): Promise<boolean>
}
