/**
 * @fileoverview The context a password-reset token or verified token is stored with.
 *
 * @layer Utils
 */

/** Stored context for a password-reset token or verifiedToken. */
export interface ResetContext {
  userId: string
  email: string
  tenantId: string
  /**
   * A digest of the password hash this token was issued against, binding it to that password.
   *
   * Each `forgot-password` writes its own `pw_reset:` key, so several can be alive at once —
   * the 60-second cooldown against a 600-second TTL allows up to ten. Completing a reset with
   * one used to leave the others valid, which is the wrong end state precisely when it matters:
   * a victim who resets because an attacker read a link from their mailbox has not closed the
   * link the attacker read. Binding each token to the password in force when it was minted
   * means the first completed reset — or an authenticated change — invalidates every one of
   * them at once, with no per-user index to keep in step.
   *
   * Empty for an account that had no password (OAuth-only) at issue time.
   */
  passwordFingerprint: string
}
