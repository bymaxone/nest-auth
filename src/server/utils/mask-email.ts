/**
 * @fileoverview Email address masking utility.
 *
 * @layer Utility
 */
import { logSafe } from './log-safe'

/**
 * Masks an email address for safe inclusion in log messages.
 *
 * Preserves the first character of the local part and the full domain so that
 * operators can identify the account without exposing the full address.
 *
 * **Masking is not the same duty as record safety, and this function owes both.** The domain is
 * copied verbatim, so `a@example.com\nforged` masked to `a***@example.com\nforged` still closes
 * the log record and opens a forged one — the address is hidden and the injection is not. The
 * addresses that reach these lines are not all DTO-validated: `profile.email` on the OAuth path
 * is whatever the provider's userinfo response contained, and `oldEmail` on the email-change path
 * is whatever the host's repository stored. Neither passed an `@IsEmail()` boundary in this
 * library. So the result goes through {@link logSafe}, which replaces it with `<malformed>`
 * rather than letting a masked address carry a newline.
 *
 * @example
 * maskEmail('john.doe@example.com') // 'j***@example.com'
 * maskEmail('a@example.com\nforged') // '<malformed>'
 *
 * @param email - Raw email address string.
 * @returns Masked email string, or `'<malformed>'` when it could break a log record.
 */
export function maskEmail(email: string): string {
  const atIndex = email.indexOf('@')
  if (atIndex <= 0) return '***'
  return logSafe(email[0] + '***@' + email.slice(atIndex + 1))
}
