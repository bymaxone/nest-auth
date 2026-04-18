/**
 * Masks an email address for safe inclusion in log messages.
 *
 * Preserves the first character of the local part and the full domain so that
 * operators can identify the account without exposing the full address.
 *
 * @example
 * maskEmail('john.doe@example.com') // 'j***@example.com'
 *
 * @param email - Raw email address string.
 * @returns Masked email string.
 */
export function maskEmail(email: string): string {
  const atIndex = email.indexOf('@')
  if (atIndex <= 0) return '***'
  return email[0] + '***@' + email.slice(atIndex + 1)
}
