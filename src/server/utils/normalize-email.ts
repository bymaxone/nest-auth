/**
 * @fileoverview Email address normalization utility.
 *
 * @layer Utility
 */

/**
 * Normalizes an email address to its canonical form: trimmed and lowercased.
 *
 * This is the single source of truth for how the server derives a canonical
 * email. It MUST run at the service boundary (not only via the DTO `@Transform`)
 * because the library's controllers use `ValidationPipe` without `transform: true`,
 * so class-transformer's `@Transform` output is discarded and the handler receives
 * the raw request body. Deriving the brute-force lockout key, the user lookup, and
 * the stored identity from this canonical value is what closes the case-rotation
 * lockout bypass — where an attacker rotates the email letter-case so each casing is
 * a distinct lockout bucket yet resolves the same account.
 *
 * @example
 * normalizeEmail('  USER@Example.COM  ') // 'user@example.com'
 *
 * @param email - Raw email address string.
 * @returns The trimmed, lowercased email.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}
