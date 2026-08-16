/**
 * Sanitizes request-derived values before they are interpolated into a log line.
 *
 * @layer Utility
 */

/**
 * Matches any character that can forge a record boundary in a line-oriented log pipeline.
 *
 * The C0 and C1 ranges, including CR, LF, NUL and the DEL byte — and `U+2028` LINE SEPARATOR and
 * `U+2029` PARAGRAPH SEPARATOR, which are neither. Those two are printable-category characters
 * that ECMAScript, JSON and any Unicode-aware consumer treat as line terminators, so a pipeline
 * that splits records on them accepts a forged one from a value this rule would otherwise have
 * called safe. A character class named for control characters is not the same as one named for
 * what breaks a line, and the second is what this guards.
 */
// eslint-disable-next-line no-control-regex -- matching control characters is the whole point
const RECORD_BREAKING_CHARACTERS = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/

/**
 * Returns `value` when it is safe to interpolate into a log line, and `'<malformed>'` otherwise.
 *
 * A log line is a record, and a value carrying a newline writes a second one. Nest's `Logger`
 * passes the message through unmodified, so an unauthenticated caller who controls any field
 * that reaches a log template — `tenantId` is the widest, since it appears on `/login`,
 * `/register`, `/verify-email`, `/password/forgot-password` and `/oauth/:provider`, all
 * `@Public()` — could write `acme\nLOG [AuthService] login: success userId=<victim>` and put a
 * fabricated successful login into the operator's SIEM, or truncate the genuine records around
 * it. ASVS v5 §16.5.1 requires log data to be sanitized against exactly this.
 *
 * The value is replaced wholesale rather than escaped: an operator reading `<malformed>` learns
 * the useful thing, which is that the field carried something no legitimate caller sends.
 * Anything printable is passed through untouched, so a tenant naming scheme this library cannot
 * anticipate still reads normally.
 *
 * The DTOs reject control characters at the boundary already. This is the second lock: a
 * `tenantIdResolver` is the host's code and returns whatever it returns, and a value that
 * reached a log line without passing a DTO would otherwise have no guard at all.
 *
 * @param value - The value about to be interpolated.
 * @returns The value, or `'<malformed>'` when it carries a character that could break a record.
 */
export function logSafe(value: string): string {
  return RECORD_BREAKING_CHARACTERS.test(value) ? '<malformed>' : value
}
