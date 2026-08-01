/**
 * Sanitizes request-derived values before they are interpolated into a log line.
 *
 * @layer Utility
 */

/**
 * Matches any C0 or C1 control character, including CR, LF, NUL and the DEL byte — the
 * characters that let a value forge a record boundary in a line-oriented log pipeline.
 */
// eslint-disable-next-line no-control-regex -- matching control characters is the whole point
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]/

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
 * @returns The value, or `'<malformed>'` when it carries a control character.
 */
export function logSafe(value: string): string {
  return CONTROL_CHARACTERS.test(value) ? '<malformed>' : value
}
