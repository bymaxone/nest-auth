/**
 * The charset constraint shared by every request field that reaches a log line.
 *
 * @layer DTO
 */

/**
 * Matches a string containing no C0 or C1 control character — no CR, LF, NUL or DEL.
 *
 * `tenantId` is bounded in length and validated as a non-empty string, but nothing constrained
 * its charset, and it reaches the logger verbatim on `/login`, `/register`, `/verify-email`,
 * `/password/forgot-password` and `/oauth/:provider` — all `@Public()`. A value of
 * `acme\nLOG [AuthService] login: success userId=<victim>` therefore wrote a second, fabricated
 * record into the operator's SIEM, and could truncate the genuine ones around it. ASVS v5
 * §16.5.1 requires log data to be sanitized against exactly this.
 *
 * The constraint is deliberately permissive: anything printable passes, so a tenant naming
 * scheme this library cannot anticipate is unaffected. Only the characters that forge a record
 * boundary are refused, and they are refused at the boundary rather than escaped downstream —
 * a value carrying a newline is not a tenant identifier any legitimate caller sends.
 *
 * The interpolation sites additionally pass through `logSafe`, because a `tenantIdResolver` is
 * the host's code and never passes through a DTO at all.
 */
// eslint-disable-next-line no-control-regex -- refusing control characters is the whole point
export const NO_CONTROL_CHARACTERS = /^[^\u0000-\u001F\u007F-\u009F]+$/
