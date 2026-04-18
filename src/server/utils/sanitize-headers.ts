/**
 * HTTP header sanitization utility for @bymax-one/nest-auth.
 *
 * Removes sensitive headers before they are included in a HookContext
 * or any audit/log output. Two complementary strategies are applied:
 *  1. Explicit blocklist — exact-match on known sensitive header names.
 *  2. Pattern match   — regex catch-all for custom secret-bearing headers.
 *
 * All output keys are normalized to lowercase for consistent downstream handling.
 */

/**
 * Exact-match blocklist of known sensitive header names (lowercase).
 * Add new entries here when additional built-in sensitive headers are identified.
 */
const BLOCKED_HEADERS = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  'www-authenticate',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-session-id'
])

/**
 * Pattern to detect custom sensitive headers by suffix.
 * Catches headers such as:
 *   x-refresh-token, x-access-token, x-client-secret,
 *   x-service-key, x-api-password, x-service-credential,
 *   x-service-auth, x-webhook-signature, x-hub-signature, x-service-hmac
 */
const SENSITIVE_HEADER_PATTERN =
  /^x-.*-(token|secret|key|password|credential|auth|bearer|signature|hmac)$/i

/**
 * Sanitizes HTTP request headers by removing sensitive values and normalizing
 * keys to lowercase.
 *
 * Uses a fail-safe blocklist approach so that newly introduced sensitive headers
 * do not leak automatically. Output keys are always lowercase regardless of the
 * casing in the input — this prevents blocklist bypass via mixed-case header names
 * and ensures consistent access in downstream hook implementations.
 *
 * @remarks
 * Two complementary strategies are applied:
 * 1. **Blocklist** — exact-match on known sensitive header names (case-insensitive input).
 * 2. **Pattern match** — regex catch-all for `x-*-(token|secret|key|password|credential)`.
 *
 * @param headers - HTTP request headers from the Express `req.headers` object.
 * @returns A new object with sensitive headers removed and all keys lowercased.
 *   The original object is never mutated.
 *
 * @example
 * ```typescript
 * const safe = sanitizeHeaders({
 *   Authorization: 'Bearer secret',
 *   'Content-Type': 'application/json',
 *   'x-request-id': 'abc-123',
 * })
 * // safe => { 'content-type': 'application/json', 'x-request-id': 'abc-123' }
 * ```
 */
export function sanitizeHeaders(
  headers: Record<string, string | string[] | undefined>
): Record<string, string | string[] | undefined> {
  return Object.fromEntries(
    Object.entries(headers)
      .map(([key, value]) => [key.toLowerCase(), value] as const)
      .filter(([key]) => !BLOCKED_HEADERS.has(key) && !SENSITIVE_HEADER_PATTERN.test(key))
  )
}

/**
 * Returns a well-formed `HookContext` carrying the minimum required fields
 * (`ip`, `userAgent`, `sanitizedHeaders`) populated with empty defaults.
 *
 * Used for fire-and-forget hook invocations that are triggered from code paths
 * without access to a live `Request` object (e.g. internal service calls,
 * email-verification confirmations). Consumers reading `context.ip` in a hook
 * implementation receive `''` rather than `undefined` — a documented contract
 * rather than a runtime surprise.
 */
export function createEmptyHookContext(): {
  ip: string
  userAgent: string
  sanitizedHeaders: Record<string, string | string[] | undefined>
} {
  return { ip: '', userAgent: '', sanitizedHeaders: {} }
}
