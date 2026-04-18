import { AUTH_ERROR_CODES } from '../../errors/auth-error-codes'
import { AuthException } from '../../errors/auth-exception'

/**
 * RFC 4122 UUID v4 pattern.
 *
 * The auth library always issues `jti` claims via `crypto.randomUUID()`, which
 * produces UUID v4 strings. Enforcing the exact shape at the guard boundary
 * prevents a signed-but-malformed token (e.g. one whose `jti` contains colons,
 * slashes, or other characters) from being used to build unexpected Redis key
 * patterns downstream (`rv:${jti}`, `sess:${jti}`, etc.).
 */
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

/**
 * Asserts that a JWT payload carries the expected `type` claim.
 *
 * Centralises token-type validation so that {@link JwtAuthGuard} and
 * {@link JwtPlatformGuard} do not duplicate the same conditional check. A mismatch
 * means a token issued for one authentication context (e.g. `'platform'`) was
 * presented to a guard that expects another (e.g. `'dashboard'`), which is a
 * sign of token misuse or a programming error in the consuming application.
 *
 * @param payload - Decoded JWT payload (only `type` is inspected).
 * @param expectedType - The literal type string the guard accepts.
 * @throws {@link AuthException} with `TOKEN_INVALID` (HTTP 401) when the types
 *   do not match or when `payload.type` is absent.
 */
export function assertTokenType(payload: { type?: string }, expectedType: string): void {
  if (payload.type !== expectedType) {
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
}

/**
 * Asserts that a JWT `jti` claim is a well-formed UUID v4 string.
 *
 * Both {@link JwtAuthGuard} and {@link JwtPlatformGuard} derive Redis key names
 * (`rv:${jti}`) from this value. Rejecting malformed shapes at the boundary
 * keeps the key space uniform and prevents key-shape injection via a forged
 * or misconfigured signer that emits a non-UUID `jti`.
 *
 * @param jti - The raw value of the `jti` claim from the decoded payload.
 * @throws {@link AuthException} with `TOKEN_INVALID` (HTTP 401) when the value
 *   is not a string or does not match the UUID v4 shape.
 */
export function assertValidJti(jti: unknown): asserts jti is string {
  if (typeof jti !== 'string' || !UUID_V4_RE.test(jti)) {
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
}

/**
 * Upper bound for the `sub` (subject) claim length.
 *
 * The `sub` value is used directly as the user-identifier component of
 * several Redis keys (`us:${sub}`, `sess:${sub}`, and downstream HMAC
 * inputs). A pathologically long subject (e.g. from a custom user-id
 * format that accidentally concatenated metadata) would bloat key sizes
 * and Redis memory without offering any legitimate value. 256 characters
 * comfortably accommodates UUIDs, ULIDs, numeric IDs, and composite
 * `tenant:user` strings while rejecting the obvious-abuse shapes.
 */
const MAX_SUBJECT_LENGTH = 256

/**
 * Asserts that a JWT `sub` (subject) claim is a non-empty string within
 * the configured upper bound.
 *
 * Unlike `jti`, `sub` does not have a single canonical format (UUID,
 * ULID, database ID, composite tenant/user strings are all common), so
 * the guard is intentionally permissive on content but strict on shape.
 * Rejecting empty strings, non-strings, and pathological lengths prevents
 * the `sub` value from producing degenerate Redis key patterns.
 *
 * @param sub - The raw value of the `sub` claim from the decoded payload.
 * @throws {@link AuthException} with `TOKEN_INVALID` (HTTP 401) when the
 *   value is not a string, is empty, or exceeds {@link MAX_SUBJECT_LENGTH}.
 */
export function assertValidSub(sub: unknown): asserts sub is string {
  if (typeof sub !== 'string' || sub.length === 0 || sub.length > MAX_SUBJECT_LENGTH) {
    throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
  }
}
