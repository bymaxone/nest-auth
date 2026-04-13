import { AUTH_ERROR_CODES } from '../../errors/auth-error-codes'
import { AuthException } from '../../errors/auth-exception'

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
