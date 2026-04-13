import { HttpException, HttpStatus } from '@nestjs/common'

import type { AuthErrorCode } from './auth-error-codes'
import { AUTH_ERROR_MESSAGES } from './auth-error-codes'

/**
 * Standardized exception class for the @bymax-one/nest-auth module.
 *
 * All authentication and authorization errors thrown by services and guards
 * use this class to ensure a consistent JSON response format:
 *
 * ```json
 * {
 *   "error": {
 *     "code": "auth.invalid_credentials",
 *     "message": "Email ou senha inválidos",
 *     "details": null
 *   }
 * }
 * ```
 *
 * @example
 * ```typescript
 * throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
 * throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN, HttpStatus.FORBIDDEN)
 * throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, HttpStatus.TOO_MANY_REQUESTS, {
 *   retryAfterSeconds: 300
 * })
 * ```
 */
export class AuthException extends HttpException {
  constructor(
    code: AuthErrorCode,
    statusCode: number = HttpStatus.UNAUTHORIZED,
    details?: Record<string, unknown>
  ) {
    super(
      {
        error: {
          code,

          // Runtime fallback for future/unknown codes not yet in AUTH_ERROR_MESSAGES (type cast in tests, forward-compat).
          // eslint-disable-next-line security/detect-object-injection -- code is AuthErrorCode (string literal union), not user input
          message: AUTH_ERROR_MESSAGES[code] ?? code,
          details: details ?? null
        }
      },
      statusCode
    )
  }
}
