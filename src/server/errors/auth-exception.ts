/**
 * @fileoverview Domain exception class for all authentication-layer errors.
 *
 * @layer Error
 */
import { HttpException, HttpStatus } from '@nestjs/common'

import type { AuthErrorCode } from './auth-error-codes'
import { AUTH_ERROR_MESSAGES, AUTH_ERROR_STATUS } from './auth-error-codes'

/**
 * Own-property views of the two catalogs, built once at module load.
 *
 * `Map`s rather than indexing the exported object literals, for the reason
 * `assert-not-blocked.ts` documents about its own table: a plain-object lookup walks the
 * prototype chain, so a code of `'constructor'` or `'toString'` resolves a truthy inherited
 * member. That defeats a `?? fallback` — the message lookup here used to answer with
 * `Object` itself — and would put a function where the HTTP status belongs. A `Map` has no
 * prototype chain to walk, and `get` is not a computed member access, so neither line needs
 * to silence `security/detect-object-injection`.
 *
 * The exported tables stay plain objects: they are the documented public surface and are
 * asserted against `conformance/wire-contract.json`. Only the lookup is hardened.
 */
const MESSAGE_BY_CODE: ReadonlyMap<string, string> = new Map(Object.entries(AUTH_ERROR_MESSAGES))
const STATUS_BY_CODE: ReadonlyMap<string, number> = new Map(Object.entries(AUTH_ERROR_STATUS))

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
 *     "message": "Invalid email or password",
 *     "details": null
 *   }
 * }
 * ```
 *
 * The HTTP status is NOT a parameter — it is derived from the code via
 * {@link AUTH_ERROR_STATUS}. There is no way to answer one code with two statuses, which is
 * what a defaulted status argument allowed: thirteen codes drifted from the status rust-auth
 * answers for the same code, and five answered differently at different throw sites, none of
 * it visible to the type system, the linter, or either library's suite. Pass a `details`
 * payload where the failure carries one; the status follows the code.
 *
 * @example
 * ```typescript
 * throw new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
 * throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN)
 * throw new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, { retryAfterSeconds: 300 })
 * ```
 */
export class AuthException extends HttpException {
  /**
   * @param code - Stable machine-readable error code from `AUTH_ERROR_CODES`. Determines both
   *   the default message and the HTTP status.
   * @param details - Optional structured payload attached to the error body under
   *   `error.details`. An array where the failure is a list — `auth.validation` renders its
   *   per-field failures that way, matching what rust-auth serializes for the same code.
   */
  constructor(code: AuthErrorCode, details?: Record<string, unknown> | readonly unknown[]) {
    super(
      {
        error: {
          code,

          // Runtime fallback for future/unknown codes not yet in AUTH_ERROR_MESSAGES (type cast in tests, forward-compat).
          message: MESSAGE_BY_CODE.get(code) ?? code,
          details: details ?? null
        }
      },

      // A code with no entry is a programming error on the throwing side, not something the
      // caller did — 500 says so, and says it with a number rather than the `undefined` an
      // unguarded lookup used to hand to Express.
      STATUS_BY_CODE.get(code) ?? HttpStatus.INTERNAL_SERVER_ERROR
    )
  }
}
