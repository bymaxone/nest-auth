import type { AuthErrorCode } from '../constants/error-codes'

/**
 * Discriminated error-code type carried by `AuthErrorResponse` and
 * `AuthClientError`.
 *
 * Narrows to a known {@link AuthErrorCode} whenever the server emits an
 * `AuthException`; falls back to an arbitrary `string` when the response
 * comes from a non-auth NestJS exception (e.g. a `ValidationPipe` 400)
 * that still ships a `code` field. Consumers can branch exhaustively on
 * `AuthErrorCode` values and treat the `string` arm as the escape hatch.
 */
export type AuthResponseCode = AuthErrorCode | (string & {})

/**
 * Shape of the error response body returned by the @bymax-one/nest-auth server.
 *
 * @remarks
 * Mirrors the JSON body emitted by `AuthException` after NestJS's exception
 * filter serializes it. The `code` field uses the `auth.<domain>_<action>`
 * convention defined by `AUTH_ERROR_CODES` and is the recommended branch
 * point for client-side error handling — `message` is meant for end-user
 * display and may be localized in the future.
 */
export interface AuthErrorResponse {
  /** End-user-facing message (may be localized server-side in future versions). */
  message: string

  /** HTTP status text (NestJS convention, e.g. `'Unauthorized'`). */
  error: string

  /** HTTP status code (e.g. `401`, `403`). */
  statusCode: number

  /**
   * Stable machine-readable error code from `AUTH_ERROR_CODES`
   * (e.g. `'auth.invalid_credentials'`).
   *
   * Optional because a NestJS-level exception thrown outside the auth flow
   * (e.g. a `ValidationPipe` 400) may not carry it.
   */
  code?: AuthResponseCode
}

/**
 * Error thrown by the auth client when an HTTP response is not 2xx.
 *
 * @remarks
 * Carries the parsed error body alongside the HTTP status so consumers can
 * branch on a stable `code` (preferred) or fall back to `status` for generic
 * cases. Defined as a class (not a plain interface) so `instanceof` checks
 * work in user code.
 */
export class AuthClientError extends Error {
  /** The HTTP status code returned by the server. */
  readonly status: number

  /**
   * The stable machine-readable error code from `AUTH_ERROR_CODES`,
   * when the server provided one.
   */
  readonly code: AuthResponseCode | undefined

  /** The full parsed error body, if the response carried JSON. */
  readonly body: AuthErrorResponse | undefined

  constructor(message: string, status: number, body?: AuthErrorResponse) {
    super(message)
    this.name = 'AuthClientError'
    this.status = status
    this.code = body?.code
    this.body = body
  }

  /**
   * Strips potentially sensitive request echoes from structured-logger output.
   *
   * Some servers reflect submitted DTO fields inside `ValidationPipe` 400
   * responses; without this override, `JSON.stringify(error)` would persist
   * those fields verbatim into application logs. The serialized form keeps
   * only the fields a log consumer actually needs to triage an auth failure.
   */
  toJSON(): {
    name: string
    message: string
    status: number
    code: AuthResponseCode | undefined
  } {
    return {
      name: this.name,
      message: this.message,
      status: this.status,
      code: this.code
    }
  }
}
