/**
 * @fileoverview The validation pipe every auth controller mounts.
 *
 * @layer Pipe
 */
import { ValidationPipe } from '@nestjs/common'
import type { ValidationError, ValidationPipeOptions } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** One rejected request field, as it serializes under `error.details`. */
export interface AuthFieldError {
  /** The offending field. Dotted path for nested objects (`address.zip`). */
  field: string
  /** Human-readable reason the field was rejected. */
  message: string
}

/**
 * Flattens class-validator's tree of errors into the flat `[{ field, message }]` list.
 *
 * Nested DTOs nest their errors, and a field can fail several constraints at once, so one
 * request field can produce several entries — each naming its own dotted path. Constraint
 * messages arrive keyed by constraint name; the values are what a caller can act on.
 *
 * @param errors - The errors class-validator produced, in its own nested shape.
 * @param parentPath - Dotted path accumulated by the recursion. Empty at the top level.
 * @returns The flattened list, in traversal order.
 */
function flattenValidationErrors(
  errors: readonly ValidationError[],
  parentPath = ''
): AuthFieldError[] {
  const flattened: AuthFieldError[] = []

  for (const error of errors) {
    const path = parentPath === '' ? error.property : `${parentPath}.${error.property}`

    for (const message of Object.values(error.constraints ?? {})) {
      flattened.push({ field: path, message })
    }

    // No emptiness check: recursing into an empty child list returns an empty list, so the guard
    // that used to be here only ever saved a call whose result was already nothing. Presence is
    // the condition that matters — `children` is optional, and reading `.length` off an absent
    // one is what this arm exists to avoid.
    if (error.children !== undefined) {
      flattened.push(...flattenValidationErrors(error.children, path))
    }
  }

  return flattened
}

/**
 * Builds the `ValidationPipe` the auth controllers mount.
 *
 * The pipe exists for one reason beyond the usual whitelisting: its `exceptionFactory`. Nest's
 * default answers a malformed body with the framework's own shape — `{ statusCode, message,
 * error }` — while every other failure in this library answers with `{ error: { code, message,
 * details } }`. A client parsing auth errors therefore needed two parsers, and the one shape it
 * could not read by `error.code` was the one that says which field to fix. Validation failures
 * now carry `auth.validation` with the per-field list under `error.details`, which is the same
 * code and the same details rust-auth emits for the same failure.
 *
 * @param options - Extra `ValidationPipe` options, merged over the defaults
 *   (`whitelist`, `forbidNonWhitelisted`). Pass `forbidUnknownValues` where a route needs it.
 * @returns A configured pipe instance, ready for `@UsePipes()`.
 */
export function createAuthValidationPipe(options: ValidationPipeOptions = {}): ValidationPipe {
  return new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    ...options,
    exceptionFactory: (errors: ValidationError[]) =>
      new AuthException(AUTH_ERROR_CODES.VALIDATION, flattenValidationErrors(errors))
  })
}
