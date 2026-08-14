/**
 * @fileoverview The exception filter that gives every failure the library's envelope.
 *
 * @layer Filter
 */
import { Catch, HttpException, HttpStatus, Logger } from '@nestjs/common'
import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common'
import type { Response } from 'express'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The body shape every auth error serializes to. */
interface AuthErrorEnvelope {
  error: { code: string; message: string; details: unknown }
}

/** Whether `body` is already the library's envelope. */
function isAuthEnvelope(body: unknown): body is AuthErrorEnvelope {
  if (typeof body !== 'object' || body === null) return false
  const error = (body as { error?: unknown }).error
  return typeof error === 'object' && error !== null && 'code' in error
}

/**
 * Gives every failure the same `{ error: { code, message, details } }` body.
 *
 * Optional, and off unless a host registers it — a library does not get to decide how an
 * application answers failures it did not raise. What it fixes when registered is that a
 * client parsing `error.code` needed a second parser for exactly the responses it can do least
 * about: an unhandled failure answers in the framework's `{ statusCode, message, error }`
 * shape, and so does any `HttpException` the surrounding application throws. rust-auth answers
 * `auth.internal` in its own envelope for the same case, so a deployment fronting both saw two
 * shapes for one condition.
 *
 * The cause is logged and never serialized: an internal failure's message is the one place a
 * stack detail or a connection string reaches a response body, so the answer carries the
 * generic code and nothing else.
 *
 * **Do not register this alongside `@bymax-one/nest-core`'s envelope filter.** They are mutually
 * exclusive in practice and this one wins: `useGlobalFilters` binds ahead of an `APP_FILTER`
 * provider, and `@Catch()` with no argument catches everything, so nest-core's filter never runs.
 * Measured on a composed application — the same request answers
 * `{error: {code, message, details}}` with this filter registered and the flat
 * `{statusCode, code, message, timestamp, path, details}` without it. A derived backend that
 * registers both therefore loses `statusCode`, `timestamp`, `path` and the correlation id, which
 * is the opposite of what registering an extra filter looks like it should do.
 *
 * Pick one. On a backend built on nest-core, take theirs: it already recognises this library's
 * envelope and passes the code, message and per-field details through unchanged.
 *
 * Nothing in this repository asserts that, and deliberately so — verifying it would mean this
 * library depending on a consumer's stack. The behaviour above was measured once and the
 * dependency removed; the standing assertion belongs to whoever composes the two.
 *
 * @example
 * ```typescript
 * // Only when nest-core's envelope filter is NOT in the application.
 * app.useGlobalFilters(new AuthExceptionFilter())
 * ```
 *
 * @layer Filter
 */
@Catch()
export class AuthExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(AuthExceptionFilter.name)

  /**
   * Writes `exception` to the response in the library envelope.
   *
   * @param exception - Whatever was thrown.
   * @param host - The arguments host, used to reach the HTTP response.
   */
  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>()

    // An AuthException already carries the envelope and the right status — pass it through
    // untouched rather than rebuilding it, so a `details` payload survives.
    //
    // Stryker disable next-line BlockStatement: emptying this branch cannot change the response.
    // AuthException extends HttpException and its body IS the envelope, so it falls into the
    // `isAuthEnvelope` arm below, which writes the same status and the same object. The branch
    // is here to say so at the top rather than to behave differently
    if (exception instanceof AuthException) {
      res.status(exception.getStatus()).json(exception.getResponse())
      return
    }

    if (exception instanceof HttpException) {
      const body = exception.getResponse()
      // A pipe or guard that already answers in the envelope (the module's validation pipe
      // does) keeps its own body.
      if (isAuthEnvelope(body)) {
        res.status(exception.getStatus()).json(body)
        return
      }
      // Anything else the surrounding application threw: keep its status, which the
      // application chose deliberately, and re-shape only the body.
      const message = typeof body === 'string' ? body : exception.message
      res.status(exception.getStatus()).json({
        error: { code: AUTH_ERROR_CODES.INTERNAL, message, details: null }
      })
      return
    }

    this.logger.error('unhandled exception', exception)
    res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      error: {
        code: AUTH_ERROR_CODES.INTERNAL,
        // The generic message, never the thrown one: this is the one path where a stack
        // detail or a connection string would otherwise reach a response body.
        message: 'Internal server error',
        details: null
      }
    })
  }
}
