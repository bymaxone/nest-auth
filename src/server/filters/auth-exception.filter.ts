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
 * @example
 * ```typescript
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
