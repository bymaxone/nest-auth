/**
 * @fileoverview The exception filter that gives every failure the library's envelope.
 *
 * @layer Filter
 */
import { BadRequestException, Catch, HttpException, HttpStatus, Logger } from '@nestjs/common'
import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common'
import type { Request, Response } from 'express'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { describeChannelStatus } from '../utils/describe-error'

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
 * The `type` values `body-parser` and `raw-body` put on the errors they raise for a request they
 * refuse. The type is the stable part of those errors; their message text is not.
 */
const BODY_PARSER_ERROR_TYPES: ReadonlySet<string> = new Set([
  'entity.parse.failed',
  'entity.too.large',
  'entity.verify.failed',
  'charset.unsupported',
  'encoding.unsupported',
  'request.aborted',
  'request.size.invalid',
  'parameters.too.many'
])

/** The answer for a request refused before routing, when only the status can be named. */
const MALFORMED_REQUEST_MESSAGE = 'Malformed request'

/**
 * The status of a request the body parser refused, or `undefined` when `exception` is not one.
 *
 * Matches on `type` plus a 4xx `status`, taken from the error itself. A parse failure of the
 * JSON itself does not reach this function in this shape: Nest rewrites a `SyntaxError` into a
 * `BadRequestException` first, which {@link isPreRoutingBadRequest} handles.
 */
function bodyParserStatus(exception: unknown): number | undefined {
  if (typeof exception !== 'object' || exception === null) return undefined
  const { type, status } = exception as { type?: unknown; status?: unknown }
  if (typeof type !== 'string' || !BODY_PARSER_ERROR_TYPES.has(type)) return undefined
  return typeof status === 'number' && status >= 400 && status < 500 ? status : undefined
}

/** The fixed message for a body-parser refusal, by status. Never the parser's own text. */
function bodyParserMessage(status: number): string {
  if (status === HttpStatus.PAYLOAD_TOO_LARGE) return 'Request entity too large'
  if (status === HttpStatus.UNSUPPORTED_MEDIA_TYPE) return 'Unsupported media type'
  return MALFORMED_REQUEST_MESSAGE
}

/**
 * Whether `exception` is a 400 raised before any route matched.
 *
 * Nest rewrites the `SyntaxError` a malformed JSON body raises, and the `URIError` an undecodable
 * path raises, into a plain `BadRequestException` carrying the original message and nothing
 * else — so by the time it reaches a filter it cannot be told from one an application threw.
 * What does tell them apart is when it happened: Express sets `req.route` when it matches a
 * route, and the body parser and the path decoding both run before that, whereas anything thrown
 * by a handler, guard, pipe or service runs after it.
 */
function isPreRoutingBadRequest(exception: HttpException, req: Request): boolean {
  return exception instanceof BadRequestException && req.route === undefined
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
 * Requests the HTTP layer refused before any route ran — a malformed body, an oversized one, an
 * unsupported charset or content-encoding — answer `auth.validation` with a fixed message and the
 * status the transport reported, never the parser's text. Express only: the filter writes through
 * Express's `Response` and reads `req.route`, so its behaviour on another adapter is not defined.
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
    const http = host.switchToHttp()
    const res = http.getResponse<Response>()

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
      // A request refused before it reached any route: the generic answer, not the parser's text,
      // which can quote the start of the body.
      if (isPreRoutingBadRequest(exception, http.getRequest<Request>())) {
        res.status(HttpStatus.BAD_REQUEST).json({
          error: {
            code: AUTH_ERROR_CODES.VALIDATION,
            message: MALFORMED_REQUEST_MESSAGE,
            details: null
          }
        })
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

    // The body parser's own refusals (oversized body, unreadable charset or encoding) arrive as
    // raw `http-errors` objects, not as `HttpException`s: a client error that would otherwise be
    // answered as the 500 below.
    const refusedStatus = bodyParserStatus(exception)
    if (refusedStatus !== undefined) {
      res.status(refusedStatus).json({
        error: {
          code: AUTH_ERROR_CODES.VALIDATION,
          message: bodyParserMessage(refusedStatus),
          details: null
        }
      })
      return
    }

    // The single most exposed log site in this library, and the reason is stated two lines below:
    // this branch is where anything the application threw ends up. `EmailChangeService` and
    // `InvitationService` re-throw a laundered error precisely so it arrives here safe, and under
    // `onDeliveryError: 'rethrow'` a mail channel's ORIGINAL error — the one a relay may have
    // filled with a quoted body — reaches this line from any code path this library does not own.
    //
    // So nothing the thrower authored is published. `describeChannelStatus` reports the SHAPE of
    // the failure — that a throw happened, and how many links its `cause` chain has — and reads
    // neither `message` nor `name` nor the `stack`.
    //
    // The previous shape was `describeError(exception, [])`: the thrower's text, with an empty
    // list asserting there was nothing to redact. That assertion is one this filter cannot make.
    // Naming values requires knowing what the thrower held, and this branch is reached by
    // anything the surrounding application threw — including, under `onDeliveryError: 'rethrow'`,
    // a relay error quoting a live OTP. An empty list did not make the line safe; it only removed
    // the one defence that was being attempted.
    this.logger.error(`unhandled exception: ${describeChannelStatus(exception)}`)
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
