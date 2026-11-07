/**
 * @fileoverview Refuses a request whose body is declared compressed, whatever the host's body
 * parser would have done with it.
 *
 * @layer Guard
 */
import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import type { Request } from 'express'

import { REQUEST_ENCODING_KEY } from '../decorators/request-encoding.decorator'
import type { RequestEncodingPolicy } from '../decorators/request-encoding.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

/**
 * Methods whose routes take no body: a path-only or query-only route is never checked.
 */
const BODYLESS_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'DELETE'])

/** The message of the refusal; the shared wire contract carries the same text. */
const UNSUPPORTED_MEDIA_TYPE_MESSAGE = 'Unsupported media type'

/**
 * Answers `415` for a request carrying a `Content-Encoding` other than `identity`.
 *
 * @remarks
 * Whether a compressed request body is decompressed is the host's body parser's decision, not the
 * library's: Express's default inflates `gzip`, `deflate` and `br`, a host that sets
 * `inflate: false` refuses them, and a framework that does not decode accepts nothing. The
 * contract the library shares with its sibling is the stricter one, and a library that relies on
 * host configuration for it holds that contract only where the host happened to set it. So the
 * refusal is made here, before any handler.
 *
 * Auth payloads are a few hundred bytes and browsers do not compress request bodies, so nothing
 * legitimate is lost. The parser has already decompressed the body by the time a guard runs, and
 * its size limit counts decompressed bytes, so the work this guard declines to do is bounded by
 * that limit either way; the refusal is for the contract, with the parser-level `inflate: false`
 * refusing earlier on a host that sets it.
 *
 * The answer is an `HttpException` whose body already is the library's error envelope. The
 * optional `AuthExceptionFilter` passes such a body through untouched and, without it, Nest
 * serialises the same object, so the response is identical either way. It is not an
 * `AuthException` because the status of `auth.validation` in the error catalog is `400`, one
 * status per code.
 */
@Injectable()
export class RequestEncodingGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  /**
   * @param context - The execution context of the request.
   * @returns `true` when the route does not check, the request declares no encoding or only
   *   `identity`, or the route checks only requests with a body and this one has none.
   * @throws {@link HttpException} `415` in the `auth.validation` envelope otherwise.
   */
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>()
    if (BODYLESS_METHODS.has(request.method)) return true

    const policy = this.reflector.get<RequestEncodingPolicy | undefined>(
      REQUEST_ENCODING_KEY,
      context.getHandler()
    )
    if (policy === 'unchecked') return true

    const header = request.headers['content-encoding']
    if (header === undefined) return true

    const encodings = header
      .split(',')
      .map((encoding) => encoding.trim().toLowerCase())
      .filter((encoding) => encoding.length > 0)
    if (encodings.every((encoding) => encoding === 'identity')) return true

    if (policy === 'when-body' && !carriesBody(request)) return true

    throw new HttpException(
      {
        error: {
          code: AUTH_ERROR_CODES.VALIDATION,
          message: UNSUPPORTED_MEDIA_TYPE_MESSAGE,
          details: null
        }
      },
      HttpStatus.UNSUPPORTED_MEDIA_TYPE
    )
  }
}

/** Whether the request declares a body: a non-zero length, or a chunked transfer. */
function carriesBody(request: Request): boolean {
  const length = request.headers['content-length']
  return (
    request.headers['transfer-encoding'] !== undefined || (length !== undefined && length !== '0')
  )
}
