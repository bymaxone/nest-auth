/**
 * @fileoverview Tests for the optional exception filter.
 *
 * The filter exists so a client parsing `error.code` needs one parser rather than two. These
 * tests pin the four cases that matter: the library's own exception passes through with its
 * details intact, a response already in the envelope is left alone, any other `HttpException`
 * keeps its status but gains the envelope, and an unhandled throw answers `auth.internal` with
 * a generic message — never the thrown one.
 */

import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Logger
} from '@nestjs/common'
import type { ArgumentsHost } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthExceptionFilter } from './auth-exception.filter'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/** A response double that records the status and body the filter wrote. */
function makeHost(req: { route?: unknown } = { route: {} }): {
  host: ArgumentsHost
  status: jest.Mock
  json: jest.Mock
} {
  const json = jest.fn()
  const status = jest.fn().mockReturnValue({ json })
  const host = {
    switchToHttp: () => ({ getResponse: () => ({ status }), getRequest: () => req })
  } as unknown as ArgumentsHost
  return { host, status, json }
}

/** The envelope the filter wrote, or `undefined` when it wrote something else. */
function writtenEnvelope(json: jest.Mock): { code: string; message: string; details: unknown } {
  return (json.mock.calls[0]?.[0] as { error: { code: string; message: string; details: unknown } })
    .error
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AuthExceptionFilter', () => {
  let filter: AuthExceptionFilter

  beforeEach(() => {
    filter = new AuthExceptionFilter()
    jest.restoreAllMocks()
  })

  it('passes an AuthException through with its status and details intact', () => {
    const { host, status, json } = makeHost()

    filter.catch(
      new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, {
        retryAfterSeconds: 300
      }),
      host
    )

    expect(status).toHaveBeenCalledWith(429)
    expect(writtenEnvelope(json)).toMatchObject({
      code: AUTH_ERROR_CODES.ACCOUNT_LOCKED,
      details: { retryAfterSeconds: 300 }
    })
  })

  it('leaves a body that is already the envelope alone', () => {
    const { host, status, json } = makeHost()
    // What the module's validation pipe raises: an HttpException whose body is already ours.
    const alreadyShaped = new BadRequestException({
      error: { code: AUTH_ERROR_CODES.VALIDATION, message: 'Validation failed', details: [] }
    })

    filter.catch(alreadyShaped, host)

    expect(status).toHaveBeenCalledWith(400)
    expect(writtenEnvelope(json).code).toBe(AUTH_ERROR_CODES.VALIDATION)
  })

  it('re-shapes another HttpException while keeping the status the app chose', () => {
    const { host, status, json } = makeHost()

    filter.catch(new ForbiddenException('nope'), host)

    expect(status).toHaveBeenCalledWith(403)
    expect(writtenEnvelope(json)).toMatchObject({
      code: AUTH_ERROR_CODES.INTERNAL,
      message: 'nope',
      details: null
    })
  })

  it('re-shapes an HttpException whose body is a plain string', () => {
    const { host, status, json } = makeHost()

    filter.catch(new HttpException('plain text body', HttpStatus.BAD_GATEWAY), host)

    expect(status).toHaveBeenCalledWith(502)
    expect(writtenEnvelope(json)).toMatchObject({
      code: AUTH_ERROR_CODES.INTERNAL,
      message: 'plain text body'
    })
  })

  it('falls back to the exception message when the body is not a string', () => {
    const { host, json } = makeHost()

    filter.catch(new HttpException({ reason: 'structured' }, HttpStatus.CONFLICT), host)

    expect(writtenEnvelope(json).message.length).toBeGreaterThan(0)
  })

  // Scenario: an HttpException whose string body and whose `message` disagree. Expected: the
  // BODY wins. Why: for an exception built the ordinary way Nest keeps the two in sync, so no
  // other test here can tell which one the filter reads — and a subclass that sets its own
  // `message` (or re-throws carrying a different one) makes the choice visible. The body is what
  // the thrower chose to put on the wire.
  it('prefers a string body over the exception message when they differ', () => {
    const { host, json } = makeHost()
    const exception = new HttpException('body-on-the-wire', HttpStatus.BAD_GATEWAY)
    Object.defineProperty(exception, 'message', { value: 'internal-message' })

    filter.catch(exception, host)

    expect(writtenEnvelope(json).message).toBe('body-on-the-wire')
  })

  // Scenario: an HttpException carrying no body at all. Expected: answered, not thrown. Why: the
  // envelope check reads `body.error`, and `typeof null === 'object'` — so without the explicit
  // null arm it takes the property off `null` and the filter itself throws. A filter that throws
  // while handling an exception is the worst failure mode available to it: the request dies with
  // no envelope, no status, and a second error in the log that hides the first.
  it.each([
    ['a null body', null],
    ['an absent body', undefined]
  ])('answers an HttpException with %s instead of throwing', (_label, body) => {
    const { host, status, json } = makeHost()

    expect(() =>
      filter.catch(new HttpException(body as never, HttpStatus.BAD_GATEWAY), host)
    ).not.toThrow()

    expect(status).toHaveBeenCalledWith(502)
    expect(writtenEnvelope(json).code).toBe(AUTH_ERROR_CODES.INTERNAL)
  })

  it('answers an unhandled throw generically, and never with the thrown message', () => {
    const { host, status, json } = makeHost()
    const errorLog = jest.spyOn(filter['logger'], 'error').mockImplementation(() => undefined)

    filter.catch(new Error('connection to postgres://user:hunter2@db failed'), host)

    expect(status).toHaveBeenCalledWith(500)
    const envelope = writtenEnvelope(json)
    expect(envelope.code).toBe(AUTH_ERROR_CODES.INTERNAL)
    expect(envelope.message).toBe('Internal server error')
    // The one path where a stack detail or a connection string would otherwise reach a body.
    expect(JSON.stringify(envelope)).not.toContain('hunter2')
    // …and the cause is still recorded where an operator can read it. The message is asserted,
    // not just the call: the response deliberately says nothing about what failed, so this line
    // is the only description of the failure that exists anywhere. An empty one leaves the
    // operator with a bare stack and no statement of what the filter was doing.
    expect(errorLog).toHaveBeenCalledWith(expect.stringContaining('unhandled exception: '))
  })

  it('answers a non-Error throw the same way', () => {
    const { host, status, json } = makeHost()
    jest.spyOn(filter['logger'], 'error').mockImplementation(() => undefined)

    filter.catch('a bare string', host)

    expect(status).toHaveBeenCalledWith(500)
    expect(writtenEnvelope(json).code).toBe(AUTH_ERROR_CODES.INTERNAL)
  })

  describe('requests refused before routing', () => {
    const MALFORMED = {
      error: { code: 'auth.validation', message: 'Malformed request', details: null }
    }

    // Verifies a 400 raised before any route matched is answered generically, and that the
    // parser's text, which can quote the body, is not in the answer.
    it('answers a pre-routing BadRequestException with the generic validation envelope', () => {
      const { host, status, json } = makeHost({})

      filter.catch(new BadRequestException('Unexpected token "secret-marker"'), host)

      expect(status).toHaveBeenCalledWith(400)
      expect(json).toHaveBeenCalledWith(MALFORMED)
    })

    // Verifies the same exception raised after a route matched keeps the application's text.
    it('leaves a BadRequestException from a matched route to the application', () => {
      const { host, status, json } = makeHost({ route: { path: '/login' } })

      filter.catch(new BadRequestException('the application said no'), host)

      expect(status).toHaveBeenCalledWith(400)
      expect(writtenEnvelope(json)).toEqual({
        code: 'auth.internal',
        message: 'the application said no',
        details: null
      })
    })

    // Verifies a pre-routing exception whose body is the envelope is passed through, so
    // an application's own answer is not replaced by the generic one.
    it('passes a pre-routing envelope body through unchanged', () => {
      const { host, json } = makeHost({})
      const envelope = { error: { code: 'auth.forbidden', message: 'no', details: ['why'] } }

      filter.catch(new HttpException(envelope, HttpStatus.BAD_REQUEST), host)

      expect(json).toHaveBeenCalledWith(envelope)
    })

    // Verifies a pre-routing exception of another class is not swept in: only the 400 Nest
    // produces for a parse or decode failure is generic.
    it('does not generalise a pre-routing exception that is not a BadRequestException', () => {
      const { host, status, json } = makeHost({})

      filter.catch(new ForbiddenException('no'), host)

      expect(status).toHaveBeenCalledWith(403)
      expect(writtenEnvelope(json).code).toBe('auth.internal')
    })

    // Verifies each parser type answers its own status with the fixed message, the status taken
    // from the error and not from the type.
    it.each([
      ['entity.too.large', 413, 'Request entity too large'],
      ['charset.unsupported', 415, 'Unsupported media type'],
      ['encoding.unsupported', 415, 'Unsupported media type'],
      ['entity.verify.failed', 403, 'Malformed request'],
      ['entity.parse.failed', 400, 'Malformed request'],
      ['request.aborted', 400, 'Malformed request'],
      ['request.size.invalid', 400, 'Malformed request'],
      ['querystring.parse.rangeError', 400, 'Malformed request'],
      ['parameters.too.many', 413, 'Request entity too large']
    ])('answers a %s refusal as %i', (type, code, message) => {
      const { host, status, json } = makeHost()

      filter.catch(Object.assign(new Error('parser text'), { type, status: code }), host)

      expect(status).toHaveBeenCalledWith(code)
      expect(json).toHaveBeenCalledWith({
        error: { code: 'auth.validation', message, details: null }
      })
    })

    // Verifies a refusal whose status is not a client error, or whose type is not one the parser
    // raises, is an unhandled failure: matching on the type alone would turn a 500 into a
    // validation answer.
    it.each([
      ['a parser type with a 5xx status', { type: 'entity.too.large', status: 500 }],
      ['a parser type with no status', { type: 'entity.too.large' }],
      [
        'a parser type with a status that is not a number',
        { type: 'entity.too.large', status: '413' }
      ],
      ['a 4xx error with an unknown type', { type: 'something.else', status: 413 }],
      ['a 4xx error with no type', { status: 413 }],
      ['a parser type with a status below 400', { type: 'entity.too.large', status: 399 }],
      ['a type that is not a string', { type: 413, status: 413 }]
    ])('keeps %s as an internal failure', (_name, fields) => {
      const { host, status, json } = makeHost()
      jest.spyOn(Logger.prototype, 'error').mockImplementation()

      filter.catch(Object.assign(new Error('boom'), fields), host)

      expect(status).toHaveBeenCalledWith(500)
      expect(writtenEnvelope(json).code).toBe('auth.internal')
    })
    // Verifies the boundary of the client-error range is inclusive at 400 and 499 on the parser
    // path: a refusal at either edge is answered, not treated as an internal failure.
    it.each([400, 499])('answers a parser refusal at the edge status %i', (code) => {
      const { host, status } = makeHost()

      filter.catch(
        Object.assign(new Error('parser text'), { type: 'request.aborted', status: code }),
        host
      )

      expect(status).toHaveBeenCalledWith(code)
    })

    // Verifies a thrown value that is not an object, or is null, is an internal failure: the
    // parser check must read `type` off an object only, and a null thrown by application code
    // must not crash the filter that answers it.
    it.each([
      ['a string', 'boom'],
      ['null', null],
      ['undefined', undefined]
    ])('keeps a thrown %s as an internal failure', (_name, thrown) => {
      const { host, status, json } = makeHost()
      jest.spyOn(Logger.prototype, 'error').mockImplementation()

      filter.catch(thrown, host)

      expect(status).toHaveBeenCalledWith(500)
      expect(writtenEnvelope(json).code).toBe('auth.internal')
    })
    describe('a plain 400 from the body parser', () => {
      /** The shape `createError(400, error)` leaves on an error with no parser `type`. */
      const untyped = (fields: Record<string, unknown> = {}): Error =>
        Object.assign(new Error('incorrect header check'), {
          status: 400,
          statusCode: 400,
          expose: true,
          ...fields
        })

      // Verifies a corrupt compressed body, which the parser reports as a 400 with no `type`, is
      // answered as a malformed request when no route matched.
      it('answers the generic validation envelope before routing', () => {
        const { host, status, json } = makeHost({})

        filter.catch(untyped(), host)

        expect(status).toHaveBeenCalledWith(400)
        expect(json).toHaveBeenCalledWith({
          error: { code: 'auth.validation', message: 'Malformed request', details: null }
        })
      })

      // Verifies the same shape after a route matched is the application's own error and stays an
      // internal failure, because only the absence of a route says the parser raised it.
      it('keeps the same shape after routing as an internal failure', () => {
        const { host, status, json } = makeHost({ route: { path: '/login' } })
        jest.spyOn(Logger.prototype, 'error').mockImplementation()

        filter.catch(untyped(), host)

        expect(status).toHaveBeenCalledWith(500)
        expect(writtenEnvelope(json).code).toBe('auth.internal')
      })

      // Verifies each property of the shape is required: a 400 that is not exposed, whose two
      // status properties disagree or are another status, that carries a type the parser did not
      // raise, or that is not an Error, is not this refusal.
      it.each([
        ['not exposed', { expose: false }],
        ['exposure missing', { expose: undefined }],
        ['status 413', { status: 413, statusCode: 413 }],
        ['status 400 but statusCode 500', { statusCode: 500 }],
        ['statusCode 400 but status 500', { status: 500 }],
        ['carrying a type the parser does not raise', { type: 'something.else' }]
      ])('does not treat a 400 %s as the parser refusal', (_name, fields) => {
        const { host, status, json } = makeHost({})
        jest.spyOn(Logger.prototype, 'error').mockImplementation()

        filter.catch(untyped(fields), host)

        expect(status).toHaveBeenCalledWith(500)
        expect(writtenEnvelope(json).code).toBe('auth.internal')
      })

      it('does not treat a plain object with the same properties as the parser refusal', () => {
        const { host, status } = makeHost({})
        jest.spyOn(Logger.prototype, 'error').mockImplementation()

        filter.catch({ status: 400, statusCode: 400, expose: true }, host)

        expect(status).toHaveBeenCalledWith(500)
      })
    })
  })
})
