/**
 * @fileoverview Tests for the optional exception filter.
 *
 * The filter exists so a client parsing `error.code` needs one parser rather than two. These
 * tests pin the four cases that matter: the library's own exception passes through with its
 * details intact, a response already in the envelope is left alone, any other `HttpException`
 * keeps its status but gains the envelope, and an unhandled throw answers `auth.internal` with
 * a generic message — never the thrown one.
 */

import { BadRequestException, ForbiddenException, HttpException, HttpStatus } from '@nestjs/common'
import type { ArgumentsHost } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthExceptionFilter } from './auth-exception.filter'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/** A response double that records the status and body the filter wrote. */
function makeHost(): {
  host: ArgumentsHost
  status: jest.Mock
  json: jest.Mock
} {
  const json = jest.fn()
  const status = jest.fn().mockReturnValue({ json })
  const host = {
    switchToHttp: () => ({ getResponse: () => ({ status }) })
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
      new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, HttpStatus.TOO_MANY_REQUESTS, {
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
    expect(errorLog).toHaveBeenCalledWith('unhandled exception', expect.any(Error))
  })

  it('answers a non-Error throw the same way', () => {
    const { host, status, json } = makeHost()
    jest.spyOn(filter['logger'], 'error').mockImplementation(() => undefined)

    filter.catch('a bare string', host)

    expect(status).toHaveBeenCalledWith(500)
    expect(writtenEnvelope(json).code).toBe(AUTH_ERROR_CODES.INTERNAL)
  })
})
