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
    // …and the cause is still recorded where an operator can read it.
    expect(errorLog).toHaveBeenCalled()
  })

  it('answers a non-Error throw the same way', () => {
    const { host, status, json } = makeHost()
    jest.spyOn(filter['logger'], 'error').mockImplementation(() => undefined)

    filter.catch('a bare string', host)

    expect(status).toHaveBeenCalledWith(500)
    expect(writtenEnvelope(json).code).toBe(AUTH_ERROR_CODES.INTERNAL)
  })
})
