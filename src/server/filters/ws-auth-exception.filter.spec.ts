/**
 * WsAuthExceptionFilter — unit tests.
 *
 * The filter's job is one line of behaviour with three inputs: an `AuthException` (pass the
 * envelope through), anything else (a generic `auth.internal`, never the thrown message), and a
 * client that cannot be emitted to (say so in the log and stop). The transport half — that a
 * refused socket client really receives this instead of Nest's generic failure — is proven in
 * `test/e2e/ws-guard.e2e-spec.ts`, because only a real handshake can show it.
 */
import { Logger } from '@nestjs/common'
import type { ArgumentsHost } from '@nestjs/common'

import { WsAuthExceptionFilter } from './ws-auth-exception.filter'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** An `ArgumentsHost` whose WS client is `client`. */
function hostWithClient(client: unknown): ArgumentsHost {
  return {
    switchToWs: () => ({ getClient: () => client })
  } as unknown as ArgumentsHost
}

describe('WsAuthExceptionFilter', () => {
  let filter: WsAuthExceptionFilter
  let emit: jest.Mock

  beforeEach(() => {
    filter = new WsAuthExceptionFilter()
    emit = jest.fn()
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })

  // Verifies the envelope travels whole. `AuthException`'s response body IS the envelope, so
  // rebuilding it would be a second place for the shape to drift — and a `details` payload from
  // the validation pipe would be the first thing lost.
  it('passes an AuthException envelope through, beside the status field', () => {
    filter.catch(new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID), hostWithClient({ emit }))

    expect(emit).toHaveBeenCalledWith('exception', {
      status: 'error',
      error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
    })
  })

  // Verifies `status: 'error'` is kept. It is the field Nest's own layer sets and the one every
  // socket.io client already branches on, so dropping it would break the consumers who are
  // handling refusals correctly today in order to help the ones who are not.
  it('keeps the status field Nest itself would have sent', () => {
    filter.catch(new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED), hostWithClient({ emit }))

    const payload = emit.mock.calls[0]?.[1] as { status: unknown }
    expect(payload.status).toBe('error')
  })

  // Verifies anything else becomes the generic code with the generic message. The thrown
  // message is deliberately not forwarded: an internal failure's own text is the one place a
  // stack detail or a connection string would reach a client.
  it('answers an unexpected failure with auth.internal and never its message', () => {
    filter.catch(new Error('connection string: postgres://user:pw@host'), hostWithClient({ emit }))

    expect(emit).toHaveBeenCalledWith('exception', {
      status: 'error',
      error: { code: AUTH_ERROR_CODES.INTERNAL, message: 'Internal server error', details: null }
    })

    const payload = JSON.stringify(emit.mock.calls[0]?.[1])
    expect(payload).not.toContain('postgres://')
  })

  // Verifies the unexpected failure is logged. Not forwarding the message to the client only
  // works if it reaches the operator instead — otherwise the filter turns a diagnosable error
  // into silence.
  it('logs the failure it refuses to forward', () => {
    const cause = new Error('boom')

    filter.catch(cause, hostWithClient({ emit }))

    expect(Logger.prototype.error).toHaveBeenCalledWith('unhandled exception', cause)
  })

  // Verifies a client with no `emit` is handled rather than crashed on. Reaching this needs a
  // transport whose client is not an emitter, which Socket.IO never produces — the arm exists
  // because throwing here would replace a refusal the caller can see with one nothing catches,
  // inside the layer whose job is to handle failures.
  it.each([
    ['a client with no emit', {}],
    ['no client at all', null],
    ['a scalar client', 'socket']
  ])('says so in the log and stops for %s', (_why, client) => {
    expect(() => filter.catch(new Error('boom'), hostWithClient(client))).not.toThrow()

    expect(Logger.prototype.error).toHaveBeenCalledWith(
      'unhandled exception on a client that cannot be emitted to',
      expect.any(Error)
    )
  })
})
