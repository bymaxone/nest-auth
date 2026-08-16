/**
 * WsAuthExceptionFilter — unit tests.
 *
 * Two transports and one payload. What only a real handshake can show — that a refused client
 * actually receives this instead of Nest's generic failure — is in
 * `test/e2e/ws-guard.e2e-spec.ts`, over both a Socket.IO gateway and a native `ws` one.
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

  beforeEach(() => {
    filter = new WsAuthExceptionFilter()
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })

  describe('a Socket.IO client', () => {
    // Verifies the envelope travels whole. `AuthException`'s response body IS the envelope, so
    // rebuilding it would be a second place for the shape to drift — and a `details` payload
    // from the validation pipe would be the first thing lost.
    it('receives the envelope beside the status field', () => {
      const emit = jest.fn()

      filter.catch(new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID), hostWithClient({ emit }))

      expect(emit).toHaveBeenCalledWith('exception', {
        status: 'error',
        error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
      })
    })

    // Verifies `status: 'error'` survives. It is the field Nest's own layer sets and the one
    // every socket.io client already branches on, so dropping it would break the consumers who
    // handle refusals correctly today in order to help the ones who do not.
    it('keeps the status field Nest itself would have sent', () => {
      const emit = jest.fn()

      filter.catch(new AuthException(AUTH_ERROR_CODES.MFA_REQUIRED), hostWithClient({ emit }))

      expect((emit.mock.calls[0]?.[1] as { status: unknown }).status).toBe('error')
    })
  })

  describe('a native ws client', () => {
    // The trap this branch exists for: a native `ws` socket also extends `EventEmitter`, so
    // `emit` succeeds on it — and dispatches a LOCAL event that never reaches the peer.
    // `@nestjs/platform-ws` delivers with `send(JSON.stringify(...))`, so that is what this must
    // do, and the ORDER of the two checks is what makes it work.
    it('is written to rather than emitted on', () => {
      const send = jest.fn()
      const emit = jest.fn()

      filter.catch(
        new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID),
        hostWithClient({ readyState: 1, send, emit })
      )

      expect(emit).not.toHaveBeenCalled()
      expect(send).toHaveBeenCalledTimes(1)

      const frame = JSON.parse(send.mock.calls[0]?.[0] as string) as {
        event: string
        data: { status: string; error: { code: string } }
      }

      // The `{event, data}` envelope the adapter uses for every other message, so a client
      // parsing frames the normal way finds this one where it looks for the others.
      expect(frame.event).toBe('exception')
      expect(frame.data.status).toBe('error')
      expect(frame.data.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // Half a native socket is not one. Both fields have to be present for the `send` path to be
    // the right one, and a Socket.IO client that happens to expose either name alone must still
    // be emitted to — reading the two as an alternative would write the refusal into a client
    // that cannot be written to, which delivers it to nobody at all.
    // The first case is not hypothetical — it is the Socket.IO client. `Socket.send()` is the
    // documented alias for `emit('message')`, and `readyState` lives on the Engine.IO transport
    // beneath it, so every Socket.IO refusal is a half-match. Reading the two as an alternative
    // would send them all down the `send` path, where the `readyState` check finds `undefined`
    // and delivers the refusal to nobody. Each case fails differently and neither fails quietly:
    // with no `readyState` the filter returns having written nothing, and with no `send` it calls
    // a function that is not there.
    it.each([
      ['a send with no readyState, the Socket.IO shape', { send: jest.fn() }],
      ['a readyState with no send', { readyState: 1 }]
    ])('is emitted to, not written to, for %s', (_why, half) => {
      const emit = jest.fn()

      filter.catch(
        new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID),
        hostWithClient({ ...half, emit })
      )

      expect(emit).toHaveBeenCalledWith('exception', {
        status: 'error',
        error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
      })
    })

    // A socket that is closing or closed cannot be told anything. The refusal still happened;
    // there is simply nobody to hear it, and writing to a closed socket throws.
    it.each([
      ['connecting', 0],
      ['closing', 2],
      ['closed', 3]
    ])('is not written to while %s', (_state, readyState) => {
      const send = jest.fn()

      filter.catch(
        new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID),
        hostWithClient({ readyState, send })
      )

      expect(send).not.toHaveBeenCalled()
    })
  })

  // Verifies a client that is neither shape is handled rather than crashed on. Reaching it needs
  // a transport whose client is neither an emitter nor a socket, which neither supported adapter
  // produces — the arm exists because throwing here would replace a refusal the caller can see
  // with one nothing catches, inside the layer whose job is to handle failures.
  it.each([
    ['a client with neither emit nor send', {}],
    ['no client at all', null],
    ['a scalar client', 'socket']
  ])('says so in the log and stops for %s', (_why, client) => {
    const exception = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)

    expect(() => filter.catch(exception, hostWithClient(client))).not.toThrow()

    expect(Logger.prototype.error).toHaveBeenCalledWith(
      'refused a request on a client this filter cannot answer: <error>'
    )
  })
})
