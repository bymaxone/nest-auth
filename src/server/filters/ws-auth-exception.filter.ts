/**
 * @fileoverview The WebSocket twin of {@link AuthExceptionFilter}.
 *
 * @layer Filter
 */
import { Catch, Logger } from '@nestjs/common'
import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common'

import { AuthException } from '../errors/auth-exception'

/**
 * A Socket.IO client: dispatch is an event, and the adapter puts it on the wire.
 *
 * Typed structurally rather than as `Socket`, so nothing here imports `socket.io` or
 * `@nestjs/websockets`. That is the same soft-peer discipline {@link WsJwtGuard} follows — both
 * packages are a consumer's choice, and importing either would make it a load-time requirement
 * of every application that imports this library's barrel.
 */
interface EmittingClient {
  emit(event: string, payload: unknown): unknown
}

/**
 * A native `ws` client, as `@nestjs/platform-ws` hands it to a gateway.
 *
 * It also extends `EventEmitter`, which is the trap: `emit('exception', …)` on one of these
 * succeeds, dispatches a LOCAL event and sends nothing to the peer. Measured in the adapter —
 * it delivers with `client.send(JSON.stringify(response))` behind a `readyState` check — so a
 * filter that only emits is silently inert on this transport. Nest's own `BaseWsExceptionFilter`
 * emits unconditionally and has the same characteristic; this one does not, because
 * {@link WsJwtGuard} supports both transports and a filter that covers one of them is worse than
 * no filter at all: the guard refuses, the client is told nothing, and the deployment looks
 * configured.
 */
interface SendingClient {
  readyState: number
  send(payload: string): unknown
}

/** Whether a value can be dispatched to with an event. */
function isEmittingClient(client: unknown): client is EmittingClient {
  return (
    typeof client === 'object' &&
    client !== null &&
    typeof (client as { emit?: unknown }).emit === 'function'
  )
}

/** `WebSocket.OPEN`, inlined for the same reason the marker string is: no import. */
const WS_OPEN = 1

/** Whether a value is a native socket that must be written to rather than emitted on. */
function isSendingClient(client: unknown): client is SendingClient {
  if (typeof client !== 'object' || client === null) return false

  const candidate = client as { readyState?: unknown; send?: unknown }
  return typeof candidate.readyState === 'number' && typeof candidate.send === 'function'
}

/**
 * Gives a refused WebSocket client the library's error envelope instead of a generic failure.
 *
 * Register it on a gateway that applies {@link WsJwtGuard}. Without it, the guard's refusals do
 * not survive the transport: `AuthException` extends `HttpException`, Nest's WebSocket exception
 * layer understands only `WsException`, and everything else is delivered as
 * `{status: 'error', message: 'Internal server error'}` — so the whole `auth.*` catalogue stops
 * at the socket boundary.
 *
 * That is not only untidy. A client cannot tell a dead credential from a crashed handler, and a
 * reconnect policy has to choose: retrying an unknown error is the sensible default, so every
 * expired token becomes a reconnect loop against an endpoint that will refuse it forever. With
 * this filter the client reads `error.code` and can send the user to sign in instead.
 *
 * The payload keeps `status: 'error'` — the field Nest's own layer sets and every socket.io
 * client already branches on — and adds the envelope beside it, so a consumer handling both
 * shapes does not need a second listener:
 *
 * ```
 * without  { status: 'error', message: 'Internal server error' }
 * with     { status: 'error', error: { code: 'auth.token_invalid', message, details } }
 * ```
 *
 * **Scoped to `AuthException` on purpose.** An argument-less `@Catch()` would claim every
 * exception a gateway raises, so a `WsException` an unrelated handler throws — a domain error
 * with its own contract — would be rewritten as `auth.internal`, and following the README would
 * silently break a consumer's existing WebSocket errors. Everything that is not this library's
 * refusal keeps travelling through Nest's own exception layer.
 *
 * **Both transports.** A Socket.IO client is dispatched to with `emit`; a native `ws` client —
 * which also extends `EventEmitter`, so emitting on it succeeds and sends NOTHING — is written
 * to with `send`, in the `{event, data}` envelope `@nestjs/platform-ws` uses for every other
 * message. Both are driven over a real handshake in `test/e2e/ws-guard.e2e-spec.ts`.
 *
 * @example
 * ```typescript
 * @UseFilters(new WsAuthExceptionFilter())
 * @UseGuards(WsJwtGuard)
 * @WebSocketGateway()
 * export class FeedGateway { ... }
 * ```
 */
@Catch(AuthException)
export class WsAuthExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(WsAuthExceptionFilter.name)

  /**
   * Delivers the library envelope to the client whose request was refused.
   *
   * @param exception - The `AuthException` a guard, pipe or handler raised.
   * @param host - The arguments host, used to reach the connected client.
   */
  catch(exception: AuthException, host: ArgumentsHost): void {
    const client: unknown = host.switchToWs().getClient()

    // Its response body IS the envelope, so it travels whole — a `details` payload from the
    // validation pipe survives rather than being flattened into a message. `status: 'error'` is
    // kept beside it: the field Nest's own layer sets, and the one socket.io clients branch on.
    const payload = { status: 'error', ...(exception.getResponse() as object) }

    // Native socket first. It also satisfies the `emit` check below, and emitting on it would
    // succeed while sending nothing — the failure this order exists to prevent.
    if (isSendingClient(client)) {
      // A socket that is closing or closed cannot be told anything; the refusal still happened,
      // and there is nobody to hear it.
      if (client.readyState === WS_OPEN) {
        client.send(JSON.stringify({ event: 'exception', data: payload }))
      }
      return
    }

    if (isEmittingClient(client)) {
      client.emit('exception', payload)
      return
    }

    // Neither shape. Returning quietly is the only option left: throwing here would replace a
    // refusal the caller can see with one nothing catches, inside the layer whose job is to
    // handle failures.
    this.logger.error('refused a request on a client this filter cannot answer', exception)
  }
}
