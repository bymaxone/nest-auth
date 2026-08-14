/**
 * @fileoverview The WebSocket twin of {@link AuthExceptionFilter}.
 *
 * @layer Filter
 */
import { Catch, Logger } from '@nestjs/common'
import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The body shape every auth error serializes to, on either transport. */
interface AuthErrorEnvelope {
  error: { code: string; message: string; details: unknown }
}

/**
 * The minimum this filter needs of a connected client: a way to send it an event.
 *
 * Typed structurally rather than as `Socket`, so nothing here imports `socket.io` or
 * `@nestjs/websockets`. That is the same soft-peer discipline {@link WsJwtGuard} follows — the
 * two packages are a consumer's choice, and a filter that imported either would make them a
 * load-time requirement of every application that imports this library's barrel.
 */
interface EmittingClient {
  emit(event: string, payload: unknown): unknown
}

/** Whether a value can be sent an event. */
function isEmittingClient(client: unknown): client is EmittingClient {
  return (
    typeof client === 'object' &&
    client !== null &&
    typeof (client as { emit?: unknown }).emit === 'function'
  )
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
 * Only an `AuthException` is re-shaped. Anything else the gateway threw is re-emitted as
 * `auth.internal` with a generic message and logged here — the same rule the HTTP filter
 * follows, and for the same reason: an internal failure's own message is the one place a stack
 * detail or a connection string would reach a client.
 *
 * @example
 * ```typescript
 * @UseFilters(new WsAuthExceptionFilter())
 * @UseGuards(WsJwtGuard)
 * @WebSocketGateway()
 * export class FeedGateway { ... }
 * ```
 */
@Catch()
export class WsAuthExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(WsAuthExceptionFilter.name)

  /**
   * Emits `exception` to the client that caused it, carrying the library envelope.
   *
   * @param exception - Whatever the gateway, its guards or its pipes threw.
   * @param host - The arguments host, used to reach the connected client.
   */
  catch(exception: unknown, host: ArgumentsHost): void {
    const client: unknown = host.switchToWs().getClient()

    // A client that cannot be emitted to is not a socket this filter can answer. Returning
    // silently is the only option left — throwing here would replace a refusal the caller can
    // see with one nothing catches, inside the layer that exists to handle failures.
    if (!isEmittingClient(client)) {
      this.logger.error('unhandled exception on a client that cannot be emitted to', exception)
      return
    }

    if (exception instanceof AuthException) {
      // Its response body IS the envelope, so it travels whole — a `details` payload from the
      // validation pipe survives rather than being flattened into a message.
      client.emit('exception', { status: 'error', ...(exception.getResponse() as object) })
      return
    }

    this.logger.error('unhandled exception', exception)

    const envelope: AuthErrorEnvelope = {
      error: {
        code: AUTH_ERROR_CODES.INTERNAL,
        // The generic message, never the thrown one — same rule as the HTTP filter.
        message: 'Internal server error',
        details: null
      }
    }

    client.emit('exception', { status: 'error', ...envelope })
  }
}
