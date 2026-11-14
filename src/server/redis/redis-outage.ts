/**
 * @fileoverview Tells a Redis outage from a Redis error, and answers the first with a typed 503.
 *
 * Every authentication decision here awaits Redis. When the store cannot answer, the request has
 * nothing to decide with: it is refused, and what the client can act on is that the refusal is
 * temporary. The answer is `AuthException(SERVICE_UNAVAILABLE)`, whose body carries the library
 * code and nothing of the store, and whose `cause` keeps the ioredis error for a host's logger.
 *
 * @layer Service
 */

import type { Redis } from 'ioredis'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * Why Redis did not answer.
 *
 * - `timeout`: the command was sent and no reply came before `commandTimeout`, which is what a
 *   paused or partitioned server and a client that is still reconnecting both look like;
 * - `closed`: the client refused the command at once, because its connection is gone and it keeps
 *   no offline queue or has been closed;
 * - `unreachable`: the client gave up after its allowed retries, or the network said so;
 * - `unavailable`: Redis answered that it cannot serve this command right now (a replica that
 *   refuses a write after a failover, a server still loading its dataset).
 */
export type RedisOutageKind = 'timeout' | 'closed' | 'unreachable' | 'unavailable'

/**
 * The messages ioredis raises as a plain `Error`, with no `code`, taken from a real client against
 * a paused container, a stopped one, and each of the two other client configurations a host may use.
 */
const MESSAGE_KINDS: ReadonlyMap<string, RedisOutageKind> = new Map([
  ['Command timed out', 'timeout'],
  ['Connection is closed.', 'closed'],
  ["Stream isn't writeable and enableOfflineQueue options is false", 'closed']
])

/** The network errors Node reports on a failed connection, in `error.code`. */
const NETWORK_CODES: ReadonlySet<string> = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'ETIMEDOUT',
  'EPIPE',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH'
])

/**
 * The first word of a Redis error reply that means the server cannot serve the command now. A reply
 * error that is a mistake (`NOSCRIPT`, `WRONGTYPE`, `ERR ...`) is not in the list, so it stays the
 * internal failure it is.
 */
const UNAVAILABLE_REPLIES: ReadonlySet<string> = new Set([
  'READONLY',
  'LOADING',
  'MASTERDOWN',
  'CLUSTERDOWN',
  'TRYAGAIN'
])

/**
 * Classifies an error a Redis call raised.
 *
 * The one place that decides whether an error is an outage, so a message ioredis adds later is
 * added here and nowhere else.
 *
 * @param error - Whatever the call rejected with.
 * @returns The kind of outage, or `undefined` when the error is not one.
 */
export function redisOutageKindOf(error: unknown): RedisOutageKind | undefined {
  if (!(error instanceof Error)) return undefined
  if (error.name === 'MaxRetriesPerRequestError') return 'unreachable'
  if (error.name === 'ReplyError') {
    // `split` always yields a first element, so the assertion only narrows what the index lookup widens.
    return UNAVAILABLE_REPLIES.has(error.message.split(' ', 1)[0] as string)
      ? 'unavailable'
      : undefined
  }
  const { code } = error as { code?: unknown }
  if (typeof code === 'string' && NETWORK_CODES.has(code)) return 'unreachable'
  return MESSAGE_KINDS.get(error.message)
}

/**
 * Turns a Redis outage into the typed 503 and passes every other error through untouched.
 *
 * @param error - The error a Redis call rejected with.
 * @returns Never: it throws.
 * @throws {AuthException} `SERVICE_UNAVAILABLE` for an outage, with the original error as `cause`.
 * @throws The same `error` for anything else.
 */
export function rethrowAsOutage(error: unknown): never {
  if (redisOutageKindOf(error) === undefined) throw error
  throw new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE, undefined, { cause: error })
}

/**
 * Whether an error is the typed 503 this module raises.
 *
 * @param error - A caught value.
 * @returns `true` for an `AuthException` carrying `SERVICE_UNAVAILABLE`.
 */
export function isServiceUnavailable(error: unknown): error is AuthException {
  if (!(error instanceof AuthException)) return false
  const body = error.getResponse() as { error?: { code?: unknown } }
  return body.error?.code === AUTH_ERROR_CODES.SERVICE_UNAVAILABLE
}

/** Whether a call returned something to wait for: ioredis answers with a promise-like. */
function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  )
}

/**
 * A view of the client whose failed calls raise the typed 503 for an outage.
 *
 * Every method of the client is wrapped, not a list of names: a command added to the service later
 * is covered without anyone remembering to add it here. A call that does not return a promise, and
 * a property that is not a method, pass through as they are.
 *
 * @param redis - The client the host supplied.
 * @returns A proxy over it.
 */
export function mappingOutages(redis: Redis): Redis {
  return new Proxy(redis, {
    get(target, property): unknown {
      const value: unknown = Reflect.get(target, property, target)
      if (typeof value !== 'function') return value
      return (...args: unknown[]): unknown => {
        const result: unknown = Reflect.apply(value, target, args)
        return isThenable(result) ? result.then(undefined, rethrowAsOutage) : result
      }
    }
  })
}
