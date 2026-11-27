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

import { Logger } from '@nestjs/common'
import type { Redis } from 'ioredis'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { logEvent } from '../observability/log-event'
import type { StoreOperation } from '../observability/log-event'
import { assertRootIsStandard } from '../utils/object-prototype-guard'
import { checked, markHandled, pinned } from '../utils/settle'

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
export const NETWORK_CODES: ReadonlySet<string> = new Set([
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
export const UNAVAILABLE_REPLIES: ReadonlySet<string> = new Set([
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

const logger = new Logger('AuthRedisService')

/**
 * The store a refused command was for: the key family of the first key it names (`redis:rl`,
 * `redis:ep`). Nothing else of the key is read into the answer.
 */
function storeOf(
  command: PropertyKey,
  args: readonly unknown[],
  namespace: string
): StoreOperation {
  // `eval` names its keys after the script and their count.
  const key = command === 'eval' ? args[2] : args[0]
  const prefix = `${namespace}:`
  if (typeof key !== 'string' || !key.startsWith(prefix)) return 'redis'
  const family = /^[a-z_]+(?=:)/.exec(key.slice(prefix.length))?.[0]
  return family === undefined ? 'redis' : `redis:${family}`
}

/**
 * Answers a command Redis refused as a mistake with `auth.internal`. The error ioredis raises carries
 * the command it failed, keys and values included, so it is not kept as the cause and nothing but its
 * class is logged.
 */
function refuseReply(operation: StoreOperation): never {
  logEvent(logger, 'AUTH_STORE_FAILED', { operation, detail: 'ReplyError' })
  throw new AuthException(AUTH_ERROR_CODES.INTERNAL)
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
 * Waits for a call of the client and raises the typed 503 when it failed for an outage, and `auth.internal` when Redis refused
 * the command. It waits with `await`, not through `then` of the promise it was given: every answer of the store passes here,
 * so a replaced `then` would answer for all of them.
 */
async function mappingOutage(
  result: PromiseLike<unknown>,
  store: () => StoreOperation
): Promise<unknown> {
  try {
    assertRootIsStandard()
    const answer = await pinned(result)
    // The answer is read for `then` when this function returns it, so the root is checked again as the last statement.
    return checked(answer)
  } catch (error: unknown) {
    const refused = error instanceof Error && error.name === 'ReplyError'
    if (refused && redisOutageKindOf(error) === undefined) return refuseReply(store())
    return rethrowAsOutage(error)
  }
}

/**
 * A view of the client whose failed calls raise the typed 503 for an outage, and `auth.internal`
 * for a command Redis refused.
 *
 * Every method of the client is wrapped, not a list of names: a command added to the service later
 * is covered without anyone remembering to add it here. A call that does not return a promise, and
 * a property that is not a method, pass through as they are.
 *
 * @param redis - The client the host supplied.
 * @param namespace - The prefix of every key the library names, which a refused command's store is read after.
 * @returns A proxy over it.
 */
export function mappingOutages(redis: Redis, namespace: string): Redis {
  return new Proxy(redis, {
    get(target, property): unknown {
      const value: unknown = Reflect.get(target, property, target)
      if (typeof value !== 'function') return value
      return (...args: unknown[]): unknown => {
        const result: unknown = Reflect.apply(value, target, args)
        // Before `isThenable` reads `then`: that read can throw, and a rejection with no handler ends the process.
        markHandled(result)
        return isThenable(result)
          ? mappingOutage(result, () => storeOf(property, args, namespace))
          : result
      }
    }
  })
}
