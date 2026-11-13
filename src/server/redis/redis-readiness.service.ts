/**
 * @fileoverview The startup check of the Redis connection every guard and flow here depends on.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'
import type { OnApplicationBootstrap } from '@nestjs/common'
import type { Redis } from 'ioredis'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'

/** How long boot waits for Redis to answer a PING, in milliseconds. */
const STARTUP_PING_TIMEOUT_MS = 5000

/** The states in which an ioredis client is on its way to `ready` without a command to start it. */
const CONNECTING_STATES: readonly string[] = ['connecting', 'connect', 'reconnecting']

/**
 * The command timeout of an ioredis client, `undefined` when it has none.
 *
 * A standalone client carries it in `options.commandTimeout` and a cluster in
 * `options.redisOptions.commandTimeout`. Only a number is a deadline: ioredis arms the timer for a
 * command when `typeof commandTimeout === 'number'`, so a string leaves every command unbounded.
 *
 * @param client - The client the host supplied.
 * @returns The timeout in milliseconds, or `undefined`.
 */
function commandTimeoutOf(client: unknown): number | undefined {
  const options = (client as { options?: unknown }).options
  if (typeof options !== 'object' || options === null) return undefined
  const own = (options as { commandTimeout?: unknown }).commandTimeout
  const nested = (options as { redisOptions?: { commandTimeout?: unknown } }).redisOptions
    ?.commandTimeout
  const found = typeof own === 'number' ? own : nested
  return typeof found === 'number' ? found : undefined
}

/**
 * Probes Redis once at bootstrap and warns about a client that cannot bound its commands.
 *
 * Every authentication decision here awaits Redis and fails closed when ioredis rejects, but a
 * client with no command timeout and the default offline queue holds each request until ioredis
 * gives up, so an outage reads as a hang. The warning names that hazard at boot. The probe
 * refuses to start against a Redis that cannot be reached at all, which turns a mis-pointed
 * address or a wrong password into a boot failure and not a first-request 5xx.
 */
@Injectable()
export class RedisReadinessService implements OnApplicationBootstrap {
  private readonly logger = new Logger(RedisReadinessService.name)

  constructor(@Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis) {}

  /**
   * Waits for a client that is still connecting to become ready, and refuses one that has given up. A client built with the offline
   * queue off refuses a command until then, and the connection is normally a moment behind the
   * module; a client that has not started (`lazyConnect`) is left to connect on the PING.
   */
  private whenReachable(): Promise<void> {
    const { status } = this.redis
    if (status === 'end') return Promise.reject(new Error('the client is closed'))
    if (!CONNECTING_STATES.includes(status)) return Promise.resolve()
    return new Promise((resolve, reject) => {
      const onReady = (): void => {
        this.redis.off('end', onEnd)
        resolve()
      }
      const onEnd = (): void => {
        this.redis.off('ready', onReady)
        reject(new Error('the client gave up connecting'))
      }
      this.redis.once('ready', onReady)
      this.redis.once('end', onEnd)
    })
  }

  /**
   * @throws {Error} When the client cannot PING, or Redis does not answer within the deadline. The
   *   message never carries the error ioredis raised, which can quote the host and port.
   */
  async onApplicationBootstrap(): Promise<void> {
    if (commandTimeoutOf(this.redis) === undefined) {
      this.logger.warn(
        'The Redis client has no commandTimeout, so a slow or unreachable Redis holds each ' +
          'request until ioredis gives up. Set commandTimeout, a small maxRetriesPerRequest and ' +
          'a bounded retryStrategy on the client you provide as BYMAX_AUTH_REDIS_CLIENT.'
      )
    }

    if (typeof this.redis.ping !== 'function') {
      throw new Error('[BymaxAuthModule] BYMAX_AUTH_REDIS_CLIENT must be an ioredis client.')
    }

    let timer: NodeJS.Timeout | undefined
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        reject(
          new Error(
            `[BymaxAuthModule] Redis did not answer PING within ${STARTUP_PING_TIMEOUT_MS} ms at startup.`
          )
        )
      }, STARTUP_PING_TIMEOUT_MS)
    })
    try {
      await Promise.race([this.whenReachable().then(() => this.redis.ping()), deadline])
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('[BymaxAuthModule]')) throw error
      throw new Error(
        '[BymaxAuthModule] Redis did not answer PING at startup: the connection was refused or ' +
          'the command failed. Check the address, the credentials and the network.'
      )
    } finally {
      clearTimeout(timer)
    }
  }
}
