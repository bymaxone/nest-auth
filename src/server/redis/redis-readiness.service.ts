/**
 * @fileoverview The startup check of the Redis connection every guard and flow here depends on.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'
import type { OnApplicationBootstrap } from '@nestjs/common'
import type { Redis } from 'ioredis'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'

/** How long boot keeps trying to PING Redis, in milliseconds. */
const STARTUP_PING_TIMEOUT_MS = 5000

/** The pause between two PING attempts, in milliseconds. */
const STARTUP_PING_RETRY_MS = 250

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
 * The address a client was built to reach, for the startup error.
 *
 * Only `host` and `port` are read, never a URL or the options as a whole, so a password in a
 * connection string or in `options.password` cannot reach the message. A cluster, a socket or
 * sentinel client, or a host that is not a plain name has no single address to name and the message
 * says so by omission.
 *
 * @param client - The client the host supplied.
 * @returns `host:port`, or `undefined`.
 */
function addressOf(client: unknown): string | undefined {
  const options = (
    client as { options?: { host?: unknown; port?: unknown; path?: unknown; sentinels?: unknown } }
  ).options
  // ioredis fills `host` and `port` with `localhost:6379` for EVERY client and sets `sentinels` to
  // `null` when there are none, so a socket or sentinel client would be named by an address it never
  // dialled.
  if (options?.path != null || options?.sentinels != null) return undefined
  const host = options?.host
  const port = options?.port
  if (typeof host !== 'string' || typeof port !== 'number') return undefined
  // A host that carries userinfo, a path or whitespace is not a host name; echoing it could
  // repeat a credential.
  return /^[^\s@/]+$/.test(host) ? `${host}:${port}` : undefined
}

/**
 * Pauses for a number of milliseconds.
 *
 * @param ms - The pause.
 * @returns A promise that resolves after it.
 */
function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Probes Redis at bootstrap and warns about a client that cannot bound its commands.
 *
 * Every authentication decision here awaits Redis and fails closed when ioredis rejects, but a
 * client with no command timeout and the default offline queue holds each request until ioredis
 * gives up, so an outage reads as a hang. The warning names that hazard at boot.
 *
 * The probe turns a mis-pointed address or a wrong password into a boot failure and not a
 * first-request 5xx. It keeps trying for the whole budget, because a Redis that is still starting
 * during a rolling deploy refuses its first connection, and because a client that is built to
 * connect lazily, or with the offline queue off, rejects the command that starts its connection.
 */
@Injectable()
export class RedisReadinessService implements OnApplicationBootstrap {
  private readonly logger = new Logger(RedisReadinessService.name)

  constructor(@Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis) {}

  /**
   * Waits for a client that is on its way to `ready`, and refuses one that has ended. A client in
   * any other state is left to the command, which is what starts a lazy connection.
   *
   * @param timeoutMs - The time left in the budget.
   * @throws {Error} When the client ends, or does not become ready in time.
   */
  private whenReachable(timeoutMs: number): Promise<void> {
    const { status } = this.redis
    if (status === 'end') return Promise.reject(new Error('the client is closed'))
    if (!CONNECTING_STATES.includes(status)) return Promise.resolve()
    return new Promise((resolve, reject) => {
      const settle = (done: () => void): void => {
        clearTimeout(timer)
        this.redis.off('ready', onReady)
        this.redis.off('end', onEnd)
        done()
      }
      const onReady = (): void => {
        settle(resolve)
      }
      const onEnd = (): void => {
        settle(() => {
          reject(new Error('the client gave up connecting'))
        })
      }
      const timer = setTimeout(() => {
        settle(() => {
          reject(new Error('the client did not become ready'))
        })
      }, timeoutMs)
      this.redis.once('ready', onReady)
      this.redis.once('end', onEnd)
    })
  }

  /**
   * One PING attempt: waits for the client if it is connecting, then sends the command.
   *
   * @param timeoutMs - The time left in the budget; the attempt gives up when it runs out.
   * @throws {Error} When the client is closed, the command fails or the time runs out.
   */
  private async attempt(timeoutMs: number): Promise<void> {
    let timer: NodeJS.Timeout | undefined
    const expiry = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        reject(new Error('the PING did not complete in time'))
      }, timeoutMs)
    })
    try {
      await Promise.race([this.whenReachable(timeoutMs).then(() => this.redis.ping()), expiry])
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * @throws {Error} When the client cannot PING, or Redis does not answer within the budget. The
   *   message names the address from the client's own `host` and `port` and never repeats what
   *   ioredis raised, which can quote a connection string.
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

    const budgetEnd = Date.now() + STARTUP_PING_TIMEOUT_MS
    for (;;) {
      try {
        await this.attempt(Math.max(budgetEnd - Date.now(), 1))
        return
      } catch {
        // A closed client cannot recover, and a spent budget is the end of the attempts.
        if (this.redis.status === 'end' || budgetEnd - Date.now() <= STARTUP_PING_RETRY_MS) break
        await pause(STARTUP_PING_RETRY_MS)
      }
    }

    const address = addressOf(this.redis)
    throw new Error(
      `[BymaxAuthModule] Redis${address === undefined ? '' : ` at ${address}`} did not answer PING ` +
        `within ${STARTUP_PING_TIMEOUT_MS} ms at startup. Check the address, the credentials ` +
        `and the network.`
    )
  }
}
