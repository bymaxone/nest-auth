/**
 * @fileoverview The startup checks of the Redis client every guard and flow here depends on.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'
import type { OnApplicationBootstrap } from '@nestjs/common'
import type { Redis } from 'ioredis'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import { IntrinsicPromise } from '../utils/captured-builtins'
import { awaiting, withDeadline } from '../utils/settle'

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
 * Refuses a client built with a `keyPrefix`. ioredis prefixes the keys a command declares, not the
 * ones a Lua script builds from its arguments, so the scripts that end sessions would miss them.
 *
 * A standalone client carries the option in `options.keyPrefix`, and a cluster copies the one of
 * its node options there. The test is the truthiness ioredis applies the prefix on.
 *
 * @param client - The client the host supplied.
 * @throws {Error} When the client has a key prefix.
 */
function refuseKeyPrefix(client: unknown): void {
  const options = (client as { options?: { keyPrefix?: unknown } }).options
  if (!options?.keyPrefix) return
  throw new Error(
    '[BymaxAuthModule] BYMAX_AUTH_REDIS_CLIENT has a keyPrefix, which ioredis does not apply ' +
      'to the keys a Lua script builds, so revoking every session would leave refresh tokens ' +
      'working. Remove keyPrefix from the client and set the redisNamespace option instead.'
  )
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
  // Only characters a host name or an address literal is made of: anything else (userinfo, a path,
  // a query, whitespace) is not a host, and echoing it could repeat a credential.
  if (!/^[A-Za-z0-9._:%-]+$/.test(host)) return undefined
  // An IPv6 literal is bracketed, so the port is not read as part of the address.
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`
}

/**
 * Pauses for a number of milliseconds.
 *
 * @param ms - The pause.
 * @returns A promise that resolves after it.
 */
function pause(ms: number): Promise<void> {
  return new IntrinsicPromise((resolve) => setTimeout(resolve, ms))
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

  constructor(@Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis) {
    refuseKeyPrefix(redis)
  }

  /**
   * Waits for a client that is on its way to `ready`, and refuses one that has ended. A client in
   * any other state is left to the command, which is what starts a lazy connection.
   *
   * @param timeoutMs - The time left in the budget.
   * @throws {Error} When the client ends, or does not become ready in time.
   */
  private whenReachable(timeoutMs: number): Promise<void> {
    const { status } = this.redis
    if (status === 'end') {
      return new IntrinsicPromise<void>((_resolve, reject) => {
        reject(new Error())
      })
    }
    if (!CONNECTING_STATES.includes(status)) {
      return new IntrinsicPromise<void>((resolve) => {
        resolve()
      })
    }
    return new IntrinsicPromise((resolve, reject) => {
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
          // Stryker disable next-line StringLiteral: equivalent. The text of this rejection is never read: the retry loop discards the reason and the final error is built from the client's address.
          reject(new Error('the client gave up connecting'))
        })
      }
      const timer = setTimeout(() => {
        // Stryker disable next-line BlockStatement: equivalent. The attempt's own deadline rejects at the same instant for the same reason, so the `reject` below adds nothing; what this branch adds is the cleanup `settle` does (listeners removed, which the specs count on a real emitter), and that call is not disabled.
        settle(() => {
          // Stryker disable next-line CallExpression,StringLiteral: equivalent. Same reason as above, and the text is never read (the retry loop discards it).
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
    const { value } = await awaiting(
      withDeadline(async () => {
        await this.whenReachable(timeoutMs)
        await this.redis.ping()
      }, timeoutMs)
    )
    // Reading the box throws the reason of a PING that failed or did not finish in time.
    void value
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
