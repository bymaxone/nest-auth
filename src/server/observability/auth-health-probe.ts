/**
 * @fileoverview The one question the readiness check asks of the store the library depends on.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'

/**
 * How long a probe waits for the store, in milliseconds.
 *
 * Under the default per-indicator timeout of `@bymax-one/nest-core` (5000), so the probe gives up first and
 * reports the failure itself instead of being abandoned by the aggregator.
 */
export const PING_TIMEOUT_MS = 4000

/**
 * Asks the Redis client the module was given whether it answers.
 *
 * A `PING` writes nothing and reads nothing a caller owns, so a readiness probe costs the store one round
 * trip and no data. It lives in the main entry because the client is private to the module; the optional
 * `observability` subpath wraps it as a health indicator.
 *
 * Each probe is bounded: it gives up after {@link PING_TIMEOUT_MS} or when the caller's signal aborts,
 * whichever is first, so a stalled socket cannot hold a readiness check open. Probes that arrive while a
 * `PING` is still pending share it, so a store that never answers is asked once, not once per probe.
 */
@Injectable()
export class AuthHealthProbe {
  #pending: Promise<string> | undefined

  constructor(
    @Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: { ping(): Promise<string> }
  ) {}

  /**
   * Whether the store answers a `PING` in time.
   *
   * @param signal - Aborted when the caller stops waiting; the probe then rejects without waiting longer.
   * @returns `true` when it answers `PONG`, `false` for any other answer.
   * @throws When the store cannot be reached, does not answer in time, or the signal aborts; the health
   *   aggregator turns the rejection into a `down` entry.
   */
  async ping(signal?: AbortSignal): Promise<boolean> {
    const stop = AbortSignal.timeout(PING_TIMEOUT_MS)
    const bound = signal === undefined ? stop : AbortSignal.any([signal, stop])
    return (await this.within(this.#ask(), bound)) === 'PONG'
  }

  /** The pending `PING`, started if none is pending. */
  #ask(): Promise<string> {
    if (this.#pending === undefined) {
      const asked = this.redis.ping()
      const clear = (): void => {
        this.#pending = undefined
      }
      asked.then(clear, clear)
      this.#pending = asked
    }
    return this.#pending
  }

  /** `answer`, or a rejection as soon as `signal` aborts. */
  private within(answer: Promise<string>, signal: AbortSignal): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const stop = (): void => reject(new Error('The authentication store did not answer in time.'))
      if (signal.aborted) return stop()
      signal.addEventListener('abort', stop, { once: true })
      answer.then(resolve, reject).finally(() => signal.removeEventListener('abort', stop))
    })
  }
}
