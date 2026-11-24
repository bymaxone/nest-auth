/**
 * @fileoverview The one question the readiness check asks of the store the library depends on.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import { IntrinsicPromise } from '../utils/captured-builtins'

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
 * `PING` is still pending share it, so a store that never answers is asked once, not once per probe. A
 * `PING` that has outlived the timeout is not shared any longer: the next probe sends a fresh one, so a
 * command the client never settles cannot keep the readiness check down after the store has recovered, and
 * at most one `PING` is sent per timeout window.
 */
@Injectable()
export class AuthHealthProbe {
  #pending: { readonly asked: Promise<string>; readonly at: number } | undefined

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

  /** The pending `PING` while it is younger than the timeout, otherwise a fresh one. */
  #ask(): Promise<string> {
    const pending = this.#pending
    // The monotonic clock: a step of the wall clock must not lengthen how long a stuck PING is shared.
    if (pending !== undefined && performance.now() - pending.at < PING_TIMEOUT_MS)
      return pending.asked
    const entry = { asked: this.redis.ping(), at: performance.now() }
    const clear = (): void => {
      if (this.#pending === entry) this.#pending = undefined
    }
    entry.asked.then(clear, clear)
    this.#pending = entry
    return entry.asked
  }

  /** `answer`, or a rejection as soon as `signal` aborts. */
  private within(answer: Promise<string>, signal: AbortSignal): Promise<string> {
    return new IntrinsicPromise<string>((resolve, reject) => {
      const stop = (): void => reject(new Error('The authentication store did not answer in time.'))
      if (signal.aborted) return stop()
      signal.addEventListener('abort', stop, { once: true })
      answer.then(resolve, reject).finally(() => signal.removeEventListener('abort', stop))
    })
  }
}
