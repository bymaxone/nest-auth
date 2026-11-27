/**
 * @fileoverview The one question the readiness check asks of the store the library depends on.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import { redisOutageKindOf } from '../redis/redis-outage'
import { IntrinsicPromise } from '../utils/captured-builtins'
import { PinnedAll, awaiting, pinned } from '../utils/settle'

/**
 * How long a probe waits for the store, in milliseconds.
 *
 * Under the default per-indicator timeout of `@bymax-one/nest-core` (5000), so the probe gives up first and
 * reports the failure itself instead of being abandoned by the aggregator.
 */
export const PING_TIMEOUT_MS = 4000

/** The first word of an error reply, which is its code. A first word of any other shape is not carried. */
const REPLY_CODE = /^[A-Z]{2,32}$/

/** The code of an error reply, when the error is one and starts with a code. */
function replyCodeOf(error: unknown): string | undefined {
  if (!(error instanceof Error) || error.name !== 'ReplyError') return undefined
  // `split` always yields a first element.
  const first = error.message.split(' ', 1)[0] as string
  return REPLY_CODE.test(first) ? first : undefined
}

/**
 * What a failed `PING` is rejected with. The client's error can hold the command it failed, and the text of a reply
 * can repeat its arguments, so neither the error nor its message is carried: only the reply code or the kind of
 * outage, when the error names one.
 */
function refusalOf(error: unknown): Error {
  const reason = replyCodeOf(error) ?? redisOutageKindOf(error)
  const suffix = reason === undefined ? '' : ` (${reason})`
  return new Error(`The authentication store failed the PING${suffix}.`)
}

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
@PinnedAll()
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
   *   aggregator turns the rejection into a `down` entry. A failure of the client is rejected with the
   *   library's own error, naming at most the reply code or the kind of outage, with no `cause`.
   */
  async ping(signal?: AbortSignal): Promise<boolean> {
    const stop = AbortSignal.timeout(PING_TIMEOUT_MS)
    const bound = signal === undefined ? stop : AbortSignal.any([signal, stop])
    return (await awaiting(this.within(this.#ask(), bound))) === 'PONG'
  }

  /** The pending `PING` while it is younger than the timeout, otherwise a fresh one. */
  #ask(): Promise<string> {
    const pending = this.#pending
    // The monotonic clock: a step of the wall clock must not lengthen how long a stuck PING is shared.
    if (pending !== undefined && performance.now() - pending.at < PING_TIMEOUT_MS)
      return pending.asked
    const entry = { asked: pinned(this.#send()), at: performance.now() }
    const clear = (): void => {
      if (this.#pending === entry) this.#pending = undefined
    }
    void (async (): Promise<void> => {
      try {
        await awaiting(entry.asked)
      } catch {
        // The failure is the caller's to read; here the entry only has to be forgotten.
      } finally {
        clear()
      }
    })()
    this.#pending = entry
    return entry.asked
  }

  /** One `PING`, whose failure, thrown or rejected, is replaced by the library's own error. */
  async #send(): Promise<string> {
    try {
      return await pinned(this.redis.ping())
    } catch (error: unknown) {
      throw refusalOf(error)
    }
  }

  /** `answer`, or a rejection as soon as `signal` aborts. */
  private within(answer: Promise<string>, signal: AbortSignal): Promise<string> {
    return new IntrinsicPromise<string>((resolve, reject) => {
      const stop = (): void => reject(new Error('The authentication store did not answer in time.'))
      if (signal.aborted) return stop()
      signal.addEventListener('abort', stop, { once: true })
      void (async (): Promise<void> => {
        try {
          resolve(await awaiting(answer))
        } catch (error: unknown) {
          reject(error)
        } finally {
          signal.removeEventListener('abort', stop)
        }
      })()
    })
  }
}
