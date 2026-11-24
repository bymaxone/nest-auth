/**
 * @fileoverview Waiting for several calls, and for a deadline, without reading a static of `Promise` and without letting a planted
 * `then` answer for the value.
 *
 * `Promise.all` and `Promise.race` are properties of a global that anything running in the process can replace after the library
 * loaded, and a replaced one decides what a read of a repository answered: a membership the store never returned, a profile the
 * plugin never fetched, the order in which sessions are evicted. The root guard does not compare them, because the monitors and
 * the test doubles of a host wrap them and the library has no way to tell those from an attack. So no decision of the library goes
 * through one. These helpers wait with `await` alone, which reads `Promise.prototype.constructor` and nothing else, and that is the
 * one property of `Promise` the baseline compares.
 *
 * Two more things close what that leaves. The root guard runs synchronously immediately before every `await` here, with no call a
 * host could replace in between, so a constructor replaced and put back by a `then` it installed is refused when it is in place at
 * the `await`, and a `then` planted on a prototype a value inherits from is refused before the value is handed to one. And the
 * answer travels in a box with no prototype: resolving a promise with an object asks it for `then`, and an object that inherits
 * from the root would be asked of whatever was planted there. The caller reads `.value`.
 *
 * Not covered: a `then` planted and erased again between the check and the resolution, by code that runs in that gap.
 *
 * @layer Utility
 */

import { types } from 'node:util'

import {
  IntrinsicPromise,
  applyFunction,
  createObject,
  defineKey,
  intrinsicThen
} from './captured-builtins'
import { assertRootIsStandard } from './object-prototype-guard'

/** The language's own constructor, so neither a replaced global nor a library bound to it before load chooses what the deadline builds. */
const CapturedPromise = IntrinsicPromise

/** Takes no action: it only marks a rejection as handled. */
function ignore(): void {}

const isNativePromise = types.isPromise

/**
 * Gives a native promise an own `constructor` that is the language's. `then` and `await` ask a promise for its constructor, and
 * without an own one that is a read of `Promise.prototype.constructor`, which a host can replace with a getter that throws or
 * a function that answers: a throw there happens before `then` attaches a handler, so the rejection stays unhandled.
 */
function pin<P>(promise: P): P {
  if (isNativePromise(promise)) {
    try {
      // A descriptor with no prototype: defining a property reads `get` and `set` through it.
      const own = createObject(null) as PropertyDescriptor
      own.value = CapturedPromise
      own.writable = true
      own.configurable = true
      defineKey(promise, 'constructor', own)
    } catch {
      // A frozen promise keeps the constructor it has; the root check refuses one that is replaced.
    }
  }
  return promise
}

/**
 * Marks a promise's rejection as handled, through the `then` taken at load, before anything else can refuse. A call the root check
 * refuses would otherwise leave a rejecting `work` with no handler, and an unhandled rejection ends the process. A value that is
 * not a native promise has nothing to mark.
 */
export function markHandled(work: unknown): void {
  pin(work)
  try {
    applyFunction(intrinsicThen, work, [ignore, ignore])
  } catch {
    // Not a native promise: nothing was started that can reject unhandled.
  }
}

/** An answer in a box with no prototype, so that no `then` is looked up on it. */
export interface Settled<T> {
  readonly value: T
}

/** Boxes a value for a promise to resolve with. */
function box<T>(value: T): Settled<T> {
  // An object literal with `__proto__: null` is syntax: it calls no built-in that could have been replaced.
  const boxed = { __proto__: null, value }
  return boxed
}

/**
 * Boxes a failure: reading `.value` throws the reason. A promise that carries a failure this way is never rejected, so there is no
 * rejection to be reported as unhandled while another call is being waited for, and no `catch` or `then` is needed to take one.
 */
function failed<T>(reason: unknown): Settled<T> {
  const boxed = {
    __proto__: null,
    get value(): T {
      throw reason
    }
  }
  return boxed
}

/**
 * Checks the root and hands the promise back for the `await` that follows on the same line. Nothing runs between the two.
 *
 * @param pending - The promise about to be awaited.
 * @returns The same promise.
 * @throws {AuthException} `auth.internal` while the root or a built-in is not the runtime's own.
 */
export function awaiting<P extends PromiseLike<unknown>>(pending: P): P {
  assertRootIsStandard()
  return pending
}

/**
 * Starts waiting for one call: the answer is a native promise whose rejection is already taken, so it can be awaited later,
 * after another call, with no unhandled rejection in between.
 *
 * @param work - The call, or its value.
 * @returns A promise of the boxed answer: it never rejects, and reading `.value` of a failure throws its reason.
 */
export function started<T>(work: PromiseLike<T> | T): Promise<Settled<T>> {
  const answer = (async (): Promise<Settled<T>> => {
    markHandled(work)
    try {
      assertRootIsStandard()
      return box(await work)
    } catch (error: unknown) {
      return failed(error)
    }
  })()
  return pin(answer)
}

/**
 * Waits for every call and answers their values in the order of the list. The calls run together because each one is started
 * before any is awaited, and the first failure settles the answer at once, as `Promise.all` did: a call that never settles
 * does not hold back the failure of another.
 *
 * @param calls - The calls, already started.
 * @returns Their values, boxed. The promise never rejects: reading `.value` throws the reason of the first call that failed.
 */
export async function allOf<T>(calls: readonly (PromiseLike<T> | T)[]): Promise<Settled<T[]>> {
  try {
    const pending: Promise<Settled<T>>[] = []
    for (let index = 0; index < calls.length; index += 1) pending.push(started(calls[index] as T))
    const everyone = pin(
      new CapturedPromise<Settled<T[]>>((resolve) => {
        const values: T[] = []
        let remaining = pending.length
        if (remaining === 0) resolve(box(values))
        for (let index = 0; index < pending.length; index += 1) {
          applyFunction(intrinsicThen, pending[index], [
            (answer: Settled<T>): void => {
              try {
                values[index] = answer.value
              } catch (error: unknown) {
                resolve(failed(error))
                return
              }
              remaining -= 1
              if (remaining === 0) resolve(box(values))
            },
            ignore
          ])
        }
      })
    )
    return await awaiting(everyone)
  } catch (error: unknown) {
    return failed(error)
  }
}

/**
 * Runs the work and rejects when it has not settled within the deadline.
 *
 * The work is not cancelled: the library stops waiting for it.
 *
 * @param work - The calls to bound.
 * @param ms - The deadline in milliseconds.
 * @param message - The message of the error thrown when the deadline passes first.
 * @returns What the work resolved to, boxed. The promise never rejects: reading `.value` throws the error of the work, or one with
 * `message` when the deadline passes first.
 */
export async function withDeadline<T>(
  work: () => Promise<T>,
  ms: number,
  message: string
): Promise<Settled<T>> {
  let timer: NodeJS.Timeout | undefined
  const settled = pin(
    new CapturedPromise<Settled<T>>((resolve) => {
      timer = setTimeout(() => {
        resolve(failed(new Error(message)))
      }, ms)
      const run = async (): Promise<void> => {
        try {
          const answer = work()
          markHandled(answer)
          assertRootIsStandard()
          resolve(box(await answer))
        } catch (error: unknown) {
          resolve(failed(error))
        }
      }
      void run()
    })
  )
  try {
    return await awaiting(settled)
  } catch (error: unknown) {
    return failed(error)
  } finally {
    clearTimeout(timer)
  }
}
