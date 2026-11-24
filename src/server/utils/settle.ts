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
  freezeObject,
  getDescriptor,
  hasOwn,
  intrinsicPromisePrototype as IntrinsicPrototype,
  intrinsicThen,
  ownKeys
} from './captured-builtins'
import { assertNoThenOnChain, assertRootIsStandard, refusedOr } from './object-prototype-guard'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

/** The language's own constructor, so neither a replaced global nor a library bound to it before load chooses what the deadline builds. */
const CapturedPromise = IntrinsicPromise

const isNativePromise = types.isPromise

/**
 * Gives a native promise an own `constructor` that is the language's. `then` and `await` ask a promise for its constructor, and
 * without an own one that is a read of `Promise.prototype.constructor`, which a host can replace with a getter that throws or
 * a function that answers: a throw there happens before `then` attaches a handler, so the rejection stays unhandled.
 */
export function pinned<P>(promise: P): P {
  if (isNativePromise(promise)) {
    // A descriptor with no prototype: defining a property reads `get` and `set` through it. Neither configurable nor writable, so
    // code that holds the promise cannot put another constructor back before the `await` reads it.
    const own = createObject(null) as PropertyDescriptor
    own.value = CapturedPromise
    own.writable = false
    own.configurable = false
    // A promise that cannot take the constructor (frozen, or with another own one that cannot change) throws here: the caller is
    // one that is about to wait, so the wait fails and is never answered by a constructor the library did not choose.
    try {
      defineKey(promise, 'constructor', own)
    } catch (error: unknown) {
      // The caller is about to refuse this promise and will never await it, so a handler is attached here when one can be: see `hear`.
      hear(promise)
      // The engine's own TypeError is not what a caller is told: a promise that refuses the pin is refused as `auth.internal`.
      throw refusedOr(error, AUTH_ERROR_CODES.INTERNAL)
    }
  }
  return promise
}

/** Whether `Promise.prototype.constructor` is still the language's own data property, read without running any accessor. */
function rootConstructorIsIntact(): boolean {
  const slot = getDescriptor(IntrinsicPrototype, 'constructor')
  return slot !== undefined && hasOwn(slot, 'value') && slot.value === IntrinsicPromise
}

/**
 * Gives a promise that the pin refused a handler for its rejection, without reading what a host could have planted. A native `await`
 * attaches it without reading `then` or the species, but it reads `constructor` first, and a slot that is not the language's own
 * data property (a getter, a replaced value) can plant a `then` in that read, so then the language's `then` is used. A promise that
 * holds a constructor of its own (permanent, and not the language's) goes the same way: `await` would use the `then` it holds.
 *
 * Known limit: every route that attaches a handler (`then`, `await`, `Promise.resolve`) reads `constructor` first, so a promise whose
 * own constructor is a getter that throws cannot take one. The refusal is still the library's own error; that promise's rejection
 * stays unhandled and is the host's, who made it.
 */
function hear(work: object): void {
  if (getDescriptor(work, 'constructor') !== undefined || !rootConstructorIsIntact()) {
    try {
      applyFunction(intrinsicThen, work, [ignore, ignore])
    } catch {
      // A constructor that throws when read cannot take a handler; the awaiter refuses it too.
    }
    return
  }
  listen(work)
}

/** Attaches a handler that ignores the rejection: `await` of a native promise asks it for neither `then` nor the species. */
function listen(work: object): void {
  void (async (): Promise<void> => {
    try {
      await work
    } catch {
      // Only marks the rejection as handled.
    }
  })()
}

/**
 * Marks a promise's rejection as handled, before anything else can refuse. A call the root check refuses would otherwise leave a
 * rejecting `work` with no handler, and an unhandled rejection ends the process. A value that is not a native promise has nothing to
 * mark. A promise the pin refuses has already been offered its handler by the pin, which cannot attach one to a promise whose own
 * constructor throws when read: see `hear`.
 */
export function markHandled(work: unknown): void {
  if (!isNativePromise(work)) return
  try {
    pinned(work)
  } catch {
    return
  }
  listen(work)
}

/**
 * Starts work whose answer nothing reads and reports how it failed, without a `.then` or `.catch` chain: a chain asks the promise
 * for `then` and builds another through its species, so a throwing species would make the chain itself throw and leave the failure
 * of the work unhandled. The work is awaited pinned, inside a `try`, so every failure of it, of the pin and of the root check ends
 * in `onFailure`, and a handler that throws is swallowed too. The call of `run` happens before this returns.
 *
 * @param run - The work, called at once; it may answer a promise, a value, or throw.
 * @param onFailure - Told `threw` for a synchronous throw and `rejected` for a failed wait, with what was thrown.
 */
export function detached(
  run: () => unknown,
  onFailure: (how: 'rejected' | 'threw', error: unknown) => void
): void {
  void (async (): Promise<void> => {
    let work: unknown
    try {
      work = run()
    } catch (error: unknown) {
      report(onFailure, 'threw', error)
      return
    }
    try {
      await awaiting(work as PromiseLike<unknown>)
    } catch (error: unknown) {
      report(onFailure, 'rejected', error)
    }
  })()
}

/** Calls the failure handler of a detached call; one that throws changes nothing. */
function report(
  onFailure: (how: 'rejected' | 'threw', error: unknown) => void,
  how: 'rejected' | 'threw',
  error: unknown
): void {
  try {
    onFailure(how, error)
  } catch {
    // Nothing is waiting for the handler.
  }
}

/** A handler that only marks a rejection as handled. */
function ignore(): void {}

/** An answer in a box with no prototype, so that no `then` is looked up on it. */
export interface Settled<T> {
  readonly value: T
}

/** Boxes a value for a promise to resolve with. */
export function box<T>(value: T): Settled<T> {
  // An object literal with `__proto__: null` is syntax: it calls no built-in that could have been replaced.
  const boxed = { __proto__: null, value }
  // Frozen: the box is handed to code of the host, which could otherwise put another answer in it before it is read.
  return freezeObject(boxed)
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
  return freezeObject(boxed)
}

/**
 * Checks the root and hands the promise back for the `await` that follows on the same line. Nothing runs between the two.
 *
 * @param pending - The promise about to be awaited.
 * @returns The same promise.
 * @throws {AuthException} `auth.internal` while the root or a built-in is not the runtime's own; the promise is marked handled first.
 */
export function awaiting<P extends PromiseLike<unknown>>(pending: P): P {
  try {
    assertRootIsStandard()
  } catch (error) {
    // The promise was made before the root was checked and is not awaited now: its rejection must still be heard, or it is
    // reported as unhandled while the caller is told the refusal.
    markHandled(pending)
    throw error
  }
  return pinned(pending)
}

/**
 * Checks the root and hands the value back for the `return` that follows on the same line. An async function that returns an
 * object resolves its own promise from it, which asks the object for `then`; a `then` planted on the prototype it inherits from
 * while the function waited would answer for it, so the whole chain of prototypes is searched too. Nothing runs between this check and that read.
 *
 * @param value - What the function is about to return.
 * @returns The same value.
 * @throws {AuthException} `auth.internal` while the root or a built-in is not the runtime's own.
 */
export function checked<T>(value: T): T {
  assertRootIsStandard()
  assertNoThenOnChain(value)
  return value
}

/**
 * Gives the wrapper of a method the name of the method. Tools that read a route's metadata look it up by `method.name` (the document
 * builder of `@nestjs/swagger` reads the parameter types of a handler that way), and a wrapper named after itself finds none.
 */
function named<F extends (...args: never[]) => unknown>(wrapper: F, method: F): F {
  const own = createObject(null) as PropertyDescriptor
  own.value = (method as { name: string }).name
  own.configurable = true
  defineKey(wrapper, 'name', own)
  return wrapper
}

/**
 * Makes the promise of one async method one whose own `constructor` is the language's, for a route handler: applied as the
 * decorator nearest the method, it runs before the route decorators attach their metadata to what it returns.
 *
 * @returns A method decorator.
 */
export function Pinned(): MethodDecorator {
  return (_target, _key, descriptor) => {
    const method = descriptor.value as (...args: never[]) => unknown
    descriptor.value = named(function pinnedMethod(this: unknown, ...args: never[]): unknown {
      return pinned(applyFunction(method, this, args))
    }, method) as never
  }
}

/**
 * Makes the promise each named async method of a class returns one whose own `constructor` is the language's. The caller of a
 * decision (a guard's caller, a controller awaiting a service, a host awaiting the API) reads `constructor` of that promise after
 * the library's last check, and a replaced `Promise.prototype.constructor` decides what that `await` yields, a refusal included.
 * The methods are called with the `this` and the arguments they were given. A route handler is not listed here: Nest reads its path and guards from the method itself, so `@Pinned()` goes on it, below the route decorators. It decorates the class, not each method, so a method
 * does not grow by the line of its decorator.
 *
 * @param names - The methods of the class, each declared on it.
 * @returns A class decorator.
 */
export function PinnedMethods(...names: string[]): ClassDecorator {
  return (target) => {
    for (const name of names) {
      const own = getDescriptor(target.prototype, name) as PropertyDescriptor
      const method = own.value as (...args: never[]) => unknown
      const wrapper = named(function pinnedMethod(this: unknown, ...args: never[]): unknown {
        return pinned(applyFunction(method, this, args))
      }, method)
      own.value = wrapper
      defineKey(target.prototype, name, own)
    }
  }
}

/**
 * Makes the promise each method a class declares return one whose own `constructor` is the language's, whatever the method is
 * named: a service whose methods the host awaits (or whose answer a guard awaits) would otherwise be read for `constructor` after the
 * library's last check, by a `Promise.prototype.constructor` the host's own store call planted while the method waited. A method
 * that answers no promise is passed through unchanged, so the decorator is safe on a class of sync and async methods alike.
 *
 * @returns A class decorator.
 */
export function PinnedAll(): ClassDecorator {
  return (target) => {
    const keys = ownKeys(target.prototype)
    for (let index = 0; index < keys.length; index += 1) {
      const name = keys[index] as string | symbol
      const own = getDescriptor(target.prototype, name) as PropertyDescriptor
      if (name === 'constructor' || !hasOwn(own, 'value') || typeof own.value !== 'function')
        continue
      const method = own.value as (...args: never[]) => unknown
      own.value = named(function pinnedMethod(this: unknown, ...args: never[]): unknown {
        return pinned(applyFunction(method, this, args))
      }, method)
      defineKey(target.prototype, name, own)
    }
  }
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
    try {
      return box(await awaiting(work as PromiseLike<T>))
    } catch (error: unknown) {
      return failed(error)
    }
  })()
  return pinned(answer)
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
    const everyone = pinned(
      new CapturedPromise<Settled<T[]>>((resolve) => {
        const values: T[] = []
        let remaining = pending.length
        if (remaining === 0) resolve(box(values))
        for (let index = 0; index < pending.length; index += 1) {
          void (async (): Promise<void> => {
            try {
              values[index] = (await (pending[index] as Promise<Settled<T>>)).value
            } catch (error: unknown) {
              resolve(failed(error))
              return
            }
            remaining -= 1
            if (remaining === 0) resolve(box(values))
          })()
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
  const settled = pinned(
    new CapturedPromise<Settled<T>>((resolve) => {
      timer = setTimeout(() => {
        resolve(failed(new Error(message)))
      }, ms)
      const run = async (): Promise<void> => {
        try {
          const answer = work()
          resolve(box(await awaiting(answer)))
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
