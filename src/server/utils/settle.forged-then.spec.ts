/**
 * @fileoverview The ways a host can answer for an awaited value through `then`: a constructor replaced and put back by a `then`
 * that forges the value, and a `then` planted on a prototype the value inherits from. The helpers refuse the first when the
 * constructor is replaced at the `await`, and the second before the value is handed over; the answer travels in a box that
 * inherits from nothing.
 *
 * @layer Test
 */

import { IntrinsicPromise } from './captured-builtins'
import { isRefusal } from './object-prototype-guard'
import { allOf, awaiting, started, withDeadline } from './settle'

const ownConstructor = Object.getOwnPropertyDescriptor(
  Promise.prototype,
  'constructor'
) as PropertyDescriptor
const ownThen = Object.getOwnPropertyDescriptor(Promise.prototype, 'then') as PropertyDescriptor

afterEach(() => {
  Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
  Object.defineProperty(Promise.prototype, 'then', ownThen)
  for (const holder of [Object.prototype, Array.prototype, Function.prototype])
    Reflect.deleteProperty(holder, 'then')
})

/** Replaces the constructor and installs a `then` that puts it back and answers `forged`, as a host's flaw could. */
function replaceAndRestore(forged: unknown): void {
  Object.defineProperty(Promise.prototype, 'constructor', {
    ...ownConstructor,
    value: function Other() {}
  })
  Object.defineProperty(Promise.prototype, 'then', {
    ...ownThen,
    value: function forgedThen(resolve: (value: unknown) => void) {
      Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
      resolve(forged)
    }
  })
}

/**
 * Plants, makes the calls and puts everything back before anything is awaited, so the runner's own awaits never meet the plant:
 * the refusal is made synchronously, at the check that precedes each `await`, and it is the outcome that is read afterwards.
 */
async function outcomesOf(
  plant: () => void,
  calls: (() => Promise<unknown>)[]
): Promise<unknown[]> {
  const promises: (Promise<unknown> | { thrown: unknown })[] = []
  plant()
  try {
    for (const call of calls) {
      try {
        promises.push(call())
      } catch (error) {
        promises.push({ thrown: error })
      }
    }
  } finally {
    Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
    Object.defineProperty(Promise.prototype, 'then', ownThen)
    for (const holder of [Object.prototype, Array.prototype, Function.prototype])
      Reflect.deleteProperty(holder, 'then')
  }
  const settled = promises.map((promise) =>
    promise instanceof Promise
      ? promise.then(
          (answered) => ({ answered }),
          (error: unknown) => error
        )
      : Promise.resolve(promise.thrown)
  )
  const outcomes: unknown[] = []
  for (const outcome of settled) outcomes.push(await outcome)
  return outcomes
}

const real = { real: true }
const calls = [
  async () => (await awaiting(started(real))).value,
  async () => (await awaiting(allOf([real]))).value,
  async () => (await awaiting(withDeadline(() => Promise.resolve(real), 1000, 'late'))).value
]

describe('a constructor replaced and put back by a then', () => {
  // Scenario: the constructor replaced and a `then` that restores it and answers a forged value. Expected: refused, never answered.
  // Why: `await` asks the constructor of a promise whether it is native, so a replaced one makes it call `then` of the host.
  it('is refused by every helper', async () => {
    const outcomes = await outcomesOf(() => {
      replaceAndRestore('FORGED')
    }, calls)

    expect(outcomes.map(isRefusal)).toEqual([true, true, true])
  })
})

describe('a then planted on a prototype a value inherits from', () => {
  // Scenario: `then` planted on the root, on arrays or on functions before the call. Expected: refused, and the value that would
  // have been hijacked is never answered. Why: resolving a promise with an object asks that object for `then`.
  it.each([
    ['Object.prototype', Object.prototype],
    ['Array.prototype', Array.prototype],
    ['Function.prototype', Function.prototype]
  ])('refuses every helper after a then on %s', async (_name, holder) => {
    const outcomes = await outcomesOf(() => {
      Object.defineProperty(holder, 'then', {
        value: (resolve: (value: unknown) => void) => {
          resolve('FORGED')
        },
        configurable: true,
        writable: true
      })
    }, calls)

    expect(outcomes.map(isRefusal)).toEqual([true, true, true])
  })
})

describe('the box', () => {
  // Scenario: an answer that is an object. Expected: the box has no prototype, so no `then` is looked up on it.
  it('inherits from nothing', async () => {
    const box = await started({ real: true })

    expect(Object.getPrototypeOf(box)).toBeNull()
    expect(box.value).toEqual({ real: true })
    expect(Object.getPrototypeOf(await allOf([1]))).toBeNull()
    expect(
      Object.getPrototypeOf(await withDeadline(() => Promise.resolve(1), 1000, 'x'))
    ).toBeNull()
  })
})

describe('the intrinsic promise', () => {
  // Scenario: the global `Promise` replaced by a subclass. Expected: the constructor the library waits on is still the language's.
  it('is the one a native async function returns', () => {
    const native = Object.getPrototypeOf((async () => undefined)()).constructor as unknown

    expect(IntrinsicPromise).toBe(native)
  })
})
