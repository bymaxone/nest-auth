/**
 * @fileoverview The effects of `settle.ts` that only a promise the language will not pin, or a root that is not standard, can show:
 * a rejection that is still heard, a thenable that is never asked for `then`, and the properties of a decorated class left as they were.
 *
 * @layer Test
 */

import { assertNoThenOnChain, isRefusal } from './object-prototype-guard'
import {
  awaiting,
  checked,
  detached,
  markHandled,
  PinnedAll,
  PinnedMethods,
  started,
  withDeadline
} from './settle'

/** Lets the microtasks and the next turn of the event loop run, which is when an unhandled rejection is reported. */
async function turn(): Promise<void> {
  await new Promise((done) => setImmediate(done))
  await new Promise((done) => setImmediate(done))
}

/** Runs `body` and answers the rejections the process reported as unhandled meanwhile. */
async function unhandledDuring(body: () => Promise<void> | void): Promise<unknown[]> {
  const reported: unknown[] = []
  const listener = (reason: unknown): void => {
    reported.push(reason)
  }
  process.on('unhandledRejection', listener)
  try {
    await body()
    await turn()
  } finally {
    process.off('unhandledRejection', listener)
  }
  return reported
}

/** A promise that already rejected and cannot take an own `constructor`, so the pin refuses it. */
function frozenRejection(message: string): Promise<never> {
  return Object.freeze(Promise.reject(new Error(message)))
}

/** Replaces `Promise.prototype.constructor` by a plain function for the duration of `body`. */
async function withReplacedConstructor(body: () => Promise<void> | void): Promise<void> {
  const own = Object.getOwnPropertyDescriptor(
    Promise.prototype,
    'constructor'
  ) as PropertyDescriptor
  Object.defineProperty(Promise.prototype, 'constructor', { ...own, value: function Other() {} })
  try {
    await body()
  } finally {
    Object.defineProperty(Promise.prototype, 'constructor', own)
  }
}

describe('a rejection nothing awaits, because the pin refused its promise', () => {
  // Scenario: `detached` runs work that answers a frozen, rejected promise. Expected: the failure is reported once and nothing is
  // left unhandled. Why: the wait ends at the refused pin, so only `markHandled` ever attaches a handler.
  it('is heard by detached', async () => {
    const onFailure = jest.fn()

    const unhandled = await unhandledDuring(() => {
      detached(() => frozenRejection('detached'), onFailure)
    })

    expect(unhandled).toEqual([])
    expect(onFailure).toHaveBeenCalledWith('rejected', expect.anything())
  })

  // Scenario: `started` is given a frozen, rejected promise. Expected: no unhandled rejection, and reading the answer throws.
  it('is heard by started', async () => {
    let call: Awaited<ReturnType<typeof started>> | undefined

    const unhandled = await unhandledDuring(async () => {
      call = await started(frozenRejection('started'))
    })

    expect(unhandled).toEqual([])
    expect(() => call?.value).toThrow()
  })

  // Scenario: `withDeadline` runs work that answers a frozen, rejected promise. Expected: no unhandled rejection, and the wait is refused.
  it('is heard by withDeadline', async () => {
    let answer: Awaited<ReturnType<typeof withDeadline>> | undefined

    const unhandled = await unhandledDuring(async () => {
      answer = await withDeadline(() => frozenRejection('deadline'), 1000, 'late')
    })

    expect(unhandled).toEqual([])
    expect(() => answer?.value).toThrow()
  })

  // Scenario: the root is not standard when `awaiting` is given a promise that rejects. Expected: the refusal is thrown and the
  // rejection is still heard. Why: the promise is never awaited, so the catch of `awaiting` is the only place that marks it.
  it('is heard by awaiting when the root check refuses', async () => {
    const unhandled = await unhandledDuring(() =>
      withReplacedConstructor(() => {
        expect(() => awaiting(Promise.reject(new Error('refused first')))).toThrow()
      })
    )

    expect(unhandled).toEqual([])
  })
})

describe('markHandled', () => {
  // Scenario: the constructor slot of the root holds another function, and a frozen promise rejects. Expected: the language's `then`
  // is used, so the `then` of the prototype is never called and the rejection is heard. Why: `await` would ask a constructor that
  // is not the language's for `then`.
  it('does not call the then of a prototype whose constructor was replaced', async () => {
    const work = frozenRejection('replaced slot')
    const original = Promise.prototype.then
    const seen = jest.fn()
    Promise.prototype.then = function spying(this: Promise<unknown>, ...args: unknown[]) {
      if (this === (work as Promise<unknown>)) seen()
      return (original as (...a: unknown[]) => unknown).apply(this, args)
    } as typeof original

    try {
      const unhandled = await unhandledDuring(() =>
        withReplacedConstructor(() => {
          markHandled(work)
        })
      )

      expect(unhandled).toEqual([])
    } finally {
      Promise.prototype.then = original
    }
    expect(seen).not.toHaveBeenCalled()
  })

  // Scenario: a thenable, which is not a native promise. Expected: its `then` is never called. Why: there is nothing to mark, and
  // `await` would run the `then` of a value that is not the library's to ask.
  it('leaves a value that is not a native promise alone', async () => {
    const then = jest.fn()

    markHandled({ then })
    markHandled(42)
    await turn()

    expect(then).not.toHaveBeenCalled()
  })
})

describe('checked', () => {
  // Scenario: the root is not standard and a value is returned. Expected: the refusal, before the chain of the value is read.
  it('refuses a value while the constructor of promises is replaced', async () => {
    await withReplacedConstructor(() => {
      let refusal: unknown
      try {
        checked({ id: 1 })
      } catch (error) {
        refusal = error
      }

      expect(isRefusal(refusal)).toBe(true)
      expect(() => {
        assertNoThenOnChain({ id: 1 })
      }).not.toThrow()
    })
  })
})

describe('the decorators of a class', () => {
  // Scenario: the wrapper takes the name of the method. Expected: the name is a configurable property, as a function's own is.
  it('names a wrapper with a configurable name', () => {
    class Named {
      public async run(): Promise<number> {
        return 1
      }
    }
    PinnedMethods('run')(Named)

    const slot = Object.getOwnPropertyDescriptor(Named.prototype.run, 'name')

    expect(slot).toMatchObject({ value: 'run', configurable: true })
  })

  // Scenario: PinnedAll on a class whose prototype holds the constructor, an accessor and a data property that is not a function,
  // besides a method. Expected: only the method is wrapped.
  it('leaves an accessor and a data property of its own as they were', async () => {
    class Own {
      public get readOnly(): number {
        return 5
      }
      public async answer(): Promise<number> {
        return 7
      }
    }
    Object.defineProperty(Own.prototype, 'ceiling', {
      value: 3,
      writable: true,
      configurable: true
    })
    PinnedAll()(Own)

    const instance = new Own()

    expect(Own.prototype.constructor).toBe(Own)
    expect(instance.readOnly).toBe(5)
    expect(Object.getOwnPropertyDescriptor(Own.prototype, 'ceiling')?.value).toBe(3)
    expect(Object.getOwnPropertyDescriptor(Own.prototype, 'answer')?.value.name).toBe('answer')
    expect(await instance.answer()).toBe(7)
  })
})
