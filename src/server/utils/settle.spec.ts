/**
 * @fileoverview Waiting for several calls and for a deadline with `await` alone.
 *
 * @layer Test
 */

import { allOf, started, withDeadline } from './settle'

/** Reads the answer of a helper: a failure is thrown by `.value`, not by the promise. */
async function unbox<T>(pending: Promise<{ readonly value: T }>): Promise<T> {
  return (await pending).value
}

/** A promise and the functions that settle it. */
function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
} {
  let resolve: (value: T) => void = () => undefined
  let reject: (reason: unknown) => void = () => undefined
  const promise = new Promise<T>((done, fail) => {
    resolve = done
    reject = fail
  })
  return { promise, resolve, reject }
}

afterEach(() => {
  jest.useRealTimers()
})

describe('started', () => {
  // Scenario: a value, a thenable and a promise. Expected: each is answered as a native promise would be.
  it('answers a value, a thenable and a promise', async () => {
    const thenable: PromiseLike<number> = {
      then: (done) => Promise.resolve(done?.(2) as number) as never
    }

    expect((await started(1)).value).toBe(1)
    expect((await started(thenable)).value).toBe(2)
    expect((await started(Promise.resolve(3))).value).toBe(3)
  })

  // Scenario: a call that rejects while nobody awaits it yet. Expected: no unhandled rejection, and the rejection when awaited.
  it('takes a rejection until it is awaited', async () => {
    const unhandled = jest.fn()
    process.on('unhandledRejection', unhandled)
    try {
      const call = started(Promise.reject(new Error('early')))
      await new Promise((done) => setImmediate(done))

      expect(unhandled).not.toHaveBeenCalled()
      await expect(unbox(call)).rejects.toThrow('early')
    } finally {
      process.off('unhandledRejection', unhandled)
    }
  })
})

describe('allOf', () => {
  // Scenario: calls that settle in the reverse order. Expected: the values come in the order of the list.
  it('answers the values in the order of the list', async () => {
    const first = deferred<string>()
    const second = deferred<string>()
    const all = allOf([first.promise, second.promise])
    second.resolve('second')
    first.resolve('first')

    expect((await all).value).toEqual(['first', 'second'])
  })

  // Scenario: an empty list. Expected: an empty answer.
  it('answers an empty list', async () => {
    expect((await allOf([])).value).toEqual([])
  })

  // Scenario: the calls of the list. Expected: each one is already running when the first is still pending.
  it('starts every call before the first one settles', async () => {
    const first = deferred<number>()
    const calls: number[] = []
    const all = allOf([
      (() => {
        calls.push(1)
        return first.promise
      })(),
      (() => {
        calls.push(2)
        return Promise.resolve(2)
      })()
    ])

    expect(calls).toEqual([1, 2])
    first.resolve(1)
    expect((await all).value).toEqual([1, 2])
  })

  // Scenario: the second call rejects while the first never settles. Expected: that rejection at once, with no unhandled rejection.
  // Why: `Promise.all` rejected on the first failure, and a read that hangs must not hold back the failure of another.
  it('rejects as soon as a call fails, without waiting for an earlier one', async () => {
    const unhandled = jest.fn()
    process.on('unhandledRejection', unhandled)
    try {
      const first = deferred<number>()
      const all = allOf([first.promise, Promise.reject(new Error('second'))])

      await expect(unbox(all)).rejects.toThrow('second')
      await new Promise((done) => setImmediate(done))
      expect(unhandled).not.toHaveBeenCalled()
    } finally {
      process.off('unhandledRejection', unhandled)
    }
  })

  // Scenario: `Promise.prototype.constructor` becomes a getter that throws while a started call is already rejected, and is put back.
  // Expected: no unhandled rejection, and the failure is still the call's own. Why: `then` asks the promise for its constructor
  // before it attaches a handler, so a throw there left the rejection of the call with none.
  it('keeps a rejection handled when the constructor of promises throws', async () => {
    const unhandled = jest.fn()
    process.on('unhandledRejection', unhandled)
    const own = Object.getOwnPropertyDescriptor(
      Promise.prototype,
      'constructor'
    ) as PropertyDescriptor
    try {
      const rejecting = Promise.reject(new Error('the read failed'))
      Object.defineProperty(Promise.prototype, 'constructor', {
        configurable: true,
        get(): never {
          throw new Error('planted')
        }
      })
      let answer: ReturnType<typeof started<unknown>>
      try {
        answer = started(rejecting)
      } finally {
        Object.defineProperty(Promise.prototype, 'constructor', own)
      }
      await new Promise((done) => setImmediate(done))

      expect(unhandled).not.toHaveBeenCalled()
      await expect(unbox(answer)).rejects.toThrow()
    } finally {
      Object.defineProperty(Promise.prototype, 'constructor', own)
      process.off('unhandledRejection', unhandled)
    }
  })

  // Scenario: two calls that reject. Expected: the one that failed first is the one thrown.
  it('throws the first rejection in the order of the list', async () => {
    const all = allOf([Promise.reject(new Error('first')), Promise.reject(new Error('second'))])

    await expect(unbox(all)).rejects.toThrow('first')
  })
})

describe('withDeadline', () => {
  // Scenario: work that answers. Expected: its value, and no timer left.
  it('answers what the work answered and leaves no timer', async () => {
    jest.useFakeTimers()

    expect((await withDeadline(() => Promise.resolve('done'), 1000, 'late')).value).toBe('done')
    expect(jest.getTimerCount()).toBe(0)
  })

  // Scenario: work that rejects before the deadline. Expected: its own error, and no timer left.
  it('throws the error of the work', async () => {
    jest.useFakeTimers()

    await expect(
      unbox(withDeadline(() => Promise.reject(new Error('failed')), 1000, 'late'))
    ).rejects.toThrow('failed')
    expect(jest.getTimerCount()).toBe(0)
  })

  // Scenario: work that throws before it returns a promise. Expected: the same, as a rejection.
  it('turns a throw of the work into a rejection', async () => {
    await expect(
      unbox(
        withDeadline(
          () => {
            throw new Error('sync')
          },
          1000,
          'late'
        )
      )
    ).rejects.toThrow('sync')
  })

  // Scenario: work that never settles. Expected: still waiting a millisecond before the deadline, rejected at it with the message.
  it('rejects at the deadline with the message', async () => {
    jest.useFakeTimers()
    let outcome: unknown = 'waiting'
    void unbox(withDeadline(() => new Promise<never>(() => undefined), 1000, 'too late')).catch(
      (error: unknown) => {
        outcome = error
      }
    )

    await jest.advanceTimersByTimeAsync(999)
    expect(outcome).toBe('waiting')
    await jest.advanceTimersByTimeAsync(1)

    expect(outcome).toEqual(new Error('too late'))
  })

  // Scenario: work that settles after the deadline passed. Expected: nothing more happens, no unhandled rejection.
  it('ignores what the work does after the deadline', async () => {
    jest.useFakeTimers()
    const late = deferred<string>()
    const waiting = withDeadline(() => late.promise, 10, 'too late')
    const outcome = expect(unbox(waiting)).rejects.toThrow('too late')
    await jest.advanceTimersByTimeAsync(10)
    await outcome

    late.reject(new Error('after'))
    await jest.advanceTimersByTimeAsync(0)
  })
})

describe('the boxes the helpers hand out', () => {
  // Scenario: the host gets the box of an answer and tries to put another one in it. Expected: it cannot, for an answer or a failure.
  it('are frozen', async () => {
    const answer = await started(Promise.resolve('real'))
    const failure = await started(Promise.reject(new Error('real failure')))

    expect(Object.isFrozen(answer)).toBe(true)
    expect(Object.isFrozen(failure)).toBe(true)
    expect(Object.isFrozen(await allOf([1]))).toBe(true)
    expect(() => {
      ;(answer as { value: unknown }).value = 'forged'
    }).toThrow(TypeError)
    expect(answer.value).toBe('real')
    expect(() => failure.value).toThrow('real failure')
  })
})

describe('a promise that cannot take the pinned constructor', () => {
  /** A promise that answers `real` and has an own constructor it made permanent, and an own `then` that answers `forged`. */
  function hostile(): Promise<string> {
    const promise = Promise.resolve('real')
    Object.defineProperty(promise, 'constructor', { value: Array, writable: false })
    Object.defineProperty(promise, 'then', {
      value: (resolve: (answer: string) => void): void => {
        resolve('forged')
      }
    })
    return promise
  }

  // Scenario: the work given to `started` is such a promise. Expected: the wait is refused, as `awaiting` refuses it, and the host's
  // `then` is never the one that answers. Why: the pin failed, and a wait that goes on bare is the one the host's constructor answers.
  it('is refused by started, not answered by its then', async () => {
    const answer = await started(hostile())

    expect(() => answer.value).toThrow(TypeError)
  })

  // Scenario: the work of `withDeadline` answers with such a promise. Expected: the same refusal.
  it('is refused by withDeadline, not answered by its then', async () => {
    const answer = await withDeadline(() => hostile(), 1000, 'late')

    expect(() => answer.value).toThrow(TypeError)
  })
})
