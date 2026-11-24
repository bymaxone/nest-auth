/**
 * @fileoverview `pinned` and `@Pinned()`: the promise a decision returns, and the one it awaits, carry the language's own
 * `constructor`, so an `await` of either never reads `Promise.prototype.constructor`.
 *
 * @layer Test
 */

import { Pinned, PinnedMethods, pinned } from './settle'

const prototypeConstructor = Object.getOwnPropertyDescriptor(
  Promise.prototype,
  'constructor'
) as PropertyDescriptor

/**
 * Replaces `Promise.prototype.constructor` by a getter that counts the reads made for `target` and answers the language's own
 * constructor, so nothing else that awaits in the process is disturbed.
 *
 * @returns The number of reads so far.
 */
function watchConstructorOf(target: Promise<unknown>): () => number {
  let reads = 0
  Object.defineProperty(Promise.prototype, 'constructor', {
    configurable: true,
    get(this: unknown): unknown {
      if (this === target) reads += 1
      return Promise
    }
  })
  return () => reads
}

afterEach(() => {
  Object.defineProperty(Promise.prototype, 'constructor', prototypeConstructor)
})

@PinnedMethods('decide', 'refuse')
class Decided {
  public readonly seen: unknown[] = []

  async decide(first: string, second: number): Promise<string> {
    this.seen.push(first, second)
    return Promise.resolve(`${first}:${second}`)
  }

  async refuse(): Promise<never> {
    throw new Error('refused')
  }
}

describe('pinned', () => {
  // Scenario: a native promise. Expected: the same promise, with its own constructor the language's. Why: an own property
  // answers the lookup an `await` makes, so the one on the prototype is never read.
  it('gives a native promise an own constructor and returns the same promise', () => {
    const promise = Promise.resolve(1)

    expect(pinned(promise)).toBe(promise)
    expect(Object.getOwnPropertyDescriptor(promise, 'constructor')).toEqual({
      value: Promise,
      writable: false,
      enumerable: false,
      configurable: false
    })
  })

  // Scenario: a value that is not a native promise. Expected: handed back untouched, with no property added.
  it('leaves a value that is not a native promise as it was', () => {
    const thenable = { then: (): void => undefined }

    expect(pinned(thenable)).toBe(thenable)
    expect(Object.keys(thenable)).toEqual(['then'])
    expect(pinned(undefined)).toBeUndefined()
  })

  // Scenario: a frozen promise cannot take the property. Expected: the pin throws, so the wait that follows rejects and is never
  // answered by a constructor the library did not choose.
  it('throws for a frozen promise, and an async caller rejects', async () => {
    const promise = Object.freeze(Promise.resolve(1))

    expect(() => pinned(promise)).toThrow(TypeError)
    expect(Object.hasOwn(promise, 'constructor')).toBe(false)
    await expect((async (): Promise<number> => await pinned(promise))()).rejects.toThrow(TypeError)
  })

  // Scenario: the constructor of a pinned promise is replaced afterwards. Expected: it cannot be, so the await keeps the language's.
  it('cannot have its constructor replaced after the pin', () => {
    const promise = pinned(Promise.resolve(1))

    expect(() => Object.defineProperty(promise, 'constructor', { value: Array })).toThrow(TypeError)
    expect(() => {
      ;(promise as { constructor: unknown }).constructor = Array
    }).toThrow(TypeError)
  })

  // Scenario: the host got there first and gave the promise its own constructor that it can never change. Expected: the pin
  // refuses, and the wait that follows rejects, so the host's constructor is never the one the await reads.
  it('refuses a promise whose own constructor the host made permanent', async () => {
    const promise = Promise.resolve(1)
    Object.defineProperty(promise, 'constructor', { value: Array, writable: false })

    expect(() => pinned(promise)).toThrow(TypeError)
    expect(promise.constructor).toBe(Array)
    await expect((async (): Promise<number> => await pinned(promise))()).rejects.toThrow(TypeError)
  })

  // Scenario: the host's permanent own constructor is an accessor. Expected: the pin refuses and the getter is never run.
  it('refuses a promise whose own constructor is a permanent accessor', () => {
    const promise = Promise.resolve(1)
    let reads = 0
    Object.defineProperty(promise, 'constructor', {
      get: () => {
        reads += 1
        return Array
      }
    })

    expect(() => pinned(promise)).toThrow(TypeError)
    expect(reads).toBe(0)
  })

  // Scenario: the host's own constructor can still be changed. Expected: the pin replaces it with the language's and locks it.
  it('replaces an own constructor the host left changeable', () => {
    const promise = Promise.resolve(1)
    Object.defineProperty(promise, 'constructor', { value: Array, configurable: true })

    expect(pinned(promise).constructor).toBe(Promise)
    expect(() => Object.defineProperty(promise, 'constructor', { value: Array })).toThrow(TypeError)
  })

  // Scenario: the host's own constructor is a changeable accessor. Expected: the pin replaces it and its getter never runs.
  it('replaces an own constructor accessor the host left changeable without running it', () => {
    const promise = Promise.resolve(1)
    let reads = 0
    Object.defineProperty(promise, 'constructor', {
      get: () => {
        reads += 1
        return Array
      },
      configurable: true
    })

    expect(pinned(promise).constructor).toBe(Promise)
    expect(reads).toBe(0)
  })

  // Scenario: the host's permanent own constructor already is the language's. Expected: nothing to refuse, the promise is kept.
  it("keeps a promise whose permanent own constructor is the language's", () => {
    const promise = Promise.resolve(1)
    Object.defineProperty(promise, 'constructor', { value: Promise, writable: false })

    expect(pinned(promise)).toBe(promise)
  })

  // Scenario: the promise carries its own `then`, a function that answers another value and an accessor that throws. Expected: the
  // awaited answer is the real one and neither is called or read. Why: a native await of a promise whose constructor is the language's
  // takes its state directly and never asks for `then`.
  it('is awaited without calling or reading an own then of the host', async () => {
    let touched = 0
    const answering = Promise.resolve('real')
    Object.defineProperty(answering, 'then', {
      value: (resolve: (value: string) => void): void => {
        touched += 1
        resolve('forged')
      }
    })
    const throwing = Promise.resolve('real')
    Object.defineProperty(throwing, 'then', {
      get: (): never => {
        touched += 1
        throw new Error('then read')
      }
    })

    expect(await pinned(answering)).toBe('real')
    expect(await pinned(throwing)).toBe('real')
    expect(touched).toBe(0)
  })

  // Scenario: the constructor of promises watched while a pinned promise is awaited. Expected: it is never read for that promise.
  // Why: the read is what a replaced constructor answers; the own property is found first.
  it('is awaited without reading the constructor of promises', async () => {
    const promise = Promise.resolve('answer')
    const reads = watchConstructorOf(promise)

    await expect(pinned(promise)).resolves.toBe('answer')
    expect(reads()).toBe(0)
  })

  // Scenario: the same with a promise that is not pinned. Expected: the `await` reads it once, which is what pinning prevents.
  it('would be read at the await without it', async () => {
    const promise = Promise.resolve('answer')
    const reads = watchConstructorOf(promise)

    await promise

    expect(reads()).toBe(1)
  })
})

describe('@PinnedMethods()', () => {
  // Scenario: a decorated async method called with arguments. Expected: it runs on the instance it was called on, with them.
  it('calls the method with its this and its arguments', async () => {
    const decided = new Decided()

    await expect(decided.decide('a', 2)).resolves.toBe('a:2')
    expect(decided.seen).toEqual(['a', 2])
  })

  // Scenario: the promise it returns. Expected: it has the own constructor of the language.
  it('returns a promise with an own constructor', async () => {
    const promise = new Decided().decide('a', 1)

    expect(Object.getOwnPropertyDescriptor(promise, 'constructor')?.value).toBe(Promise)
    await promise
  })

  // Scenario: the caller awaits what a decision returned, an answer and a refusal, with the constructor watched. Expected: the
  // answer and the refusal, and no read of the constructor for either promise. Why: the caller's `await` is the last hop.
  it('lets the caller await an answer and a refusal without a read of the constructor', async () => {
    const decided = new Decided()
    const answer = decided.decide('a', 3)
    const refusal = decided.refuse()
    let reads = 0
    Object.defineProperty(Promise.prototype, 'constructor', {
      configurable: true,
      get(this: unknown): unknown {
        if (this === answer || this === refusal) reads += 1
        return Promise
      }
    })

    await expect(answer).resolves.toBe('a:3')
    await expect(refusal).rejects.toThrow('refused')
    expect(reads).toBe(0)
  })
})

describe('@Pinned() on a route handler', () => {
  class Handler {
    @Pinned()
    async handle(this: Handler, left: string, right: number): Promise<string> {
      await Promise.resolve()
      return `${left}:${right}:${this instanceof Handler}`
    }
  }

  // Scenario: a handler decorated on the method, called with arguments. Expected: it keeps `this` and the arguments, answers the
  // same value, and the promise it returns has the own constructor. Why: a route handler is decorated per method because Nest reads
  // the route from the method itself, which a class decorator would replace.
  it('keeps this and the arguments, and returns a pinned promise', async () => {
    const promise = new Handler().handle('a', 2)

    expect(Object.getOwnPropertyDescriptor(promise, 'constructor')?.value).toBe(Promise)
    await expect(promise).resolves.toBe('a:2:true')
  })
  // Scenario: the wrapper a route handler becomes. Expected: it is named like the method. Why: the document builder of
  // `@nestjs/swagger` finds the parameter types of a handler by `method.name`, and without them registers no schema for a DTO.
  it('is named like the method it wraps', () => {
    expect(Handler.prototype.handle.name).toBe('handle')
  })
})
