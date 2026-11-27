/**
 * @fileoverview The proxy over the client of Redis keeps a rejection it was handed heard, asks nothing of a thenable while the root
 * is not standard, and lets a command that answers nothing synchronously pass through.
 *
 * @layer Test
 */

import { Redis } from 'ioredis'

import { isRefusal } from '../utils/object-prototype-guard'
import { mappingOutages } from './redis-outage'

/** The proxy over a client whose one method answers `answer`, read as the plain method it behaves as. */
function methodOf(answer: unknown): () => unknown {
  const client: Redis = Object.assign(Object.create(null), { command: (): unknown => answer })
  const method: unknown = Reflect.get(mappingOutages(client, 'auth'), 'command')
  if (typeof method !== 'function') throw new Error('the proxy answered no method')
  return (): unknown => Reflect.apply(method, undefined, []) as unknown
}

/** Lets the microtasks and the next turns of the event loop run, which is when an unhandled rejection is reported. */
async function turn(): Promise<void> {
  await new Promise((done) => setImmediate(done))
  await new Promise((done) => setImmediate(done))
}

/** Runs `body` and answers the rejections the process reported as unhandled meanwhile. */
async function unhandledDuring(body: () => void): Promise<unknown[]> {
  const reported: unknown[] = []
  const listener = (reason: unknown): void => {
    reported.push(reason)
  }
  process.on('unhandledRejection', listener)
  try {
    body()
    await turn()
  } finally {
    process.off('unhandledRejection', listener)
  }
  return reported
}

/** Plants a key on `Object.prototype` for the duration of `body`, which is how a polluted process looks to the guard. */
async function whilePlanted(body: () => Promise<void>): Promise<void> {
  Object.defineProperty(Object.prototype, 'plantedForTheGate', {
    value: 'planted',
    configurable: true,
    enumerable: true,
    writable: true
  })
  try {
    await body()
  } finally {
    Reflect.deleteProperty(Object.prototype, 'plantedForTheGate')
  }
}

describe('mappingOutages and a rejection the call answered', () => {
  // Scenario: a command answers a rejected promise whose own `then` is a getter that throws. Expected: the wrapper throws that
  // error and the rejection is not reported as unhandled. Why: `isThenable` reads `then` and that read throws before any handler
  // is attached, so only the mark made before the read keeps the rejection from ending the process.
  it('hears the rejection of a promise whose then throws when read', async () => {
    const answer = Promise.reject(new Error('the command failed'))
    Object.defineProperty(answer, 'then', {
      get: (): never => {
        throw new Error('then read')
      }
    })
    const command = methodOf(answer)
    let thrown: unknown

    const unhandled = await unhandledDuring(() => {
      try {
        command()
      } catch (error) {
        thrown = error
      }
    })

    expect(thrown).toEqual(new Error('then read'))
    expect(unhandled).toEqual([])
  })
})

describe('mappingOutages while a key is planted on Object.prototype', () => {
  // Scenario: a command answers a thenable that is not a native promise, and a key is planted. Expected: the library's refusal, and
  // the `then` of the thenable is never called. Why: the wait asks a thenable for `then`, which runs code the library did not
  // choose, so the root is checked before the wait and not after it.
  it('refuses before it asks a thenable for then', async () => {
    const then = jest.fn((resolve: (value: string) => void) => {
      resolve('answer')
    })
    const command = methodOf({ then })
    let refusal: unknown

    await whilePlanted(async () => {
      refusal = await (command() as Promise<unknown>).catch((error: unknown) => error)
    })

    expect(isRefusal(refusal)).toBe(true)
    expect(then).not.toHaveBeenCalled()
  })
})

describe('mappingOutages and a command that answers nothing', () => {
  // Scenario: a command returns `undefined` synchronously, as a command with nothing to say does. Expected: `undefined`, with no
  // error. Why: `undefined` is not an object, so it is never read for `then`.
  it('returns undefined as it is', () => {
    expect(methodOf(undefined)()).toBeUndefined()
  })

  // Scenario: a command returns `null` synchronously. Expected: `null`, with no error. Why: `null` is an object by `typeof`, so only
  // the check for it keeps the read of `then` from throwing on it.
  it('returns null as it is', () => {
    expect(methodOf(null)()).toBeNull()
  })
})
