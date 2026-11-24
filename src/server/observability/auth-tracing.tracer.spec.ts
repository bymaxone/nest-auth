/**
 * @fileoverview The span of a tracer that plants an accessor on `Promise.prototype.constructor` in `span.end()`, which runs after the
 * operation has decided. The host awaits what `AuthTracing.span` returns, so the answer is never the one the plant forged: the
 * result is checked again before it leaves, and the host's await reads a pinned promise.
 *
 * @layer Test
 */

import { isRefusal } from '../utils/object-prototype-guard'
import { AuthTracing } from './auth-tracing'

const proto = Promise.prototype as unknown as Record<string, unknown>
const ownConstructor = Object.getOwnPropertyDescriptor(
  Promise.prototype,
  'constructor'
) as PropertyDescriptor
const ownThen = Promise.prototype.then

/** Plants a one-shot accessor whose first read installs a one-shot `then` that answers `forgedValue`. */
function plant(forgedValue: unknown): void {
  Object.defineProperty(Promise.prototype, 'constructor', {
    configurable: true,
    get() {
      Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
      Object.defineProperty(proto, 'then', {
        configurable: true,
        writable: true,
        value(this: Promise<unknown>, resolve: (value: unknown) => void) {
          Object.defineProperty(proto, 'then', {
            configurable: true,
            writable: true,
            value: ownThen
          })
          ownThen.call(
            this,
            () => undefined,
            () => undefined
          )
          resolve(forgedValue)
        }
      })
      return function NotPromise() {}
    }
  })
}

/** What the tracer was handed back by the callback it called, so a row can look at the promise the host's SDK receives. */
const handed: unknown[] = []

jest.mock('@opentelemetry/api', () => ({
  trace: {
    getTracer: () => ({
      startActiveSpan: (...args: unknown[]) => {
        const callback = args[args.length - 1] as (span: unknown) => unknown
        const returned = callback({
          setStatus: () => undefined,
          end: () => {
            plant('FORGED')
          }
        })
        handed.push(returned)
        return returned
      }
    })
  }
}))

afterEach(() => {
  Object.defineProperty(Promise.prototype, 'constructor', ownConstructor)
  Object.defineProperty(Promise.prototype, 'then', {
    value: ownThen,
    writable: true,
    configurable: true
  })
})

describe('a tracer that plants an accessor after the decision', () => {
  // Scenario: `span.end()` plants the accessor and the operation answered `real`. Expected: the host's await never yields the
  // forged value: it gets the answer or the guard's refusal (C5).
  it('never answers the forged value', async () => {
    const tracing = new AuthTracing()
    await tracing.onModuleInit()

    let answer: unknown
    try {
      answer = await tracing.span('auth.login' as never, {}, () => Promise.resolve('real'))
    } catch (error) {
      answer = error
    }

    expect(answer).not.toBe('FORGED')
    expect(answer === 'real' || isRefusal(answer)).toBe(true)
  })

  // Scenario: the tracer is handed the promise of the operation. Expected: it carries the language's constructor as a permanent own
  // data property, so the `await` or `then` of the host's SDK reads nothing a plant can answer for (C5, "give the host a mirror").
  it('hands the tracer a pinned promise', async () => {
    handed.length = 0
    const tracing = new AuthTracing()
    await tracing.onModuleInit()
    try {
      await tracing.span('auth.login' as never, {}, () => Promise.resolve('real'))
    } catch {
      // The plant made the check refuse; what was handed to the tracer is what is asserted.
    }

    const own = Object.getOwnPropertyDescriptor(handed[0], 'constructor')
    expect(own).toMatchObject({ writable: false, configurable: false, value: Promise })
  })
})
