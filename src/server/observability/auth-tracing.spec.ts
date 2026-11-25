/**
 * @fileoverview The span seam runs the operation exactly once, whatever the tracer does, and reports only
 * the library error code on failure.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthTracing } from './auth-tracing'

interface FakeSpan {
  setStatus: jest.Mock
  end: jest.Mock
}

type StartActiveSpan = (
  name: string,
  options: { attributes: Record<string, string> },
  fn: (span: FakeSpan) => unknown
) => unknown

/** What the fake tracer does when a span is started; each case sets it. */
let startActiveSpan: StartActiveSpan

/** The names the seam asked the API for a tracer under. */
const mockTracerNames: string[] = []

jest.mock('@opentelemetry/api', () => ({
  trace: {
    getTracer: (name: string) => {
      mockTracerNames.push(name)
      return {
        startActiveSpan: (...args: unknown[]) =>
          startActiveSpan(...(args as Parameters<StartActiveSpan>))
      }
    }
  }
}))

/** A span whose calls are recorded. */
function span(): FakeSpan {
  return { setStatus: jest.fn(), end: jest.fn() }
}

/** A seam that has loaded the (fake) API. */
async function loaded(): Promise<AuthTracing> {
  const tracing = new AuthTracing()
  await tracing.onModuleInit()
  return tracing
}

describe('AuthTracing', () => {
  beforeEach(() => {
    const live = span()
    startActiveSpan = (_name, _options, fn) => fn(live)
  })

  // Scenario: the seam never loaded the API. Expected: the operation runs bare and its result passes through.
  it('runs the operation bare before the API is loaded', async () => {
    const run = jest.fn(() => Promise.resolve('done'))

    await expect(new AuthTracing().span('auth.login', {}, run)).resolves.toBe('done')

    expect(run).toHaveBeenCalledTimes(1)
  })

  // Scenario: the API is loaded. Expected: the named span starts with the attributes given, ends once, and
  // the result passes through.
  it('starts the named span with its attributes and ends it', async () => {
    const live = span()
    const seen: Array<[string, Record<string, string>]> = []
    startActiveSpan = (name, options, fn) => {
      seen.push([name, options.attributes])
      return fn(live)
    }

    const result = await (
      await loaded()
    ).span('auth.refresh', { 'bymax.auth.plane': 'platform' }, () => Promise.resolve('rotated'))

    expect(result).toBe('rotated')
    expect(seen).toEqual([['auth.refresh', { 'bymax.auth.plane': 'platform' }]])
    expect(mockTracerNames).toContain('@bymax-one/nest-auth')
    expect(live.end).toHaveBeenCalledTimes(1)
    expect(live.setStatus).not.toHaveBeenCalled()
  })

  // Scenario: the operation fails with a library error whose message holds a sentinel. Expected: the error
  // is rethrown unchanged, the span ends with status ERROR carrying the code and nothing of the message.
  it('marks the span failed with the library code only', async () => {
    const live = span()
    startActiveSpan = (_name, _options, fn) => fn(live)
    const failure = new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS, {
      note: 'SENTINEL-4242'
    })

    await expect(
      (await loaded()).span('auth.login', {}, () => Promise.reject(failure))
    ).rejects.toBe(failure)

    expect(live.setStatus).toHaveBeenCalledWith({ code: 2, message: 'auth.invalid_credentials' })
    expect(JSON.stringify(live.setStatus.mock.calls)).not.toContain('SENTINEL-4242')
    expect(live.end).toHaveBeenCalledTimes(1)
  })

  // Scenario: the operation fails with something that is not a library error, and with a library error whose
  // code is not shaped like one. Expected: a generic code, never the text.
  it.each([
    ['a plain error', new Error('SENTINEL-4242 secret@example.com')],
    ['a thrown string', 'SENTINEL-4242'],
    ['an unshaped code', new AuthException('Auth.Weird Code' as never)],
    ['a code with a prefix', new AuthException('x.auth.foo' as never)],
    ['a code with a suffix', new AuthException('auth.foo.bar' as never)]
  ])('reports a generic code for %s', async (_case, failure) => {
    const live = span()
    startActiveSpan = (_name, _options, fn) => fn(live)

    await expect(
      (await loaded()).span('auth.mfa.verify', {}, () => Promise.reject(failure))
    ).rejects.toBe(failure)

    expect(live.setStatus).toHaveBeenCalledWith({ code: 2, message: 'auth.error' })
  })

  // Scenario: the tracer throws before it runs the callback. Expected: the operation runs once, bare.
  it('runs the operation once when the tracer throws', async () => {
    startActiveSpan = () => {
      throw new Error('tracer broke')
    }
    const run = jest.fn(() => Promise.resolve('bare'))

    await expect((await loaded()).span('auth.login', {}, run)).resolves.toBe('bare')

    expect(run).toHaveBeenCalledTimes(1)
  })

  // Scenario: the tracer never calls the callback. Expected: the operation still runs once.
  it('runs the operation once when the tracer never calls back', async () => {
    startActiveSpan = () => undefined
    const run = jest.fn(() => Promise.resolve('bare'))

    await expect((await loaded()).span('auth.login', {}, run)).resolves.toBe('bare')

    expect(run).toHaveBeenCalledTimes(1)
  })

  // Scenario: the tracer calls the callback twice. Expected: the operation runs once.
  it('runs the operation once when the tracer calls back twice', async () => {
    const live = span()
    startActiveSpan = (_name, _options, fn) => {
      fn(live)
      return fn(live)
    }
    const run = jest.fn(() => Promise.resolve('once'))

    await expect((await loaded()).span('auth.login', {}, run)).resolves.toBe('once')

    expect(run).toHaveBeenCalledTimes(1)
  })

  // Scenario: the tracer calls the callback only after the operation already ran bare. Expected: it does not
  // run a second time.
  it('runs the operation once when the tracer calls back late', async () => {
    const live = span()
    let late: (() => unknown) | undefined
    startActiveSpan = (_name, _options, fn) => {
      late = () => fn(live)
      return undefined
    }
    const run = jest.fn(() => Promise.resolve('once'))

    await expect((await loaded()).span('auth.login', {}, run)).resolves.toBe('once')
    late?.()
    await Promise.resolve()

    expect(run).toHaveBeenCalledTimes(1)
  })

  // Scenario: the span's own calls throw and reject. Expected: the operation's result and error are unchanged.
  it('ignores a span that throws or rejects', async () => {
    const live: FakeSpan = {
      setStatus: jest.fn(() => {
        throw new Error('setStatus broke')
      }),
      end: jest.fn(() => Promise.reject(new Error('end rejected')))
    }
    startActiveSpan = (_name, _options, fn) => fn(live)
    const failure = new Error('operation failed')
    const tracing = await loaded()

    await expect(tracing.span('auth.login', {}, () => Promise.reject(failure))).rejects.toBe(
      failure
    )
    await expect(tracing.span('auth.login', {}, () => Promise.resolve(7))).resolves.toBe(7)
  })
})

describe('AuthTracing and the promise handed to a tracer that never looks at it', () => {
  // Scenario: the operation fails and the tracer drops the promise it was handed without attaching a handler. Expected: the failure
  // reaches the caller and the process reports no unhandled rejection. Why: the promise handed to the tracer is a copy of the
  // operation's own outcome that nothing in the library waits on, so only the mark made when it was built keeps its rejection heard.
  it('leaves no rejection unhandled', async () => {
    startActiveSpan = (_name, _options, fn) => {
      fn(span())
    }
    const failure = new Error('the operation failed')
    const tracing = await loaded()
    const reported: unknown[] = []
    const listener = (reason: unknown): void => {
      reported.push(reason)
    }
    process.on('unhandledRejection', listener)
    let thrown: unknown
    try {
      thrown = await tracing
        .span('auth.login', {}, () => Promise.reject(failure))
        .catch((error: unknown) => error)
      await new Promise((done) => setImmediate(done))
      await new Promise((done) => setImmediate(done))
    } finally {
      process.off('unhandledRejection', listener)
    }

    expect(thrown).toBe(failure)
    expect(reported).toEqual([])
  })
})
