/**
 * @fileoverview The readiness probe is bounded: it gives up after its own timeout, under the health
 * aggregator's, or when the caller's signal aborts, and probes that arrive while a `PING` is pending share it.
 *
 * @layer Test
 */

import { AuthHealthProbe, PING_TIMEOUT_MS } from './auth-health-probe'

/** A promise that settles when the test says so. */
function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (error: Error) => void
} {
  let resolve: (value: T) => void = () => undefined
  let reject: (error: Error) => void = () => undefined
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('AuthHealthProbe', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  // Scenario: the answer is PONG, and anything else. Expected: true and false.
  it('answers true for PONG and false for any other answer', async () => {
    const answers = ['PONG', 'LOADING', '']
    const probe = new AuthHealthProbe({ ping: () => Promise.resolve(answers.shift() ?? '') })

    await expect(probe.ping()).resolves.toBe(true)
    await expect(probe.ping()).resolves.toBe(false)
    await expect(probe.ping()).resolves.toBe(false)
  })

  // Scenario: the store never answers. Expected: the probe rejects on its own, after the timeout it asked for,
  // which is under the aggregator's default of five seconds. Why: a stalled socket must not hold a readiness
  // check open.
  it('gives up on a store that never answers, after a timeout under the aggregator’s', async () => {
    const real = AbortSignal.timeout.bind(AbortSignal)
    const requested: number[] = []
    jest.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
      requested.push(ms)
      return real(10)
    })
    const probe = new AuthHealthProbe({ ping: () => new Promise<string>(() => undefined) })

    await expect(probe.ping()).rejects.toThrow('did not answer in time')

    expect(requested).toEqual([PING_TIMEOUT_MS])
    expect(PING_TIMEOUT_MS).toBeLessThan(5000)
  })

  // Scenario: the caller's signal aborts while the store has not answered, and one that was aborted before the
  // call. Expected: both reject at once with the same refusal, without waiting for the timeout.
  it('rejects when the caller’s signal aborts, or already has', async () => {
    const probe = new AuthHealthProbe({ ping: () => new Promise<string>(() => undefined) })
    const controller = new AbortController()

    const waiting = probe.ping(controller.signal)
    controller.abort()
    await expect(waiting).rejects.toThrow('did not answer in time')
    await expect(probe.ping(AbortSignal.abort())).rejects.toThrow('did not answer in time')
  })

  // Scenario: the caller gives up while the store has not answered, and the store then answers or fails.
  // Expected: both continuations the probe attached to the store's promise handle a rejection, so neither
  // ending is left unhandled, and the next probe asks the store afresh and is answered.
  it.each([
    ['answers', (late: ReturnType<typeof deferred<string>>) => late.resolve('PONG')],
    ['fails', (late: ReturnType<typeof deferred<string>>) => late.reject(new Error('ECONNRESET'))]
  ])('handles the store ending after the wait when it %s', async (_case, settle) => {
    const unhandled: unknown[] = []
    const listener = (reason: unknown): void => {
      unhandled.push(reason)
    }
    process.on('unhandledRejection', listener)
    const late = deferred<string>()
    const attached = jest.spyOn(late.promise, 'then')
    const asked = jest
      .fn<Promise<string>, []>()
      .mockReturnValueOnce(late.promise)
      .mockResolvedValue('PONG')
    const probe = new AuthHealthProbe({ ping: asked })
    const controller = new AbortController()

    const waiting = probe.ping(controller.signal)
    controller.abort()
    await expect(waiting).rejects.toThrow('did not answer in time')
    settle(late)
    await new Promise((resolve) => setImmediate(resolve))
    process.off('unhandledRejection', listener)

    // The probe's own bookkeeping and the wait for the caller are awaits, never `.then` chains: the promise is never asked for
    // its `then`, and the late ending is heard.
    expect(attached).not.toHaveBeenCalled()
    expect(unhandled).toEqual([])
    // The late ending leaves the next probe to ask the store afresh and get its answer.
    await expect(probe.ping()).resolves.toBe(true)
    expect(asked).toHaveBeenCalledTimes(2)
  })

  // Scenario: several probes arrive while one PING is pending, then it settles and another probe arrives.
  // Expected: one PING for the first group, a new one afterwards, and a failed PING is not kept.
  it('shares a pending PING and asks again once it has settled', async () => {
    const first = deferred<string>()
    const asked = jest
      .fn<Promise<string>, []>()
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce('PONG')
      .mockRejectedValueOnce(new Error('READONLY'))
      .mockResolvedValueOnce('PONG')
    const probe = new AuthHealthProbe({ ping: asked })

    const group = [probe.ping(), probe.ping(), probe.ping()]
    expect(asked).toHaveBeenCalledTimes(1)
    first.resolve('PONG')
    await expect(Promise.all(group)).resolves.toEqual([true, true, true])

    await expect(probe.ping()).resolves.toBe(true)
    await expect(probe.ping()).rejects.toThrow('READONLY')
    await expect(probe.ping()).resolves.toBe(true)
    expect(asked).toHaveBeenCalledTimes(4)
  })

  // Scenario: a store that never answers, probed many times. Expected: the client is asked once, not once
  // per probe. Why: the stalled socket must not collect a PING for every readiness request.
  it('asks a stalled store once however many probes arrive', async () => {
    const asked = jest.fn(() => new Promise<string>(() => undefined))
    const probe = new AuthHealthProbe({ ping: asked })

    const probes = Array.from({ length: 20 }, () => probe.ping(AbortSignal.timeout(5)))
    await Promise.allSettled(probes)

    expect(asked).toHaveBeenCalledTimes(1)
  })

  // Scenario: a PING that the client never settles, then the store recovers. Expected: while the stuck PING is
  // younger than the timeout it is shared; once it has outlived the timeout the next probe sends a fresh PING
  // and is up, and the stuck one settling late does not discard the fresh one. Why: a dead promise reused for
  // ever would keep readiness down after the store came back.
  it('recovers after a PING that never settles', async () => {
    let now = 1_000_000
    jest.spyOn(performance, 'now').mockImplementation(() => now)
    // The wall clock steps backward by a minute; the age of a pending PING does not follow it.
    jest.spyOn(Date, 'now').mockImplementation(() => 5_000_000 - now)
    const stuck = deferred<string>()
    const fresh = deferred<string>()
    const asked = jest
      .fn<Promise<string>, []>()
      .mockReturnValueOnce(stuck.promise)
      .mockReturnValueOnce(fresh.promise)
      .mockResolvedValue('PONG')
    const probe = new AuthHealthProbe({ ping: asked })

    await expect(probe.ping(AbortSignal.abort())).rejects.toThrow('did not answer in time')
    now += PING_TIMEOUT_MS - 1
    await expect(probe.ping(AbortSignal.abort())).rejects.toThrow('did not answer in time')
    expect(asked).toHaveBeenCalledTimes(1)

    now += 1
    const recovered = probe.ping()
    expect(asked).toHaveBeenCalledTimes(2)
    stuck.resolve('LOADING')
    await Promise.resolve()
    const sharedWithFresh = probe.ping()
    expect(asked).toHaveBeenCalledTimes(2)
    fresh.resolve('PONG')

    await expect(recovered).resolves.toBe(true)
    await expect(sharedWithFresh).resolves.toBe(true)
  })

  // Scenario: the wait is bounded by an abort signal, and the store answers. Expected: the probe listens for
  // the abort once, and takes the listener off when the answer arrives. Why: a signal that outlives the probe
  // must not collect a listener per probe.
  it('listens for the abort once and removes the listener when the store answers', async () => {
    const bound = new AbortController().signal
    const add = jest.spyOn(bound, 'addEventListener')
    const remove = jest.spyOn(bound, 'removeEventListener')
    jest.spyOn(AbortSignal, 'any').mockReturnValue(bound)
    const probe = new AuthHealthProbe({ ping: () => Promise.resolve('PONG') })

    await expect(probe.ping(new AbortController().signal)).resolves.toBe(true)
    await Promise.resolve()

    expect(add).toHaveBeenCalledWith('abort', expect.any(Function), { once: true })
    const listener = add.mock.calls[0]?.[1]
    expect(remove).toHaveBeenCalledWith('abort', listener)
  })

  // Scenario: the client throws instead of returning a promise. Expected: the probe rejects with it.
  it('rejects with what a throwing client throws', async () => {
    const probe = new AuthHealthProbe({
      ping: () => {
        throw new Error('not connected')
      }
    })

    await expect(probe.ping()).rejects.toThrow('not connected')
  })
})
