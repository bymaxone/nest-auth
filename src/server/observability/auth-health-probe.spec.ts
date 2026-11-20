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

  // Scenario: the store answers after the caller gave up, and rejects after the caller gave up. Expected: no
  // unhandled rejection reaches the process.
  it('leaves no unhandled rejection when the store answers or fails after the wait ended', async () => {
    const unhandled = jest.fn()
    process.on('unhandledRejection', unhandled)
    const late = deferred<string>()
    const probe = new AuthHealthProbe({ ping: () => late.promise })

    await expect(probe.ping(AbortSignal.abort())).rejects.toThrow('did not answer in time')
    late.reject(new Error('ECONNRESET'))
    await new Promise((resolve) => setImmediate(resolve))
    process.off('unhandledRejection', unhandled)

    expect(unhandled).not.toHaveBeenCalled()
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
    jest.spyOn(Date, 'now').mockImplementation(() => now)
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
