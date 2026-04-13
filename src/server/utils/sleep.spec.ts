import { sleep } from './sleep'

describe('sleep', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  // Verifies that the promise resolves after the specified number of milliseconds when fake timers advance.
  it('should resolve after the specified delay', async () => {
    const promise = sleep(200)
    jest.advanceTimersByTime(200)
    await expect(promise).resolves.toBeUndefined()
  })

  // Verifies that a zero-millisecond delay resolves immediately without advancing timers.
  it('should resolve immediately for 0 ms', async () => {
    const promise = sleep(0)
    jest.advanceTimersByTime(0)
    await expect(promise).resolves.toBeUndefined()
  })

  // Verifies that negative millisecond values are clamped to 0 and the promise resolves immediately.
  it('should resolve immediately for negative values (clamped to 0)', async () => {
    const promise = sleep(-100)
    jest.advanceTimersByTime(0)
    await expect(promise).resolves.toBeUndefined()
  })

  // Verifies that values larger than MAX_SLEEP_MS (10_000) are capped so the promise resolves at 10_000 ms.
  it('should cap at MAX_SLEEP_MS (10_000) for values above the limit', async () => {
    const promise = sleep(99_999)
    // Should resolve at 10_000 ms, not 99_999 ms
    jest.advanceTimersByTime(10_000)
    await expect(promise).resolves.toBeUndefined()
  })

  // Verifies that sleep always returns a Promise instance regardless of the input value.
  it('should return a Promise', () => {
    const result = sleep(1)
    expect(result).toBeInstanceOf(Promise)
    // Advance timers to prevent test leakage
    jest.advanceTimersByTime(1)
  })
})
