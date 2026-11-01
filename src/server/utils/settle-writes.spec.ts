/**
 * @fileoverview Tests for settleWrites and raiseFirst, which run a revocation's writes to
 * completion and raise the first failure afterwards.
 */

import { raiseFirst, settleWrites } from './settle-writes'

const FIRST = new Error('first refusal')
const SECOND = new Error('second refusal')

describe('settleWrites', () => {
  // Scenario: every write succeeds. Expected: no failures, and each write ran once, in order.
  it('should run every write in order and report no failure when all succeed', async () => {
    const order: string[] = []

    const failures = await settleWrites([
      async () => void order.push('a'),
      async () => void order.push('b')
    ])

    expect(failures).toEqual([])
    expect(order).toEqual(['a', 'b'])
  })

  // Scenario: a write fails in the middle. Expected: the writes after it still run, and the error
  // is reported. Why: stopping there would leave the later writes, and the access they revoke, undone.
  it('should keep going after a failing write and report its error', async () => {
    const later = jest.fn().mockResolvedValue(undefined)

    const failures = await settleWrites([
      async () => undefined,
      async () => Promise.reject(FIRST),
      later
    ])

    expect(failures).toEqual([FIRST])
    expect(later).toHaveBeenCalledTimes(1)
  })

  // Scenario: several writes fail. Expected: the errors come back in the order the writes ran.
  it('should report every failure in the order the writes ran', async () => {
    const failures = await settleWrites([
      async () => Promise.reject(FIRST),
      async () => Promise.reject(SECOND)
    ])

    expect(failures).toEqual([FIRST, SECOND])
  })

  // Scenario: a write has not settled. Expected: the next one does not start until it has.
  it('should start a write only after the previous one has settled', async () => {
    const events: string[] = []
    let release: () => void = () => undefined
    const slow = new Promise<void>((resolve) => {
      release = resolve
    })

    const pending = settleWrites([
      async () => {
        events.push('slow-start')
        await slow
        events.push('slow-end')
      },
      async () => void events.push('next')
    ])
    await Promise.resolve()
    expect(events).toEqual(['slow-start'])
    release()
    await pending

    expect(events).toEqual(['slow-start', 'slow-end', 'next'])
  })

  // Scenario: no writes. Expected: no failures.
  it('should report no failure for an empty list', async () => {
    await expect(settleWrites([])).resolves.toEqual([])
  })
})

describe('raiseFirst', () => {
  // Scenario: nothing failed. Expected: returns normally.
  it('should do nothing for an empty list', () => {
    expect(() => raiseFirst([])).not.toThrow()
  })

  // Scenario: more than one failure. Expected: the first is the one raised, as itself.
  it('should raise the first failure unchanged', () => {
    expect(() => raiseFirst([FIRST, SECOND])).toThrow(FIRST)
  })

  // Scenario: the first failure is a falsy value (a rejection with undefined). Expected: it is still
  // raised. Why: the list's length decides, not the value, or such a rejection would pass as success.
  it('should raise a failure even when the rejection value is falsy', () => {
    let thrown: unknown = 'not thrown'
    try {
      raiseFirst([undefined])
    } catch (err) {
      thrown = err
    }

    expect(thrown).toBeUndefined()
  })
})
