/**
 * @fileoverview The time of a real date is the time the date holds, not what a subclass says it is: an override of
 * `getTime` on an object that is a date would let the host name a deadline other than the one the date carries.
 *
 * @layer Test
 */

import { apiKeyRecord, userRecord } from './__tests__/host-records'
import { copyHostRecord } from './host-read'
import { API_KEY_REPOSITORY_CONTRACT, USER_REPOSITORY_CONTRACT } from './repository-contracts'

const KEY = API_KEY_REPOSITORY_CONTRACT.findById
const USER = USER_REPOSITORY_CONTRACT.findById

/** A real date whose `getTime` answers `answer` instead of its time. */
const lying = (time: number, answer: unknown): Date => {
  class Lying extends Date {
    override getTime(): number {
      return answer as number
    }
  }
  return new Lying(time)
}

describe('the time of a real date', () => {
  // Scenario: a real date of 1000 whose subclass answers 5, and one that answers NaN, as a deadline (a strict date) and
  // as a last login (a date that only informs). Expected: each copy holds 1000, the time of the date. Why: the slot of a
  // real date is the time it holds, and a method a subclass overrides is the host's word, not the date's.
  it.each([
    ['a different time', 5],
    ['a NaN', Number.NaN]
  ])('copies the time a real date holds when its getTime answers %s', (_name, answer) => {
    const deadline = copyHostRecord(apiKeyRecord({ expiresAt: lying(1000, answer) }), KEY) as {
      expiresAt: Date
    }
    const login = copyHostRecord(userRecord({ lastLoginAt: lying(1000, answer) }), USER) as {
      lastLoginAt: Date
    }

    expect(deadline.expiresAt.getTime()).toBe(1000)
    expect(login.lastLoginAt.getTime()).toBe(1000)
  })
})
