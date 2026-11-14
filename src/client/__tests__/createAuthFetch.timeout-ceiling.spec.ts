/**
 * The `timeout` option of `createAuthFetch` reaches `setTimeout`, which gives any delay it cannot
 * honor (`NaN`, `Infinity`, above 2147483647) a 1 ms deadline: every request would be aborted.
 * The wrapper refuses such a value when it is created.
 */

import { createAuthClient } from '../createAuthClient'
import { createAuthFetch } from '../createAuthFetch'

const REFUSED = /timeout must be a number of milliseconds from 0 to 2147483647/

/** A value a JavaScript caller can pass although the option is typed as a number. */
const NOT_A_NUMBER: unknown = '5000'

describe('createAuthFetch timeout ceiling', () => {
  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['one above the ceiling', 2_147_483_648],
    ['negative', -1],
    ['a string', NOT_A_NUMBER as number]
  ])('refuses %s', (_label, timeout) => {
    expect(() => createAuthFetch({ timeout })).toThrow(new RegExp(REFUSED))
    expect(() => createAuthFetch({ timeout })).toThrow(TypeError)
  })

  it.each([
    ['zero, which disables it', 0],
    ['a fraction', 0.5],
    ['the ceiling itself', 2_147_483_647]
  ])('accepts %s', (_label, timeout) => {
    expect(() => createAuthFetch({ timeout })).not.toThrow()
  })

  it('refuses a bad timeout given to the client that builds the wrapper', () => {
    expect(() => createAuthClient({ baseUrl: 'http://localhost', timeout: Number.NaN })).toThrow(
      REFUSED
    )
  })
})
