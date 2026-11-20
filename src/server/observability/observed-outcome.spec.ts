/**
 * @fileoverview A refusal is told apart in a side table, and nothing a caller receives changes.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { observed, observedRefusal } from './observed-outcome'

describe('observed refusal', () => {
  // Scenario: an exception marked as reuse. Expected: the same object comes back, readable as that kind, and
  // its body, status and code are exactly those of an unmarked one.
  it('marks an exception without changing what the caller receives', () => {
    const plain = new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    const marked = observed(
      'reuse_detected',
      new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)
    )

    expect(observedRefusal(marked)).toBe('reuse_detected')
    expect(marked.getResponse()).toStrictEqual(plain.getResponse())
    expect(marked.getStatus()).toBe(plain.getStatus())
    expect(Object.keys(marked)).toEqual(Object.keys(plain))
  })

  // Scenario: an unmarked exception, and values that are not objects. Expected: no kind.
  it.each([
    ['an unmarked exception', new AuthException(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID)],
    ['a string', 'reuse_detected'],
    ['null', null],
    ['undefined', undefined]
  ])('reads no kind from %s', (_case, value) => {
    expect(observedRefusal(value)).toBeUndefined()
  })
})
