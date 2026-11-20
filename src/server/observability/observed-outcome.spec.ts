/**
 * @fileoverview A refusal is told apart in a side table, and nothing a caller receives changes.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { markedPlane, markingPlane, observed, observedRefusal, onPlane } from './observed-outcome'

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

describe('the plane of a refusal', () => {
  // Scenario: an exception marked with a plane. Expected: the same object, readable as that plane, with the
  // body, status and own keys of an unmarked one.
  it('marks an exception without changing what the caller receives', () => {
    const plain = new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)
    const marked = onPlane('platform', new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE))

    expect(markedPlane(marked)).toBe('platform')
    expect(marked.getResponse()).toStrictEqual(plain.getResponse())
    expect(marked.getStatus()).toBe(plain.getStatus())
    expect(Object.keys(marked)).toEqual(Object.keys(plain))
  })

  it.each([
    ['an unmarked exception', new AuthException(AUTH_ERROR_CODES.MFA_INVALID_CODE)],
    ['a string', 'platform'],
    ['null', null],
    ['undefined', undefined]
  ])('reads no plane from %s', (_case, value) => {
    expect(markedPlane(value)).toBeUndefined()
  })

  // Scenario: a flow run under a plane that returns, throws an exception, and throws something that is not
  // one. Expected: the result passes through, the exception is the same object carrying the plane, and a
  // thrown string is rethrown as it is.
  it('marks what a flow throws and lets everything else through', async () => {
    const failure = new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED)

    await expect(markingPlane('dashboard', () => Promise.resolve(7))).resolves.toBe(7)
    await expect(markingPlane('platform', () => Promise.reject(failure))).rejects.toBe(failure)
    expect(markedPlane(failure)).toBe('platform')
    await expect(markingPlane('platform', () => Promise.reject('plain'))).rejects.toBe('plain')
  })
})
