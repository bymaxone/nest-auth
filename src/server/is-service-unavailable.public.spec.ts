/**
 * @fileoverview `isServiceUnavailable` is part of the public API of the server subpath: a host
 * filter or client that wants to treat the library's `503 auth.service_unavailable` differently from
 * every other `AuthException` imports it from the package entry, not from an internal path.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES, AuthException, isServiceUnavailable } from './index'

describe('isServiceUnavailable as the package exports it', () => {
  // Scenario: the library's own 503, as a host filter receives it. Expected: recognised, and
  // narrowed to AuthException so the code can be read without a cast.
  it('recognises the typed 503 and narrows it to AuthException', () => {
    const error: unknown = new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE)

    if (!isServiceUnavailable(error)) throw new Error('the 503 was not recognised')

    expect(error.getStatus()).toBe(503)
  })

  // Scenario: other AuthExceptions and values that are not one. Expected: not the 503.
  it.each([
    ['another AuthException', new AuthException(AUTH_ERROR_CODES.INTERNAL)],
    ['a plain Error', new Error('Command timed out')],
    ['a string', 'auth.service_unavailable'],
    ['null', null],
    ['undefined', undefined]
  ])('does not take %s for the 503', (_name, value) => {
    expect(isServiceUnavailable(value)).toBe(false)
  })

  // Scenario: an AuthException whose cause is the store's error, as the library throws it.
  // Expected: the 503; the cause does not matter.
  it('recognises the 503 when it carries a cause', () => {
    const error = new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE, undefined, {
      cause: new Error('connection lost')
    })

    expect(isServiceUnavailable(error)).toBe(true)
  })
})
