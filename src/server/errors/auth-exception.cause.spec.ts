/**
 * @fileoverview The optional `cause` of `AuthException`: kept on the exception for a host's
 * logger, never serialized into the body.
 */

import { AUTH_ERROR_CODES } from './auth-error-codes'
import { AuthException } from './auth-exception'

describe('AuthException cause', () => {
  // Scenario: an exception built with the error it reports. Expected: `cause` is that error and the
  // body is exactly what it would be without it.
  it('keeps the cause off the body', () => {
    const cause = new Error('Command timed out')

    const withCause = new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE, undefined, { cause })
    const without = new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE)

    expect(withCause.cause).toBe(cause)
    expect(withCause.getResponse()).toEqual(without.getResponse())
    expect(withCause.getStatus()).toBe(503)
  })

  // Scenario: no options, and options with no cause. Expected: no `cause` property at all.
  it('has no cause unless one is given', () => {
    expect(new AuthException(AUTH_ERROR_CODES.INTERNAL).cause).toBeUndefined()
    expect(new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, {}).cause).toBeUndefined()
  })
})
