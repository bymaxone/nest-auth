/**
 * Unit tests — assertNotBlocked
 *
 * Verifies the account-status gate shared by the dashboard and platform credential
 * flows. The gate is what stops a suspended, inactive, or banned account from
 * authenticating with an otherwise-valid password, so every branch is pinned here:
 * the pass-through, each status-to-code mapping, the unmapped fallback, and the
 * case-insensitivity on BOTH sides of the comparison.
 *
 * Pure-function tests — no mocks, no async, no I/O.
 */

import { AuthException } from '../errors/auth-exception'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { assertNotBlocked } from './assert-not-blocked'

/** Default blocked set shipped by the module, in its canonical uppercase form. */
const DEFAULT_BLOCKED = ['BANNED', 'INACTIVE', 'SUSPENDED']

/**
 * Runs the gate and returns the thrown exception's wire code and HTTP status, so a
 * test asserts what the caller actually receives rather than the internal mapping.
 */
function captureRejection(status: string, blocked: readonly string[]) {
  try {
    assertNotBlocked(status, blocked)
  } catch (error) {
    const exception = error as AuthException
    const body = exception.getResponse() as { error: { code: string } }
    return { code: body.error.code, statusCode: exception.getStatus() }
  }

  throw new Error(`expected assertNotBlocked to reject status "${status}"`)
}

describe('assertNotBlocked', () => {
  // Verifies the pass-through: an active account is the overwhelmingly common case and
  // must not throw, otherwise every login would fail closed.
  it('returns without throwing when the status is not blocked', () => {
    expect(() => assertNotBlocked('active', DEFAULT_BLOCKED)).not.toThrow()
  })

  // Verifies an empty blocked list disables the gate entirely rather than blocking
  // everything — a consumer may legitimately configure `blockedStatuses: []`.
  it('never throws when no statuses are configured as blocked', () => {
    expect(() => assertNotBlocked('suspended', [])).not.toThrow()
  })

  // Verifies the gate rejects with AuthException (not a bare Error), so the controller
  // layer serializes it into the standard auth error envelope.
  it('throws an AuthException for a blocked status', () => {
    expect(() => assertNotBlocked('SUSPENDED', DEFAULT_BLOCKED)).toThrow(AuthException)
  })

  // Verifies the HTTP status is 403 and not the AuthException default of 401: the caller
  // proved nothing about credentials, the account itself is refused.
  it('rejects with HTTP 403 rather than the 401 default', () => {
    expect(captureRejection('SUSPENDED', DEFAULT_BLOCKED).statusCode).toBe(403)
  })

  // Verifies each documented status maps to its own error code, so the caller learns why
  // the account was refused instead of receiving one opaque rejection for every state.
  it.each([
    ['banned', AUTH_ERROR_CODES.ACCOUNT_BANNED],
    ['inactive', AUTH_ERROR_CODES.ACCOUNT_INACTIVE],
    ['suspended', AUTH_ERROR_CODES.ACCOUNT_SUSPENDED],
    ['pending', AUTH_ERROR_CODES.PENDING_APPROVAL],
    ['pending_approval', AUTH_ERROR_CODES.PENDING_APPROVAL]
  ])('maps the %s status to its specific error code', (status, expectedCode) => {
    expect(captureRejection(status, [status]).code).toBe(expectedCode)
  })

  // Verifies an application-defined status that is configured as blocked but absent from
  // the mapping still rejects, falling back to ACCOUNT_INACTIVE instead of leaking through.
  it('falls back to ACCOUNT_INACTIVE for a blocked status with no specific code', () => {
    expect(captureRejection('archived', ['archived']).code).toBe(AUTH_ERROR_CODES.ACCOUNT_INACTIVE)
  })

  // Verifies the status side is lowercased before comparison: a consumer persisting
  // 'Suspended' must still be blocked by the uppercase default configuration.
  it('blocks a mixed-case status against the uppercase default configuration', () => {
    expect(() => assertNotBlocked('Suspended', DEFAULT_BLOCKED)).toThrow(AuthException)
  })

  // Verifies the configured side is lowercased too. Without it, a consumer configuring
  // lowercase statuses against uppercase-persisted values would silently admit blocked
  // accounts — the gate would pass and the login would succeed.
  it('blocks an uppercase status against a lowercase configuration', () => {
    expect(() => assertNotBlocked('BANNED', ['banned'])).toThrow(AuthException)
  })

  // Verifies matching is exact rather than substring-based: a status that merely contains
  // a blocked value ('reinstated' vs 'inactive') must authenticate normally.
  it('does not block a status that is not an exact match', () => {
    expect(() => assertNotBlocked('active_pending_review', DEFAULT_BLOCKED)).not.toThrow()
  })

  // Verifies the status-to-code lookup cannot resolve an inherited member. The status is
  // application-defined data, so a plain-object lookup would return a truthy prototype
  // member for 'constructor' or 'toString', defeating the `??` fallback and handing
  // AuthException a function instead of an error code. Each must reject with the
  // documented fallback code.
  it.each(['constructor', 'toString', 'hasOwnProperty', '__proto__'])(
    'falls back to ACCOUNT_INACTIVE for the inherited key %s',
    (pollutedStatus) => {
      expect(captureRejection(pollutedStatus, [pollutedStatus]).code).toBe(
        AUTH_ERROR_CODES.ACCOUNT_INACTIVE
      )
    }
  )
})
