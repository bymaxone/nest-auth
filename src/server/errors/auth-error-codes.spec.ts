/**
 * Unit tests for the auth error-code catalogue.
 *
 * Layer: unit.
 * Goal: guarantee every error code ships a non-empty default message and that
 *   the message map and code map stay in sync. Message *text* is intentionally
 *   not pinned — it is end-user-facing Portuguese that consumers may override
 *   via i18n — but every code must resolve to a usable, non-empty string.
 * Mocks: none (pure constants).
 */

import { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES } from './auth-error-codes'

describe('AUTH_ERROR_MESSAGES', () => {
  /**
   * Every error code has a non-empty default message.
   *
   * `AuthException` looks up this map to populate the user-facing `message`
   * field. A blank entry would surface an empty error to end users, so each
   * value must be a non-empty string. This also pins every message against a
   * regression that blanks it out, without coupling tests to the exact wording.
   */
  it.each(Object.entries(AUTH_ERROR_MESSAGES))(
    'has a non-empty default message for %s',
    (_code, message) => {
      expect(typeof message).toBe('string')
      expect(message.trim().length).toBeGreaterThan(0)
    }
  )

  /**
   * The message catalogue covers exactly the declared error codes.
   *
   * A code without a message would fall back to an empty/undefined string at
   * runtime; a message without a code is dead data. Keeping the two maps in
   * one-to-one correspondence prevents both.
   */
  it('defines a message for every declared error code and no extras', () => {
    const codeValues = Object.values(AUTH_ERROR_CODES).sort()
    const messageKeys = Object.keys(AUTH_ERROR_MESSAGES).sort()

    expect(messageKeys).toEqual(codeValues)
  })
})
