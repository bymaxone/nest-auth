import { HttpException, HttpStatus } from '@nestjs/common'

import { AUTH_ERROR_CODES, AUTH_ERROR_MESSAGES } from './auth-error-codes'
import type { AuthErrorCode } from './auth-error-codes'
import { AuthException } from './auth-exception'

// ---------------------------------------------------------------------------
// AUTH_ERROR_CODES
// ---------------------------------------------------------------------------

describe('AUTH_ERROR_CODES', () => {
  // Verifies that AUTH_ERROR_CODES has at least 34 entries to guard against accidental removal.
  it('should have at least 34 entries', () => {
    // Guard against accidental removal — new codes should only grow this count.
    expect(Object.keys(AUTH_ERROR_CODES).length).toBeGreaterThanOrEqual(34)
  })

  // Verifies that every error code value is a string prefixed with 'auth.' to ensure consistent naming.
  it('should have string values for all codes', () => {
    for (const value of Object.values(AUTH_ERROR_CODES)) {
      expect(typeof value).toBe('string')
      expect(value).toMatch(/^auth\./)
    }
  })

  // Verifies that all core credential and account status error codes are present with the expected string values.
  it('should include all credential and account codes', () => {
    expect(AUTH_ERROR_CODES.INVALID_CREDENTIALS).toBe('auth.invalid_credentials')
    expect(AUTH_ERROR_CODES.ACCOUNT_LOCKED).toBe('auth.account_locked')
    expect(AUTH_ERROR_CODES.ACCOUNT_INACTIVE).toBe('auth.account_inactive')
    expect(AUTH_ERROR_CODES.ACCOUNT_SUSPENDED).toBe('auth.account_suspended')
    expect(AUTH_ERROR_CODES.ACCOUNT_BANNED).toBe('auth.account_banned')
    expect(AUTH_ERROR_CODES.PENDING_APPROVAL).toBe('auth.pending_approval')
  })

  // Verifies that all token and session-related error codes are present.
  it('should include all token and session codes', () => {
    expect(AUTH_ERROR_CODES.TOKEN_EXPIRED).toBe('auth.token_expired')
    expect(AUTH_ERROR_CODES.TOKEN_REVOKED).toBe('auth.token_revoked')
    expect(AUTH_ERROR_CODES.TOKEN_INVALID).toBe('auth.token_invalid')
    expect(AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID).toBe('auth.refresh_token_invalid')
    expect(AUTH_ERROR_CODES.SESSION_EXPIRED).toBe('auth.session_expired')
    expect(AUTH_ERROR_CODES.SESSION_LIMIT_REACHED).toBe('auth.session_limit_reached')
    expect(AUTH_ERROR_CODES.SESSION_NOT_FOUND).toBe('auth.session_not_found')
  })

  // Verifies that all MFA-related error codes are present.
  it('should include all MFA codes', () => {
    expect(AUTH_ERROR_CODES.MFA_REQUIRED).toBe('auth.mfa_required')
    expect(AUTH_ERROR_CODES.MFA_INVALID_CODE).toBe('auth.mfa_invalid_code')
    expect(AUTH_ERROR_CODES.MFA_ALREADY_ENABLED).toBe('auth.mfa_already_enabled')
    expect(AUTH_ERROR_CODES.MFA_NOT_ENABLED).toBe('auth.mfa_not_enabled')
    expect(AUTH_ERROR_CODES.MFA_SETUP_REQUIRED).toBe('auth.mfa_setup_required')
    expect(AUTH_ERROR_CODES.MFA_TEMP_TOKEN_INVALID).toBe('auth.mfa_temp_token_invalid')
    expect(AUTH_ERROR_CODES.RECOVERY_CODE_INVALID).toBe('auth.recovery_code_invalid')
  })

  // Verifies that password and OTP-related error codes are present.
  it('should include all password and OTP codes', () => {
    expect(AUTH_ERROR_CODES.PASSWORD_TOO_WEAK).toBe('auth.password_too_weak')
    expect(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID).toBe('auth.password_reset_token_invalid')
    expect(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_EXPIRED).toBe('auth.password_reset_token_expired')
    expect(AUTH_ERROR_CODES.OTP_INVALID).toBe('auth.otp_invalid')
    expect(AUTH_ERROR_CODES.OTP_EXPIRED).toBe('auth.otp_expired')
    expect(AUTH_ERROR_CODES.OTP_MAX_ATTEMPTS).toBe('auth.otp_max_attempts')
  })

  // Verifies that OAuth, invitation, and platform admin error codes are present.
  it('should include OAuth, invitation, and platform codes', () => {
    expect(AUTH_ERROR_CODES.OAUTH_FAILED).toBe('auth.oauth_failed')
    expect(AUTH_ERROR_CODES.OAUTH_EMAIL_MISMATCH).toBe('auth.oauth_email_mismatch')
    expect(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN).toBe('auth.invalid_invitation_token')
    expect(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED).toBe('auth.platform_auth_required')
  })

  // Verifies that no two error codes share the same string value (uniqueness invariant).
  it('should have unique values (no duplicate codes)', () => {
    const values = Object.values(AUTH_ERROR_CODES)
    const unique = new Set(values)
    expect(unique.size).toBe(values.length)
  })

  // Verifies that every error code has a corresponding entry in AUTH_ERROR_MESSAGES for Portuguese message lookup.
  it('should have an AUTH_ERROR_MESSAGES entry for every code', () => {
    for (const code of Object.values(AUTH_ERROR_CODES)) {
      expect(AUTH_ERROR_MESSAGES[code]).toBeDefined()
      expect(typeof AUTH_ERROR_MESSAGES[code]).toBe('string')
    }
  })
})

// ---------------------------------------------------------------------------
// AuthException — response format
// ---------------------------------------------------------------------------

describe('AuthException — response format', () => {
  // Verifies that AuthException produces a response body with the standard { error: { code, message, details } } shape.
  it('should produce the standard error response shape', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    const response = ex.getResponse() as { error: Record<string, unknown> }

    expect(response).toHaveProperty('error')
    expect(response.error).toHaveProperty('code', AUTH_ERROR_CODES.TOKEN_INVALID)
    expect(response.error).toHaveProperty('message')
    expect(response.error).toHaveProperty('details', null)
  })

  // Verifies that the message in the response is the Portuguese string from AUTH_ERROR_MESSAGES.
  it('should look up the Portuguese message from AUTH_ERROR_MESSAGES', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.INVALID_CREDENTIALS)
    const response = ex.getResponse() as { error: { message: string } }
    expect(response.error.message).toBe('Email ou senha inválidos')
  })

  // Verifies that the default HTTP status is 401 Unauthorized when no status is provided.
  it('should default to HTTP 401 Unauthorized', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    expect(ex.getStatus()).toBe(HttpStatus.UNAUTHORIZED)
  })

  // Verifies that a custom HTTP status code is reflected in getStatus().
  it('should accept a custom HTTP status code', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.FORBIDDEN, HttpStatus.FORBIDDEN)
    expect(ex.getStatus()).toBe(HttpStatus.FORBIDDEN)
  })

  // Verifies that HTTP 429 TOO_MANY_REQUESTS can be used for rate-limit errors.
  it('should accept a custom HTTP status code for 429', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, HttpStatus.TOO_MANY_REQUESTS)
    expect(ex.getStatus()).toBe(HttpStatus.TOO_MANY_REQUESTS)
  })

  // Verifies that optional details are included in the response body when provided.
  it('should include details in the response when provided', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.ACCOUNT_LOCKED, HttpStatus.TOO_MANY_REQUESTS, {
      retryAfterSeconds: 300
    })
    const response = ex.getResponse() as { error: { details: Record<string, unknown> } }
    expect(response.error.details).toEqual({ retryAfterSeconds: 300 })
  })

  // Verifies that details is null in the response when no details object is provided.
  it('should set details to null when not provided', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    const response = ex.getResponse() as { error: { details: unknown } }
    expect(response.error.details).toBeNull()
  })

  // Verifies that an unknown code falls back to using the code string itself as the message.
  it('should use the code itself as message when code is not in AUTH_ERROR_MESSAGES', () => {
    // Type cast needed: this test intentionally exercises the fallback path with a
    // future/unknown code value that doesn't exist in AUTH_ERROR_CODES today.
    const unknownCode = 'auth.some_future_code' as AuthErrorCode
    const ex = new AuthException(unknownCode)
    const response = ex.getResponse() as { error: { code: string; message: string } }
    expect(response.error.code).toBe(unknownCode)
    expect(response.error.message).toBe(unknownCode)
  })

  // Verifies that AuthException is a subclass of NestJS HttpException for proper filter handling.
  it('should extend HttpException', () => {
    const ex = new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    expect(ex).toBeInstanceOf(HttpException)
  })
})
