/**
 * Error codes and message mappings for the @bymax-one/nest-auth module.
 *
 * All codes follow the `auth.<domain>_<action>` naming convention.
 * Codes are string literals (no numeric codes) to remain meaningful in logs
 * and API responses without a code lookup table.
 *
 * @remarks
 * Security principles enforced by these codes:
 * - Credential errors always use `INVALID_CREDENTIALS` to prevent user enumeration.
 * - Token structural errors always use `TOKEN_INVALID` to prevent leaking whether
 *   a token was well-formed vs expired vs revoked.
 * - `TOKEN_EXPIRED` and `TOKEN_REVOKED` are defined but should only appear in
 *   internal logic paths (e.g. access-token blacklist check, refresh-token lookup).
 *   Public-facing guards must use `TOKEN_INVALID` to prevent oracle information leakage.
 * - Anti-enumeration endpoints (verify-email, forgot-password) return 200 regardless
 *   of whether the email exists; a code/token error is returned only when the code
 *   itself is submitted.
 *
 * @layer Error
 */

/**
 * Canonical error codes thrown by `AuthException` throughout the module.
 *
 * Use these constants (not raw string literals) to benefit from type-level
 * autocomplete and to ensure consistency when catching or testing errors.
 */
export const AUTH_ERROR_CODES = {
  // ---------------------------------------------------------------------------
  // Credentials and account state
  // ---------------------------------------------------------------------------

  /** Login with incorrect email or password. Message is generic to prevent enumeration. */
  INVALID_CREDENTIALS: 'auth.invalid_credentials',

  /** Email-level brute-force lockout exceeded `maxAttempts` within `windowSeconds`. */
  ACCOUNT_LOCKED: 'auth.account_locked',

  /** User account status is INACTIVE. */
  ACCOUNT_INACTIVE: 'auth.account_inactive',

  /** User account status is SUSPENDED. */
  ACCOUNT_SUSPENDED: 'auth.account_suspended',

  /** User account status is BANNED. */
  ACCOUNT_BANNED: 'auth.account_banned',

  /** User account is pending manual approval. */
  PENDING_APPROVAL: 'auth.pending_approval',

  // ---------------------------------------------------------------------------
  // Tokens and sessions
  // ---------------------------------------------------------------------------

  /**
   * Access JWT has expired (after `accessExpiresIn`).
   * @remarks Use only in internal token-parsing logic — do NOT expose this code
   * in public-facing guard responses to prevent timing and oracle attacks.
   */
  TOKEN_EXPIRED: 'auth.token_expired',

  /**
   * Access JWT is in the Redis revocation blacklist (post-logout).
   * @remarks Same restriction as TOKEN_EXPIRED — internal use only.
   */
  TOKEN_REVOKED: 'auth.token_revoked',

  /** JWT is malformed, has an invalid signature, or the referenced user does not exist. */
  TOKEN_INVALID: 'auth.token_invalid',

  /** Refresh token not found in Redis — expired or revoked. */
  REFRESH_TOKEN_INVALID: 'auth.refresh_token_invalid',

  /** Session associated with the refresh token no longer exists in Redis. */
  SESSION_EXPIRED: 'auth.session_expired',

  /** Maximum concurrent session limit reached (informational — FIFO eviction handles this automatically). */
  SESSION_LIMIT_REACHED: 'auth.session_limit_reached',

  /** Attempted to revoke a session that does not exist or does not belong to the user. */
  SESSION_NOT_FOUND: 'auth.session_not_found',

  // ---------------------------------------------------------------------------
  // Registration and email
  // ---------------------------------------------------------------------------

  /** Attempted to register an email that already exists in the same tenant. */
  EMAIL_ALREADY_EXISTS: 'auth.email_already_exists',

  /** Login attempted when `emailVerification.required` is true and email is unverified. */
  EMAIL_NOT_VERIFIED: 'auth.email_not_verified',

  /**
   * The address-change token is unknown, expired, already used, or no longer bound to the
   * password it was minted against.
   *
   * One code for all four, deliberately: the holder of a bad link learns only that it does
   * not work, which is all they can act on. Telling them *why* would say whether an address
   * change is pending for the account — and a change request that an attacker planted is
   * exactly the thing they would want confirmed.
   */
  EMAIL_CHANGE_TOKEN_INVALID: 'auth.email_change_token_invalid',

  // ---------------------------------------------------------------------------
  // MFA
  // ---------------------------------------------------------------------------

  /** Endpoint requires MFA verification but the JWT does not have `mfaVerified: true`. */
  MFA_REQUIRED: 'auth.mfa_required',

  /** Submitted TOTP 6-digit code is incorrect. */
  MFA_INVALID_CODE: 'auth.mfa_invalid_code',

  /** MFA setup attempted when MFA is already enabled. */
  MFA_ALREADY_ENABLED: 'auth.mfa_already_enabled',

  /** MFA disable or challenge attempted when MFA is not enabled. */
  MFA_NOT_ENABLED: 'auth.mfa_not_enabled',

  /** TOTP verification attempted before MFA setup was completed. */
  MFA_SETUP_REQUIRED: 'auth.mfa_setup_required',

  /** MFA temporary token (5-minute JWT) is invalid or expired. */
  MFA_TEMP_TOKEN_INVALID: 'auth.mfa_temp_token_invalid',

  /** Submitted recovery code does not match any stored hash. */
  RECOVERY_CODE_INVALID: 'auth.recovery_code_invalid',

  // ---------------------------------------------------------------------------
  // Password
  // ---------------------------------------------------------------------------

  /** Password does not meet minimum strength requirements (e.g., fewer than 8 characters). */
  PASSWORD_TOO_WEAK: 'auth.password_too_weak',

  /**
   * The password appears in a known-breach corpus. Distinct from `PASSWORD_TOO_WEAK`: the
   * password may satisfy every complexity rule and still be one an attacker will try first.
   */
  PASSWORD_COMPROMISED: 'auth.password_compromised',

  /** Password reset token not found in Redis. */
  PASSWORD_RESET_TOKEN_INVALID: 'auth.password_reset_token_invalid',

  /** Password reset token found but its TTL has expired. */
  PASSWORD_RESET_TOKEN_EXPIRED: 'auth.password_reset_token_expired',

  // ---------------------------------------------------------------------------
  // OTP (email verification, password reset via OTP)
  // ---------------------------------------------------------------------------

  /**
   * An OTP verification failed. The **only** code an OTP failure ever answers with: a wrong
   * code, a record that is not in Redis, and an exhausted attempt ceiling are deliberately
   * indistinguishable, and take the same time.
   *
   * Telling them apart defeated the anti-enumeration in front of them. `forgot-password`
   * answers the same whether or not the address exists, but only writes an OTP record when it
   * does — so one wrong code afterwards used to say which it had been.
   */
  OTP_INVALID: 'auth.otp_invalid',

  /**
   * Internal-only: the OTP record was not in Redis. Never reaches a client — surfaced as
   * {@link AUTH_ERROR_CODES.OTP_INVALID}, the same treatment {@link
   * AUTH_ERROR_CODES.TOKEN_EXPIRED} gets. Kept for logs and for the shared error catalog,
   * which rust-auth holds identical.
   */
  OTP_EXPIRED: 'auth.otp_expired',

  /**
   * Internal-only: OTP verification hit the five-attempt ceiling. Never reaches a client —
   * surfaced as {@link AUTH_ERROR_CODES.OTP_INVALID}, because only a record that exists can
   * reach a ceiling, which is the same disclosure by a slower route.
   */
  OTP_MAX_ATTEMPTS: 'auth.otp_max_attempts',

  // ---------------------------------------------------------------------------
  // Authorization
  // ---------------------------------------------------------------------------

  /** User's role does not satisfy the hierarchy required by the endpoint. */
  INSUFFICIENT_ROLE: 'auth.insufficient_role',

  /** Generic access-denied fallback when no more specific code applies. */
  FORBIDDEN: 'auth.forbidden',

  /**
   * The request body or query failed DTO validation. Per-field failures serialize into
   * `error.details` as `[{ field, message }]`. Raised by the module's validation pipe so a
   * malformed request answers in the same envelope as every other error rather than in the
   * framework's default shape — the same code and the same details rust-auth emits.
   */
  VALIDATION: 'auth.validation',

  /**
   * The caller exceeded a per-IP rate limit on an auth route. Carries `Retry-After`.
   * Distinct from `ACCOUNT_LOCKED`, which is the per-identity brute-force lockout.
   */
  TOO_MANY_REQUESTS: 'auth.too_many_requests',

  /**
   * A state-changing request carrying the session cookie came from an origin the deployment
   * does not trust. Raised by `TrustedOriginGuard` — see `cookies.trustedOrigins`.
   */
  UNTRUSTED_ORIGIN: 'auth.untrusted_origin',

  // ---------------------------------------------------------------------------
  // Invitations
  // ---------------------------------------------------------------------------

  /** Invitation token not found in Redis — invalid or expired. */
  INVALID_INVITATION_TOKEN: 'auth.invalid_invitation_token',

  // ---------------------------------------------------------------------------
  // OAuth
  // ---------------------------------------------------------------------------

  /** Generic OAuth failure — provider rejected the request or returned an error. */
  OAUTH_FAILED: 'auth.oauth_failed',

  /** OAuth provider returned an email that does not match the expected address. */
  OAUTH_EMAIL_MISMATCH: 'auth.oauth_email_mismatch',

  // ---------------------------------------------------------------------------
  // Platform admin
  // ---------------------------------------------------------------------------

  /** Platform-admin endpoint accessed with a dashboard JWT instead of a platform JWT. */
  PLATFORM_AUTH_REQUIRED: 'auth.platform_auth_required'
} as const

/**
 * String literal union of all valid `AuthException` error codes.
 *
 * Use this type to enforce that only recognized codes are passed to
 * `AuthException` and related APIs.
 */
export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[keyof typeof AUTH_ERROR_CODES]

/**
 * Human-readable message for each error code.
 *
 * Looked up automatically by `AuthException` to populate the `message` field
 * in error responses. Messages are in English; they are end-user facing defaults.
 *
 * This object is `Readonly` — do NOT mutate it directly to support other
 * locales. Instead, pass a `messages` override map to `BymaxAuthModule.forRoot()`
 * (planned for a future version) or handle i18n at the NestJS filter layer.
 */
export const AUTH_ERROR_MESSAGES: Readonly<Record<AuthErrorCode, string>> = {
  'auth.invalid_credentials': 'Invalid email or password',
  'auth.account_locked': 'Account temporarily locked. Please try again in a few minutes.',
  'auth.account_inactive': 'Account inactive',
  'auth.account_suspended': 'Account suspended',
  'auth.account_banned': 'Account banned',
  'auth.pending_approval': 'Account pending approval',
  'auth.token_expired': 'Token expired',
  'auth.token_revoked': 'Token revoked',
  'auth.token_invalid': 'Invalid token',
  'auth.refresh_token_invalid': 'Invalid or expired refresh token',
  'auth.session_expired': 'Session expired',
  'auth.session_limit_reached': 'Session limit reached',
  'auth.session_not_found': 'Session not found',
  'auth.email_already_exists': 'Email already registered',
  'auth.email_not_verified': 'Email not verified',
  'auth.email_change_token_invalid': 'Invalid or expired email change link',
  'auth.mfa_required': 'Two-factor authentication required',
  'auth.mfa_invalid_code': 'Invalid MFA code',
  'auth.mfa_already_enabled': 'MFA is already enabled',
  'auth.mfa_not_enabled': 'MFA is not enabled',
  'auth.mfa_setup_required': 'MFA setup required',
  'auth.mfa_temp_token_invalid': 'Invalid or expired temporary MFA token',
  'auth.recovery_code_invalid': 'Invalid recovery code',
  'auth.password_too_weak': 'Password too weak',
  'auth.password_compromised':
    'This password has appeared in a data breach. Please choose a different one.',
  'auth.password_reset_token_invalid': 'Invalid password reset token',
  'auth.password_reset_token_expired': 'Expired password reset token',
  'auth.otp_invalid': 'Invalid OTP code',
  'auth.otp_expired': 'Expired OTP code',
  'auth.otp_max_attempts': 'Maximum number of attempts exceeded',
  'auth.insufficient_role': 'Insufficient permission',
  'auth.forbidden': 'Access denied',
  'auth.validation': 'Validation failed',
  'auth.too_many_requests': 'Too many requests. Please try again shortly.',
  'auth.untrusted_origin': 'Request origin not allowed',
  'auth.invalid_invitation_token': 'Invalid or expired invitation token',
  'auth.oauth_failed': 'OAuth authentication failed',
  'auth.oauth_email_mismatch': 'OAuth email does not match',
  'auth.platform_auth_required': 'Platform authentication required'
}
