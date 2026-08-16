/**
 * Stable machine-readable error codes returned by the
 * @bymax-one/nest-auth server, mirrored here for the shared subpath.
 *
 * Re-declared (not re-exported from `../../server`) so that this entry
 * point stays free of any server-side runtime imports — the shared
 * subpath must remain importable in browser and edge runtimes.
 *
 * @remarks
 * These literals MUST stay byte-for-byte identical to
 * `AUTH_ERROR_CODES` in `src/server/errors/auth-error-codes.ts`. Any
 * change there must be reflected here, or the client will branch on the
 * wrong code at runtime.
 */
export const AUTH_ERROR_CODES = {
  // Credentials and account state
  INVALID_CREDENTIALS: 'auth.invalid_credentials',
  ACCOUNT_LOCKED: 'auth.account_locked',
  ACCOUNT_INACTIVE: 'auth.account_inactive',
  ACCOUNT_SUSPENDED: 'auth.account_suspended',
  ACCOUNT_BANNED: 'auth.account_banned',
  PENDING_APPROVAL: 'auth.pending_approval',

  // Tokens and sessions
  /** Internal-only: expiry. Never on the wire — collapsed onto TOKEN_INVALID, to deny an oracle
   *  separating a token that WAS valid from one that never was. */
  TOKEN_EXPIRED: 'auth.token_expired',
  /** Internal-only: logout or epoch bump. Never on the wire — see TOKEN_EXPIRED. */
  TOKEN_REVOKED: 'auth.token_revoked',
  /** What a client receives for EVERY unusable credential: expired, revoked, malformed, absent. */
  TOKEN_INVALID: 'auth.token_invalid',
  /** Internal-only: the request carried no credential. Never on the wire — see TOKEN_INVALID. */
  TOKEN_MISSING: 'auth.token_missing',

  REFRESH_TOKEN_INVALID: 'auth.refresh_token_invalid',
  SESSION_NOT_FOUND: 'auth.session_not_found',

  // Registration and email
  EMAIL_ALREADY_EXISTS: 'auth.email_already_exists',
  EMAIL_NOT_VERIFIED: 'auth.email_not_verified',
  EMAIL_CHANGE_TOKEN_INVALID: 'auth.email_change_token_invalid',

  // MFA
  MFA_REQUIRED: 'auth.mfa_required',
  MFA_INVALID_CODE: 'auth.mfa_invalid_code',
  MFA_ALREADY_ENABLED: 'auth.mfa_already_enabled',
  MFA_NOT_ENABLED: 'auth.mfa_not_enabled',
  MFA_SETUP_REQUIRED: 'auth.mfa_setup_required',
  MFA_TEMP_TOKEN_INVALID: 'auth.mfa_temp_token_invalid',
  MFA_STATE_CONFLICT: 'auth.mfa_state_conflict',

  // Password

  /** The password appears in a known-breach corpus. */
  PASSWORD_COMPROMISED: 'auth.password_compromised',
  PASSWORD_RESET_TOKEN_INVALID: 'auth.password_reset_token_invalid',

  // OTP (email verification, password reset via OTP)

  /**
   * The only code an OTP failure reaches a client with. A wrong code, a record that is not in
   * Redis, and an exhausted attempt ceiling are deliberately indistinguishable: `forgot-password`
   * answers the same whether or not the address exists, but only writes an OTP record when it
   * does, so telling them apart made that uniform answer definitive after one extra request.
   */
  OTP_INVALID: 'auth.otp_invalid',

  /** Internal-only: the OTP record was absent. Never on the wire — see {@link OTP_INVALID}. */
  OTP_EXPIRED: 'auth.otp_expired',

  /** Internal-only: the attempt ceiling was hit. Never on the wire — see {@link OTP_INVALID}. */
  OTP_MAX_ATTEMPTS: 'auth.otp_max_attempts',

  // Authorization
  INSUFFICIENT_ROLE: 'auth.insufficient_role',
  FORBIDDEN: 'auth.forbidden',

  /**
   * The request body or query failed DTO validation. Per-field failures serialize into
   * `error.details` as `[{ field, message }]`.
   */
  VALIDATION: 'auth.validation',

  /** The caller exceeded a per-IP rate limit on an auth route. */
  TOO_MANY_REQUESTS: 'auth.too_many_requests',

  /**
   * A state-changing request carrying the session cookie came from an origin the deployment
   * does not trust.
   */
  UNTRUSTED_ORIGIN: 'auth.untrusted_origin',

  /**
   * A change to how the account authenticates was attempted without a recent authentication.
   * The client should send the user back through sign-in and retry.
   */
  REAUTHENTICATION_REQUIRED: 'auth.reauthentication_required',

  // Invitations
  INVALID_INVITATION_TOKEN: 'auth.invalid_invitation_token',

  // OAuth
  OAUTH_FAILED: 'auth.oauth_failed',
  OAUTH_EMAIL_MISMATCH: 'auth.oauth_email_mismatch',

  // Platform admin
  PLATFORM_AUTH_REQUIRED: 'auth.platform_auth_required',

  /**
   * An unexpected internal failure. Raised only by the server's optional `AuthExceptionFilter`,
   * which gives unhandled failures the same envelope everything else answers with.
   */
  INTERNAL: 'auth.internal'
} as const

/**
 * String literal union of every `AUTH_ERROR_CODES` value.
 *
 * Use this type to constrain client-side error-code matchers (switch
 * statements, lookup tables) so that an unrecognized code is caught at
 * compile time.
 */
export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[keyof typeof AUTH_ERROR_CODES]

/**
 * HTTP status each error code answers with, mirrored from the server declaration.
 *
 * Duplicated rather than imported for the same reason {@link AUTH_ERROR_CODES} is: this subpath
 * must compile in a browser, and the server entry carries the NestJS peer dependencies. The
 * drift-guard spec beside this file is the only place the two declarations meet.
 *
 * It lives here because the three uses the README invites — a typed client, an API document, a
 * test asserting against the mapping — are exactly the ones that must not pull the server entry.
 * It shipped only from there, next to a paragraph correctly saying `AUTH_ERROR_CODES` comes from
 * `/shared`, so the adjacency invited the assumption that this did too.
 *
 * These are WIRE statuses: an internal-only code carries the status of the public code it
 * collapses onto, not one of its own.
 */
export const AUTH_ERROR_STATUS: Readonly<Record<AuthErrorCode, number>> = {
  'auth.invalid_credentials': 401,
  'auth.account_locked': 429,
  'auth.account_inactive': 403,
  'auth.account_suspended': 403,
  'auth.account_banned': 403,
  'auth.pending_approval': 403,
  'auth.token_expired': 401,
  'auth.token_revoked': 401,
  'auth.token_invalid': 401,
  'auth.token_missing': 401,
  'auth.refresh_token_invalid': 401,
  'auth.session_not_found': 404,
  'auth.email_already_exists': 409,
  'auth.email_not_verified': 403,
  'auth.email_change_token_invalid': 400,
  'auth.mfa_required': 403,
  'auth.mfa_invalid_code': 401,
  'auth.mfa_already_enabled': 409,
  'auth.mfa_not_enabled': 400,
  'auth.mfa_setup_required': 400,
  'auth.mfa_temp_token_invalid': 401,
  'auth.mfa_state_conflict': 409,
  'auth.password_compromised': 400,
  'auth.password_reset_token_invalid': 400,
  'auth.otp_invalid': 401,
  'auth.otp_expired': 401,
  'auth.otp_max_attempts': 401,
  'auth.insufficient_role': 403,
  'auth.forbidden': 403,
  'auth.validation': 400,
  'auth.too_many_requests': 429,
  'auth.untrusted_origin': 403,
  'auth.reauthentication_required': 403,
  'auth.invalid_invitation_token': 400,
  'auth.oauth_failed': 401,
  'auth.oauth_email_mismatch': 409,
  'auth.platform_auth_required': 401,
  'auth.internal': 500
}
