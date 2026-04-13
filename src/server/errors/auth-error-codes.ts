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

  /** Password reset token not found in Redis. */
  PASSWORD_RESET_TOKEN_INVALID: 'auth.password_reset_token_invalid',

  /** Password reset token found but its TTL has expired. */
  PASSWORD_RESET_TOKEN_EXPIRED: 'auth.password_reset_token_expired',

  // ---------------------------------------------------------------------------
  // OTP (email verification, password reset via OTP)
  // ---------------------------------------------------------------------------

  /** Submitted OTP code does not match the stored value. */
  OTP_INVALID: 'auth.otp_invalid',

  /** OTP not found in Redis — TTL has expired. */
  OTP_EXPIRED: 'auth.otp_expired',

  /** OTP verification failed more than 5 times — token is now locked. */
  OTP_MAX_ATTEMPTS: 'auth.otp_max_attempts',

  // ---------------------------------------------------------------------------
  // Authorization
  // ---------------------------------------------------------------------------

  /** User's role does not satisfy the hierarchy required by the endpoint. */
  INSUFFICIENT_ROLE: 'auth.insufficient_role',

  /** Generic access-denied fallback when no more specific code applies. */
  FORBIDDEN: 'auth.forbidden',

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
 * in error responses. Messages are in Portuguese as they are end-user facing.
 *
 * This object is `Readonly` — do NOT mutate it directly to support other
 * locales. Instead, pass a `messages` override map to `BymaxAuthModule.forRoot()`
 * (planned for a future version) or handle i18n at the NestJS filter layer.
 */
export const AUTH_ERROR_MESSAGES: Readonly<Record<AuthErrorCode, string>> = {
  'auth.invalid_credentials': 'Email ou senha inválidos',
  'auth.account_locked': 'Conta temporariamente bloqueada. Tente novamente em alguns minutos.',
  'auth.account_inactive': 'Conta inativa',
  'auth.account_suspended': 'Conta suspensa',
  'auth.account_banned': 'Conta banida',
  'auth.pending_approval': 'Conta pendente de aprovação',
  'auth.token_expired': 'Token expirado',
  'auth.token_revoked': 'Token revogado',
  'auth.token_invalid': 'Token inválido',
  'auth.refresh_token_invalid': 'Refresh token inválido ou expirado',
  'auth.session_expired': 'Sessão expirada',
  'auth.session_limit_reached': 'Limite de sessões atingido',
  'auth.session_not_found': 'Sessão não encontrada',
  'auth.email_already_exists': 'Email já cadastrado',
  'auth.email_not_verified': 'Email não verificado',
  'auth.mfa_required': 'Autenticação de dois fatores necessária',
  'auth.mfa_invalid_code': 'Código MFA inválido',
  'auth.mfa_already_enabled': 'MFA já está habilitado',
  'auth.mfa_not_enabled': 'MFA não está habilitado',
  'auth.mfa_setup_required': 'Configuração de MFA necessária',
  'auth.mfa_temp_token_invalid': 'Token temporário de MFA inválido ou expirado',
  'auth.recovery_code_invalid': 'Código de recuperação inválido',
  'auth.password_too_weak': 'Senha muito fraca',
  'auth.password_reset_token_invalid': 'Token de redefinição de senha inválido',
  'auth.password_reset_token_expired': 'Token de redefinição de senha expirado',
  'auth.otp_invalid': 'Código OTP inválido',
  'auth.otp_expired': 'Código OTP expirado',
  'auth.otp_max_attempts': 'Número máximo de tentativas excedido',
  'auth.insufficient_role': 'Permissão insuficiente',
  'auth.forbidden': 'Acesso negado',
  'auth.invalid_invitation_token': 'Token de convite inválido ou expirado',
  'auth.oauth_failed': 'Falha na autenticação OAuth',
  'auth.oauth_email_mismatch': 'Email do OAuth não corresponde',
  'auth.platform_auth_required': 'Autenticação de plataforma necessária'
}
