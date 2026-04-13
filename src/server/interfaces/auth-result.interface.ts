/**
 * Auth result type definitions for @bymax-one/nest-auth.
 *
 * Describes the data structures returned by authentication operations across
 * the three authentication flows: dashboard users, platform administrators,
 * and the MFA challenge step.
 */

import type { SafeAuthPlatformUser } from './platform-user-repository.interface'
import type { SafeAuthUser } from './user-repository.interface'

/**
 * Result returned after a successful dashboard user login.
 *
 * @remarks
 * `user` is typed as {@link SafeAuthUser} — `passwordHash`, `mfaSecret`, and
 * `mfaRecoveryCodes` are intentionally excluded. Controllers that serialize this
 * result and return it to the client cannot accidentally leak credential material.
 *
 * `rawRefreshToken` is deliberately named "raw" to signal that this is the
 * opaque token value. It must never be stored as-is on the server side —
 * only its hashed form (`sessionHash`) should persist in Redis/DB.
 * `sessionHash` is only present when `sessions.enabled` is `true` in the
 * module configuration.
 */
export interface AuthResult {
  /** The authenticated user (credential fields omitted). */
  user: SafeAuthUser
  /** Short-lived JWT access token. */
  accessToken: string
  /**
   * Opaque refresh token in its raw (plain-text) form.
   * Named `rawRefreshToken` — never `refreshToken` — to prevent accidental
   * storage of the unsalted value.
   */
  rawRefreshToken: string
  /**
   * HMAC-SHA-256 hash of the raw refresh token.
   * Only present when `sessions.enabled = true` in the module config.
   * This value is what gets persisted in Redis for revocation checks.
   */
  sessionHash?: string
}

/**
 * Result returned after a successful platform administrator login.
 *
 * @remarks
 * `admin` is typed as {@link SafeAuthPlatformUser} — credential fields are
 * excluded for the same reason as in {@link AuthResult}.
 *
 * Platform admins do not use session-based refresh tracking by default, so
 * `sessionHash` is absent from this result type.
 * `rawRefreshToken` follows the same naming convention as {@link AuthResult}.
 *
 * The `admin` field name (vs `user` in `AuthResult`) reflects the distinct
 * identity domain. Code that handles both result types must branch on the
 * presence of `admin` vs `user` rather than relying on a common field name.
 */
export interface PlatformAuthResult {
  /** The authenticated platform administrator (credential fields omitted). */
  admin: SafeAuthPlatformUser
  /** Short-lived JWT access token. */
  accessToken: string
  /**
   * Opaque refresh token in its raw (plain-text) form.
   * Named `rawRefreshToken` — never `refreshToken` — to prevent accidental
   * storage of the unsalted value.
   */
  rawRefreshToken: string
}

/**
 * Result returned by {@link TokenManagerService.reissueTokens} after a successful
 * refresh token rotation.
 *
 * @remarks
 * Unlike {@link AuthResult}, this type does **not** include a full `SafeAuthUser`
 * object. The Redis session only stores `{ userId, tenantId, role }` — not the
 * complete user record. Returning a full `SafeAuthUser` here would require either
 * a database fetch (not appropriate in this service) or hollow stub fields
 * (which could silently bypass status-based guards in callers).
 *
 * Callers that need the full user record (e.g. to include it in the HTTP response)
 * must fetch it from the user repository using `session.userId`.
 */
export interface RotatedTokenResult {
  /** Minimal identity extracted from the Redis session record. */
  session: {
    userId: string
    tenantId: string
    role: string
  }
  /** Short-lived JWT access token. */
  accessToken: string
  /**
   * Opaque refresh token in its raw (plain-text) form.
   * Named `rawRefreshToken` — never `refreshToken` — to prevent accidental storage.
   */
  rawRefreshToken: string
}

/**
 * Result returned when authentication requires MFA completion.
 *
 * The `mfaRequired: true` literal type enables reliable type narrowing in
 * union return types:
 *
 * @example
 * ```typescript
 * const result = await authService.login(dto)
 * if (result.mfaRequired) {
 *   // TypeScript narrows to MfaChallengeResult here
 *   return { mfaTempToken: result.mfaTempToken }
 * }
 * // TypeScript narrows to AuthResult here
 * ```
 */
export interface MfaChallengeResult {
  /** Literal `true` discriminant — enables type narrowing in union return types. */
  mfaRequired: true
  /** Short-lived MFA challenge token (5-minute TTL) to be exchanged after OTP verification. */
  mfaTempToken: string
}
