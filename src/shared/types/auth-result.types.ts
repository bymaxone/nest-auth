import type { AuthPlatformUserClient, AuthUserClient } from './auth-user.types'

/**
 * Result returned by the client after a successful login or token refresh.
 *
 * @remarks
 * `accessToken` is included so that bearer-token consumers (mobile apps,
 * non-cookie environments) can surface it directly. When the server is
 * configured for cookie delivery (`tokenDelivery: 'cookie'`), the access
 * token is set as an HttpOnly cookie by the server and this field is an
 * empty string — clients should rely on the cookie in that mode.
 */
export interface AuthResult {
  /** The authenticated user (credential and secret fields omitted). */
  user: AuthUserClient

  /**
   * Short-lived JWT access token, or empty string when the server is
   * configured for HttpOnly cookie delivery.
   *
   * @warning
   * In bearer mode this value is a credential. Hold it **in memory only**
   * (module-scoped variable, React state, or equivalent). Never write it to
   * `localStorage`, `sessionStorage`, `IndexedDB`, or any persistent store —
   * any same-origin script (including third-party widgets) can read those,
   * so persisting the token turns any XSS into full account takeover for
   * the token's remaining TTL. Never place it in a URL or log output.
   */
  accessToken: string
}

/**
 * Result returned by the client after a successful platform admin login or refresh.
 *
 * @remarks
 * Uses the `admin` field (vs `user` in {@link AuthResult}) so that callers
 * handling both flows can branch reliably on the discriminating field name.
 */
export interface PlatformAuthResult {
  /** The authenticated platform administrator (credential and secret fields omitted). */
  admin: AuthPlatformUserClient

  /**
   * Short-lived JWT access token, or empty string when the server is
   * configured for HttpOnly cookie delivery.
   *
   * @warning
   * In bearer mode this value is a credential. Hold it **in memory only**
   * (module-scoped variable, React state, or equivalent). Never write it to
   * `localStorage`, `sessionStorage`, `IndexedDB`, or any persistent store —
   * any same-origin script (including third-party widgets) can read those,
   * so persisting the token turns any XSS into full account takeover for
   * the token's remaining TTL. Never place it in a URL or log output.
   */
  accessToken: string
}

/**
 * Result returned when authentication requires MFA verification.
 *
 * The `mfaRequired: true` literal type enables reliable type narrowing in
 * union return types so that callers can branch on a single discriminant:
 *
 * @example
 * ```typescript
 * const result = await authClient.login(email, password)
 * if ('mfaRequired' in result) {
 *   // result is MfaChallengeResult here
 * } else {
 *   // result is AuthResult here
 * }
 * ```
 */
export interface MfaChallengeResult {
  /** Literal `true` discriminant — enables type narrowing in union return types. */
  mfaRequired: true

  /**
   * Short-lived MFA challenge token (default 5-minute TTL).
   * The client exchanges this token plus the user's OTP for a full access token.
   *
   * @remarks
   * Treat this value as a credential. Never log it, persist it to disk, or
   * place it in a URL — exposure enables MFA bypass within the token's
   * lifetime. Hold it only in memory between the login response and the
   * subsequent MFA verification call.
   */
  mfaTempToken: string
}

/**
 * Discriminated union of all possible login responses.
 *
 * Use this type as the return type of any login method that may either
 * complete the auth flow or escalate to an MFA challenge step.
 */
export type LoginResult = AuthResult | MfaChallengeResult

/**
 * Discriminated union of all possible platform admin login responses.
 */
export type PlatformLoginResult = PlatformAuthResult | MfaChallengeResult
