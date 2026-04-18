/**
 * Shared cookie- and configuration-related type definitions.
 *
 * These types describe naming and shape contracts shared between server and
 * client. They contain no runtime values — pure type-only declarations that
 * compile away.
 */

/**
 * Set of cookie names used by the auth system.
 *
 * The defaults live in `AUTH_ACCESS_COOKIE_NAME`, `AUTH_REFRESH_COOKIE_NAME`,
 * and `AUTH_HAS_SESSION_COOKIE_NAME`. Consumers that override the cookie
 * names on the server (via `BymaxAuthModule.forRoot({ cookies: { ... } })`)
 * must surface the same names to the client through this shape so both
 * sides stay in sync.
 */
export interface AuthCookieNames {
  /**
   * Name of the HttpOnly cookie that carries the JWT access token.
   * Default: `'access_token'`.
   */
  accessTokenName: string

  /**
   * Name of the HttpOnly cookie that carries the opaque refresh token.
   * Default: `'refresh_token'`.
   */
  refreshTokenName: string

  /**
   * Name of the non-HttpOnly cookie used as a hint to the frontend that a
   * session likely exists (the actual access token is HttpOnly and not
   * readable by JavaScript). Default: `'has_session'`.
   */
  sessionSignalName: string

  /**
   * Path scope of the refresh-token cookie. Restricting it to the auth
   * route prefix prevents the cookie from being sent on every request.
   * Default: `'/auth'`.
   */
  refreshCookiePath: string
}

/**
 * Discriminated authentication context.
 *
 * Used by client code that may operate against either the dashboard or the
 * platform admin endpoints. Modeled as a string literal union so that both
 * library and consumer code can branch exhaustively.
 */
export type AuthContextKind = 'dashboard' | 'platform'

/**
 * Token delivery strategy in use on the server.
 *
 * - `cookie`: tokens are set as HttpOnly cookies; the client never reads them.
 * - `bearer`: tokens are returned in the response body; the client sends
 *   them in the `Authorization: Bearer <token>` header.
 */
export type TokenDeliveryMode = 'cookie' | 'bearer'
