/**
 * Default cookie names and path used by the @bymax-one/nest-auth server.
 *
 * These literals are the same defaults declared in
 * `src/server/config/default-options.ts` under the `cookies` group. They
 * are duplicated in the shared subpath so that browser and edge-runtime
 * clients can reference them without pulling in any server-side runtime.
 *
 * @remarks
 * If a consumer overrides cookie names on the server (via
 * `BymaxAuthModule.forRoot({ cookies: { ... } })`), client code MUST be
 * configured with the matching values — these constants reflect only the
 * library defaults.
 */

/**
 * Default name of the HttpOnly cookie that carries the JWT access token.
 *
 * Mirrors `cookies.accessTokenName` in the server's `DEFAULT_OPTIONS`.
 */
export const AUTH_ACCESS_COOKIE_NAME = 'access_token' as const

/**
 * Default name of the HttpOnly cookie that carries the opaque refresh token.
 *
 * Mirrors `cookies.refreshTokenName` in the server's `DEFAULT_OPTIONS`.
 */
export const AUTH_REFRESH_COOKIE_NAME = 'refresh_token' as const

/**
 * Default name of the non-HttpOnly cookie used as a hint to the frontend
 * that a session likely exists.
 *
 * The actual access token is HttpOnly and not readable from JavaScript;
 * this companion flag lets the client decide whether to attempt a session
 * bootstrap before issuing requests. Mirrors `cookies.sessionSignalName`
 * in the server's `DEFAULT_OPTIONS`.
 */
export const AUTH_HAS_SESSION_COOKIE_NAME = 'has_session' as const

/**
 * Default path scope of the refresh-token cookie.
 *
 * Restricting the refresh cookie to the auth route prefix prevents the
 * browser from attaching it to every request, which reduces the attack
 * surface for token exfiltration via cross-site request forgery and side
 * channels. Mirrors `cookies.refreshCookiePath` in the server's
 * `DEFAULT_OPTIONS`.
 *
 * @remarks
 * Two server options influence the correct value:
 * - `cookies.refreshCookiePath` — direct override of the cookie scope.
 * - `routePrefix` — when changed (default `'auth'`), the refresh cookie
 *   path must be updated to match (e.g. setting `routePrefix: 'api/auth'`
 *   requires `cookies.refreshCookiePath: '/api/auth'`), otherwise the
 *   browser will not attach the cookie to refresh requests and every
 *   refresh will fail.
 */
export const AUTH_REFRESH_COOKIE_PATH = '/auth' as const
