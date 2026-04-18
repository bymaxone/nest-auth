/**
 * @bymax-one/nest-auth/nextjs — Next.js 16 integration.
 *
 * Public API of the Next.js subpath:
 *
 *   - **Factories**: `createAuthProxy`, `createSilentRefreshHandler`,
 *     `createClientRefreshHandler`, `createLogoutHandler`.
 *   - **Helpers**: `isBackgroundRequest`, `buildSilentRefreshUrl`,
 *     `parseSetCookieHeader`, `dedupeSetCookieHeaders`,
 *     `getSetCookieHeaders`, `decodeJwtToken`, `verifyJwtToken`,
 *     `isTokenExpired`, `getUserRole`, `getUserId`, `getTenantId`,
 *     `resolveSafeDestination`.
 *   - **Canonical routes**: `SILENT_REFRESH_ROUTE`,
 *     `CLIENT_REFRESH_ROUTE`, `LOGOUT_ROUTE`.
 *   - **Types**: every public interface / type the factories and
 *     helpers accept or return.
 *
 * All symbols are Edge-Runtime-safe: the subpath reaches only the
 * Web Fetch / URL / Web Crypto APIs and the project's own shared
 * constants.
 *
 * Peer deps (declared in `package.json`): `next ^16`, `react ^19`.
 *
 * Deliberate export-hygiene choices:
 *
 *   - Every type alias uses `export type` so the bundler can strip
 *     type-only imports from the consumer's runtime bundle.
 *   - Internal helpers (`classifyRoute`, `handlePublicRoute`,
 *     `normalizePath`, `trimTrailingSlash`, `serializeClearCookie`,
 *     `buildRefreshUrl`, etc.) are NOT re-exported. They live under
 *     `helpers/` with module-private scope and may change without a
 *     major-version bump.
 */

// ---------------------------------------------------------------------------
// Helpers — pure functions, no peer-dep runtime requirements
// ---------------------------------------------------------------------------

export { isBackgroundRequest } from './helpers/isBackgroundRequest'
export type { RequestWithHeaders } from './helpers/isBackgroundRequest'

export { buildSilentRefreshUrl } from './helpers/buildSilentRefreshUrl'
export type { RequestWithUrl } from './helpers/buildSilentRefreshUrl'

export {
  dedupeSetCookieHeaders,
  getSetCookieHeaders,
  parseSetCookieHeader
} from './helpers/dedupeSetCookieHeaders'
export type { HeadersLike, ParsedSetCookie } from './helpers/dedupeSetCookieHeaders'

export {
  decodeJwtToken,
  getTenantId,
  getUserId,
  getUserRole,
  isTokenExpired,
  verifyJwtToken
} from './helpers/jwt'
export type { DecodedToken, JwtHeader } from './helpers/jwt'

// ---------------------------------------------------------------------------
// Factory — auth proxy (Next.js Edge middleware)
// ---------------------------------------------------------------------------

export { createAuthProxy } from './createAuthProxy'
export type {
  AuthProxyConfig,
  AuthProxyInstance,
  ProtectedRoutePattern,
  ResolvedAuthProxyConfig
} from './createAuthProxy'

// ---------------------------------------------------------------------------
// Factories — route handlers mounted under `/api/auth/*`
// ---------------------------------------------------------------------------

export {
  SILENT_REFRESH_ROUTE,
  createSilentRefreshHandler,
  resolveSafeDestination
} from './createSilentRefreshHandler'
export type { SilentRefreshHandler, SilentRefreshHandlerConfig } from './createSilentRefreshHandler'

export { CLIENT_REFRESH_ROUTE, createClientRefreshHandler } from './createClientRefreshHandler'
export type { ClientRefreshHandler, ClientRefreshHandlerConfig } from './createClientRefreshHandler'

export { LOGOUT_ROUTE, createLogoutHandler } from './createLogoutHandler'
export type {
  LogoutHandler,
  LogoutHandlerConfig,
  LogoutHandlerRedirectConfig,
  LogoutHandlerStatusConfig
} from './createLogoutHandler'
