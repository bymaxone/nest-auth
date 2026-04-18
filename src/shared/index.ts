/**
 * @bymax-one/nest-auth/shared — Public API of the shared subpath.
 *
 * Pure types and constants only. This entry point ships ZERO runtime
 * dependencies and must remain importable in browser, edge, and Node.js
 * runtimes alike. Anything imported here must transitively avoid the
 * `node:`, NestJS, ioredis, and class-validator namespaces.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_HAS_SESSION_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_PATH
} from './constants/cookie-defaults'

export { AUTH_ERROR_CODES } from './constants/error-codes'
export type { AuthErrorCode } from './constants/error-codes'

export {
  AUTH_DASHBOARD_ROUTES,
  AUTH_INVITATION_ROUTES,
  AUTH_MFA_ROUTES,
  AUTH_PASSWORD_ROUTES,
  AUTH_PLATFORM_ROUTES,
  AUTH_PROXY_ROUTES,
  AUTH_REFRESH_SKIP_PATH_SUFFIXES,
  AUTH_ROUTES,
  AUTH_SESSION_ROUTES,
  buildAuthRefreshSkipSuffixes
} from './constants/routes'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type { AuthPlatformUserClient, AuthUserClient } from './types/auth-user.types'

export type {
  AuthResult,
  LoginResult,
  MfaChallengeResult,
  PlatformAuthResult,
  PlatformLoginResult
} from './types/auth-result.types'

export { AuthClientError } from './types/auth-error.types'
export type { AuthErrorResponse, AuthResponseCode } from './types/auth-error.types'

export type {
  AuthJwtPayload,
  DashboardJwtPayload,
  MfaTempPayload,
  PlatformJwtPayload
} from './types/jwt-payload.types'

export type { AuthContextKind, AuthCookieNames, TokenDeliveryMode } from './types/auth-config.types'
