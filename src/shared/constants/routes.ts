/**
 * HTTP route paths exposed by the @bymax-one/nest-auth server controllers.
 *
 * All paths are relative to the configured `routePrefix` (default
 * `'auth'`). The defaults below assume the prefix-less paths so that
 * client code can compose a full URL as
 * `${baseUrl}/${routePrefix}/${AUTH_ROUTES.dashboard.login}`.
 *
 * @remarks
 * These constants exist so server routes and client request URLs stay
 * in sync. Mirrors the `@Controller`/`@Post`/`@Get` declarations in
 * `src/server/controllers/*.ts`. Update both sides together if a route
 * is renamed.
 */

/**
 * Dashboard (tenant user) authentication routes.
 *
 * Mounted at the top of the auth route prefix
 * (`src/server/controllers/auth.controller.ts`).
 */
export const AUTH_DASHBOARD_ROUTES = {
  /** POST — register a new local (email + password) user. */
  register: 'register',
  /** POST — exchange credentials for an access token (or MFA challenge). */
  login: 'login',
  /** POST — revoke the current access and refresh tokens. */
  logout: 'logout',
  /** POST — rotate a valid refresh token for a fresh access token. */
  refresh: 'refresh',
  /** GET — return the currently authenticated user. */
  me: 'me',
  /** POST — submit the email-verification token returned by the verification email. */
  verifyEmail: 'verify-email',
  /** POST — request a fresh email-verification token. */
  resendVerification: 'resend-verification'
} as const

/**
 * MFA (TOTP) routes.
 *
 * Mounted under `mfa/` (`src/server/controllers/mfa.controller.ts`).
 */
export const AUTH_MFA_ROUTES = {
  /** POST — begin TOTP enrollment and return the secret + provisioning URI. */
  setup: 'mfa/setup',
  /** POST — confirm TOTP enrollment by submitting the first valid code. */
  verifyEnable: 'mfa/verify-enable',
  /** POST — exchange an MFA temp token + OTP for a full access token. */
  challenge: 'mfa/challenge',
  /** POST — disable MFA after re-authenticating with a fresh OTP. */
  disable: 'mfa/disable'
} as const

/**
 * Password reset routes.
 *
 * Mounted under `password/`
 * (`src/server/controllers/password-reset.controller.ts`).
 */
export const AUTH_PASSWORD_ROUTES = {
  /** POST — request a password reset (email lookup is anti-enumeration). */
  forgotPassword: 'password/forgot-password',
  /** POST — submit a new password using the reset token. */
  resetPassword: 'password/reset-password',
  /** POST — verify the reset OTP (when `passwordReset.method = 'otp'`). */
  verifyOtp: 'password/verify-otp',
  /** POST — request a fresh OTP after the previous one expired. */
  resendOtp: 'password/resend-otp'
} as const

/**
 * Platform administrator routes.
 *
 * Mounted under `platform/`
 * (`src/server/controllers/platform-auth.controller.ts`).
 */
export const AUTH_PLATFORM_ROUTES = {
  /** POST — exchange platform admin credentials for an access token. */
  login: 'platform/login',
  /** POST — exchange an MFA temp token + OTP for a platform access token. */
  mfaChallenge: 'platform/mfa/challenge',
  /** GET — return the currently authenticated platform administrator. */
  me: 'platform/me',
  /** POST — revoke the platform access and refresh tokens. */
  logout: 'platform/logout',
  /** POST — rotate a platform refresh token for a fresh access token. */
  refresh: 'platform/refresh',
  /** DELETE — revoke every active session for the current platform admin. */
  revokeAllSessions: 'platform/sessions'
} as const

/**
 * Session management routes (`controllers.sessions: true`).
 *
 * Mounted under `sessions/`
 * (`src/server/controllers/session.controller.ts`).
 */
export const AUTH_SESSION_ROUTES = {
  /** GET — list every active session for the current user. */
  list: 'sessions',
  /** DELETE — revoke every session belonging to the current user. */
  revokeAll: 'sessions/all',
  /**
   * DELETE — revoke a single session by id. The `:id` placeholder must be
   * substituted with the session identifier before the request is issued.
   */
  revokeOne: 'sessions/:id'
} as const

/**
 * Invitation routes (`controllers.invitations: true`).
 *
 * Mounted under `invitations/`
 * (`src/server/controllers/invitation.controller.ts`).
 */
export const AUTH_INVITATION_ROUTES = {
  /** POST — create a new invitation (admin-only). */
  create: 'invitations',
  /** POST — accept an invitation token and register the recipient. */
  accept: 'invitations/accept'
} as const

/**
 * Aggregated route map grouped by domain.
 *
 * Provides a single import point for client code that needs to reach
 * multiple route families.
 */
export const AUTH_ROUTES = {
  dashboard: AUTH_DASHBOARD_ROUTES,
  mfa: AUTH_MFA_ROUTES,
  password: AUTH_PASSWORD_ROUTES,
  platform: AUTH_PLATFORM_ROUTES,
  sessions: AUTH_SESSION_ROUTES,
  invitations: AUTH_INVITATION_ROUTES
} as const

/**
 * Default Next.js proxy endpoints used by `createAuthClient` and the
 * Next.js helper handlers in the `nextjs` subpath.
 *
 * These are the front-channel proxy routes a Next.js application is
 * expected to expose under `app/api/auth/*`. They translate browser
 * requests into upstream NestJS calls while keeping cookies HttpOnly.
 */
export const AUTH_PROXY_ROUTES = {
  /** POST — same-domain refresh entry point (server-to-server). */
  clientRefresh: '/api/auth/client-refresh',
  /** GET — invisible refresh used by the proxy to reissue tokens. */
  silentRefresh: '/api/auth/silent-refresh',
  /** POST — Next.js logout proxy (clears cookies + revokes server-side). */
  logout: '/api/auth/logout'
} as const

/**
 * Controller-relative path fragments that must NEVER trigger an
 * automatic refresh when they return 401.
 *
 * Used by {@link buildAuthRefreshSkipSuffixes} together with the
 * consumer's `routePrefix` to produce the absolute skip list at
 * `createAuthFetch` time.
 */
const AUTH_REFRESH_SKIP_CONTROLLER_PATHS = [
  // Dashboard auth-issuing endpoints
  'register',
  'login',
  'refresh',
  'logout',
  'verify-email',
  'resend-verification',
  // Password reset endpoints
  'password/forgot-password',
  'password/reset-password',
  'password/verify-otp',
  'password/resend-otp',
  // MFA endpoints
  'mfa/setup',
  'mfa/verify-enable',
  'mfa/challenge',
  'mfa/disable',
  // Invitation acceptance issues tokens
  'invitations/accept',
  // Platform endpoints
  'platform/login',
  'platform/refresh',
  'platform/logout',
  'platform/mfa/challenge',
  'platform/sessions'
] as const

/**
 * Next.js proxy refresh entry points. Never prefixed by the NestJS
 * `routePrefix` — these are browser-facing Next.js routes that wrap
 * the upstream auth server. Must always be skipped to avoid recursive
 * refresh loops.
 */
const AUTH_REFRESH_SKIP_PROXY_PATHS = [
  '/api/auth/client-refresh',
  '/api/auth/silent-refresh'
] as const

/**
 * Build the pathname-suffix skip list that `createAuthFetch` uses to
 * decide whether a 401 from a given URL should trigger a refresh.
 *
 * Parameterized by `routePrefix` so that deployments using a non-default
 * mount point (e.g. `'authentication'`, `'api/v1/auth'`) get a skip list
 * that actually matches their URLs. The suffixes combine the prefix
 * with every known auth-issuing controller path plus the proxy refresh
 * endpoints (which never carry the server prefix).
 *
 * @param routePrefix - The NestJS `routePrefix` in effect for the
 *   consumer's deployment. Leading/trailing slashes are normalized.
 *   Default is `'auth'` when omitted.
 */
export function buildAuthRefreshSkipSuffixes(routePrefix: string = 'auth'): readonly string[] {
  const normalized = routePrefix.replace(/^\/+|\/+$/g, '')
  const prefix = normalized.length > 0 ? `/${normalized}` : ''
  return [
    ...AUTH_REFRESH_SKIP_CONTROLLER_PATHS.map((path) => `${prefix}/${path}`),
    ...AUTH_REFRESH_SKIP_PROXY_PATHS
  ]
}

/**
 * Default pathname-suffix skip list for the canonical `'auth'` prefix.
 *
 * Exported for backwards compatibility and for consumers who know they
 * use the default prefix. Non-default deployments should call
 * {@link buildAuthRefreshSkipSuffixes} directly or pass `routePrefix`
 * to `createAuthFetch`/`createAuthClient`.
 */
export const AUTH_REFRESH_SKIP_PATH_SUFFIXES = buildAuthRefreshSkipSuffixes()
