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
  /** POST — mint a single-use ticket for a WebSocket upgrade. */
  wsTicket: 'ws-ticket',
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
  disable: 'mfa/disable',
  /** POST — replace the recovery codes, re-authenticating with a fresh OTP. */
  recoveryCodes: 'mfa/recovery-codes'
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
  /**
   * POST — change the password of the signed-in user, verifying the current one.
   *
   * The only route in this family behind the JWT guard: the rest are reached by a
   * caller who has no session, which is what a reset is for.
   */
  changePassword: 'password/change',
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
 * Platform administrator MFA routes (`controllers.platform: true`).
 *
 * Mounted under `platform/mfa/`
 * (`src/server/controllers/platform-mfa.controller.ts`). A separate family because the
 * controller is separate, NOT because the switch is: `controllers.platform: true` mounts
 * `PlatformAuthController` and `PlatformMfaController` together, and there is no
 * `controllers.platformMfa` option to turn one on without the other. The platform plane requires
 * MFA of its administrators, so a deployment that could mount the login surface without the
 * enrollment surface would be one where an operator can be required to present a second factor
 * they have no endpoint to set up.
 *
 * The challenge is NOT here — it belongs to the login flow on `PlatformAuthController`, which is
 * why it sits with the routes that issue credentials rather than with the ones that manage them.
 */
export const AUTH_PLATFORM_MFA_ROUTES = {
  /** POST — begin TOTP enrollment for a platform administrator. */
  setup: 'platform/mfa/setup',
  /** POST — confirm enrollment by submitting the first valid code. */
  verifyEnable: 'platform/mfa/verify-enable',
  /** POST — disable MFA after re-authenticating with a fresh OTP. */
  disable: 'platform/mfa/disable',
  /** POST — replace the recovery codes, re-authenticating with a fresh OTP. */
  recoveryCodes: 'platform/mfa/recovery-codes'
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
  /**
   * POST — revoke every session belonging to the current user except the one
   * making the call.
   *
   * POST rather than DELETE because the refresh token that names the current
   * session travels in the body under `tokenDelivery: 'bearer'`, and OpenAPI 3.0.3
   * defers to RFC 7231: a payload on DELETE has no defined semantics, so a
   * generated client drops it.
   */
  revokeAll: 'sessions/revoke-all',
  /**
   * DELETE — revoke a single session by id. The `:id` placeholder must be
   * substituted with the session identifier before the request is issued.
   */
  revokeOne: 'sessions/:id'
} as const

/**
 * Address-change routes (`controllers.emailChange: true`).
 *
 * Mounted under `email/` (`src/server/controllers/email-change.controller.ts`).
 */
export const AUTH_EMAIL_CHANGE_ROUTES = {
  /** POST — request a change; mails a token to the new address. */
  request: 'email/change',
  /** POST — confirm the change with that token. */
  confirm: 'email/change/confirm'
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
  accept: 'invitations/accept',
  /** POST — withdraw a pending invitation before it is accepted (admin-only). */
  revoke: 'invitations/revoke'
} as const

/**
 * OAuth routes (`oauth.google` configured).
 *
 * Mounted under `oauth/` (`src/server/oauth/oauth.controller.ts`). Both carry a
 * `:provider` segment that must be substituted before the request is issued —
 * `'google'` is the only provider this library implements today.
 */
export const AUTH_OAUTH_ROUTES = {
  /** GET — redirect the browser to the provider's consent screen. */
  initiate: 'oauth/:provider',
  /** GET — the provider redirects back here with the authorization code. */
  callback: 'oauth/:provider/callback'
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
  platformMfa: AUTH_PLATFORM_MFA_ROUTES,
  sessions: AUTH_SESSION_ROUTES,
  invitations: AUTH_INVITATION_ROUTES,
  emailChange: AUTH_EMAIL_CHANGE_ROUTES,
  oauth: AUTH_OAUTH_ROUTES
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
 * Controller-relative path fragments where a refresh can NEVER help, whatever the 401 says: the
 * token endpoints (recursion), the credential-issuing ones (no session yet), and the platform
 * surface (another plane — a dashboard refresh cannot fix a platform token).
 *
 * NOT how a credential failure is recognised: `createAuthFetch` reads the error code first, and
 * only `auth.token_invalid` means "expired". That also covers routes a path list never could —
 * `password/change` is JWT-guarded, so an expired token and a wrong password 401 from one path.
 *
 * The dashboard MFA endpoints are deliberately absent for that reason: they are JWT-guarded, so
 * skipping them would refuse to refresh a session that only needed refreshing.
 *
 * Used by {@link buildAuthRefreshSkipSuffixes} with the consumer's `routePrefix`.
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
  // The MFA challenge issues the session — there is none to refresh. Its siblings
  // (`mfa/setup`, `mfa/verify-enable`, `mfa/disable`) are NOT here: they are JWT-guarded, so a
  // 401 there can be a genuine expiry, and their credential failures are recognised by code.
  'mfa/challenge',
  // Invitation acceptance issues tokens
  'invitations/accept',
  // The address-change confirmation is public: the holder is proving control of a mailbox,
  // not of a session.
  'email/change/confirm',
  // The platform surface, ALL of it. Every protected route here is JWT-PLATFORM-guarded, so an
  // expired platform token answers `auth.token_invalid` — the code the client reads as "expired"
  // — and a dashboard refresh cannot fix another plane's credential. Listing only some of them
  // left the rest launching a refresh that spends the budget and can call `onSessionExpired` for
  // a dashboard session that is perfectly healthy.
  'platform/login',
  'platform/refresh',
  'platform/logout',
  'platform/me',
  'platform/sessions',
  'platform/mfa/challenge',
  'platform/mfa/setup',
  'platform/mfa/verify-enable',
  'platform/mfa/disable',
  'platform/mfa/recovery-codes'
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
 * Strip leading and trailing `/` characters without a regular expression.
 *
 * The obvious `replace(/^\/+|\/+$/g, '')` is quadratic on a run of slashes — the `$`-anchored
 * alternative backtracks over every prefix of the run — which CodeQL flags as a polynomial
 * ReDoS. The input here is deployment configuration rather than anything a caller sends, so it
 * was never reachable in practice; a scan cannot know that, and neither can the next reader.
 * A pair of scans is linear and says what it does.
 *
 * @param value - The string to trim.
 * @returns `value` with every leading and trailing `/` removed.
 */
function trimSlashes(value: string): string {
  let start = 0
  let end = value.length
  // Block form because the reason spans both lines and a wrapped `next-line` binds to its own
  // continuation.
  //
  // Stryker disable ConditionalExpression,EqualityOperator: the index bounds cannot be observed.
  // `end` starts at `value.length`, so a scan that runs past the run of slashes reads `undefined`
  // and stops on the character test alone; and a bound that lets the two cross produces a
  // reversed range, which `slice` returns as `''` — the same answer the un-crossed range gives
  // for an all-slash input. They are here so each loop states its own invariant rather than
  // relying on the lookup falling off the end
  while (start < end && value[start] === '/') start += 1
  while (end > start && value[end - 1] === '/') end -= 1
  // Stryker restore ConditionalExpression,EqualityOperator
  return value.slice(start, end)
}

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
  const normalized = trimSlashes(routePrefix)
  const prefix = normalized.length > 0 ? `/${normalized}` : ''
  return [
    ...AUTH_REFRESH_SKIP_CONTROLLER_PATHS.map((path) => `${prefix}/${path}`),
    ...AUTH_REFRESH_SKIP_PROXY_PATHS
  ]
}

/**
 * Default pathname-suffix skip list for the canonical `'auth'` prefix.
 *
 * A convenience for the overwhelmingly common case — the default `routePrefix: 'auth'` —
 * so a consumer on it does not have to call the builder to get the same array. Any other
 * prefix must call {@link buildAuthRefreshSkipSuffixes} or pass `routePrefix` to
 * `createAuthFetch` / `createAuthClient`: this list would silently skip the wrong paths.
 */
export const AUTH_REFRESH_SKIP_PATH_SUFFIXES = buildAuthRefreshSkipSuffixes()
