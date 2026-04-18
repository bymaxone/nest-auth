/**
 * Barrel export tests for the @bymax-one/nest-auth/shared subpath.
 *
 * Goal: lock the public surface of `src/shared/index.ts` so that
 * accidental removal or rename of an exported constant immediately
 * fails CI. The shared subpath is a contract surface consumed by
 * client + react + nextjs subpaths and by external library users —
 * silent regressions here would break downstream code.
 *
 * All imports MUST go through `../index`, never directly into
 * `../constants/*` or `../types/*`. That guarantees the barrel itself
 * is what we are validating.
 */

import {
  AUTH_ACCESS_COOKIE_NAME,
  AUTH_DASHBOARD_ROUTES,
  AUTH_ERROR_CODES,
  AUTH_HAS_SESSION_COOKIE_NAME,
  AUTH_INVITATION_ROUTES,
  AUTH_MFA_ROUTES,
  AUTH_PASSWORD_ROUTES,
  AUTH_PLATFORM_ROUTES,
  AUTH_PROXY_ROUTES,
  AUTH_REFRESH_COOKIE_NAME,
  AUTH_REFRESH_COOKIE_PATH,
  AUTH_REFRESH_SKIP_PATH_SUFFIXES,
  AUTH_ROUTES,
  AUTH_SESSION_ROUTES,
  AuthClientError
} from '../index'
import type {
  AuthContextKind,
  AuthCookieNames,
  AuthErrorResponse,
  AuthJwtPayload,
  AuthPlatformUserClient,
  AuthResult,
  AuthUserClient,
  DashboardJwtPayload,
  LoginResult,
  MfaChallengeResult,
  MfaTempPayload,
  PlatformAuthResult,
  PlatformJwtPayload,
  PlatformLoginResult,
  TokenDeliveryMode
} from '../index'

// ---------------------------------------------------------------------------
// Constant export coverage
// ---------------------------------------------------------------------------

/**
 * Verifies every advertised constant is reachable through the barrel.
 *
 * If any of these turn `undefined`, downstream code that imports them
 * will compile (TypeScript only erases types) but blow up at runtime
 * with cryptic errors. This block is the early-warning system.
 */
describe('shared barrel — constant exports', () => {
  // The cookie name constants ARE the wire-protocol contract between
  // server and browser; defaultization in the wrong file would break
  // every consumer. Confirm the exact literal values.
  it('exports the cookie defaults with their canonical literal values', () => {
    expect(AUTH_ACCESS_COOKIE_NAME).toBe('access_token')
    expect(AUTH_REFRESH_COOKIE_NAME).toBe('refresh_token')
    expect(AUTH_HAS_SESSION_COOKIE_NAME).toBe('has_session')
    expect(AUTH_REFRESH_COOKIE_PATH).toBe('/auth')
  })

  // Sanity-check that the route maps are present and non-empty objects.
  // A future refactor that accidentally drops one of these groups would
  // be caught here long before any client integration test catches it.
  it('exposes every route family as a non-empty object', () => {
    expect(typeof AUTH_DASHBOARD_ROUTES).toBe('object')
    expect(Object.keys(AUTH_DASHBOARD_ROUTES).length).toBeGreaterThan(0)
    expect(typeof AUTH_MFA_ROUTES).toBe('object')
    expect(Object.keys(AUTH_MFA_ROUTES).length).toBeGreaterThan(0)
    expect(typeof AUTH_PASSWORD_ROUTES).toBe('object')
    expect(Object.keys(AUTH_PASSWORD_ROUTES).length).toBeGreaterThan(0)
    expect(typeof AUTH_PLATFORM_ROUTES).toBe('object')
    expect(Object.keys(AUTH_PLATFORM_ROUTES).length).toBeGreaterThan(0)
    expect(typeof AUTH_SESSION_ROUTES).toBe('object')
    expect(Object.keys(AUTH_SESSION_ROUTES).length).toBeGreaterThan(0)
    expect(typeof AUTH_INVITATION_ROUTES).toBe('object')
    expect(Object.keys(AUTH_INVITATION_ROUTES).length).toBeGreaterThan(0)
    expect(typeof AUTH_PROXY_ROUTES).toBe('object')
    expect(Object.keys(AUTH_PROXY_ROUTES).length).toBeGreaterThan(0)
  })

  // The aggregate map must contain every NestJS controller route family
  // so consumers can reach them through a single import. Missing keys
  // here signal that the barrel composition diverged from the
  // constituent declarations.
  //
  // Note: `AUTH_PROXY_ROUTES` is intentionally NOT part of `AUTH_ROUTES`.
  // It describes Next.js front-channel proxy endpoints (HTTP routes the
  // consuming app exposes under `/api/auth/*`), not server controller
  // paths — mixing the two would invite consumers to ship proxy paths
  // to the NestJS backend or vice versa.
  it('aggregates every server-controller route family inside AUTH_ROUTES', () => {
    expect(AUTH_ROUTES).toMatchObject({
      dashboard: AUTH_DASHBOARD_ROUTES,
      mfa: AUTH_MFA_ROUTES,
      password: AUTH_PASSWORD_ROUTES,
      platform: AUTH_PLATFORM_ROUTES,
      sessions: AUTH_SESSION_ROUTES,
      invitations: AUTH_INVITATION_ROUTES
    })
    expect(AUTH_ROUTES).not.toHaveProperty('proxy')
  })
})

// ---------------------------------------------------------------------------
// Error code surface
// ---------------------------------------------------------------------------

/**
 * The error code constants are the stable identifiers client code
 * branches on. Removing or renaming any of these is a breaking change.
 * The `error-codes.spec.ts` test already guards drift against the
 * server side; this block guards the public re-export.
 */
describe('shared barrel — AUTH_ERROR_CODES', () => {
  // Pin the canonical sentinel codes: a missing one would silently
  // break every consumer that has hard-coded the constant key.
  it('re-exports the canonical sentinel error codes', () => {
    expect(AUTH_ERROR_CODES.INVALID_CREDENTIALS).toBe('auth.invalid_credentials')
    expect(AUTH_ERROR_CODES.TOKEN_INVALID).toBe('auth.token_invalid')
    expect(AUTH_ERROR_CODES.MFA_REQUIRED).toBe('auth.mfa_required')
    expect(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS).toBe('auth.email_already_exists')
  })
})

// ---------------------------------------------------------------------------
// Refresh skip list
// ---------------------------------------------------------------------------

/**
 * `AUTH_REFRESH_SKIP_PATH_SUFFIXES` is the safety net that prevents
 * the auth client from triggering an automatic refresh on a 401
 * returned by an endpoint that itself handles authentication. A miss
 * here causes infinite refresh loops or, worse, swallows real 401s
 * with a misleading "session expired" callback.
 */
describe('shared barrel — AUTH_REFRESH_SKIP_PATH_SUFFIXES', () => {
  // The minimum viable skip set: dashboard login, dashboard refresh,
  // both Next.js refresh proxies, and the MFA challenge exchange.
  it('contains every refresh-loop-critical path suffix', () => {
    expect(AUTH_REFRESH_SKIP_PATH_SUFFIXES).toContain('/auth/login')
    expect(AUTH_REFRESH_SKIP_PATH_SUFFIXES).toContain('/auth/refresh')
    expect(AUTH_REFRESH_SKIP_PATH_SUFFIXES).toContain('/api/auth/client-refresh')
    expect(AUTH_REFRESH_SKIP_PATH_SUFFIXES).toContain('/api/auth/silent-refresh')
    expect(AUTH_REFRESH_SKIP_PATH_SUFFIXES).toContain('/auth/mfa/challenge')
  })
})

// ---------------------------------------------------------------------------
// Route shape spot checks
// ---------------------------------------------------------------------------

/**
 * Cross-domain spot checks: ensure the dashboard and platform variants
 * carry their controller-prefixed values. A mismatch here typically
 * means somebody collapsed two declarations during a refactor.
 */
describe('shared barrel — AUTH_ROUTES shape', () => {
  // Dashboard login is mounted at the top of the auth route prefix,
  // so its value is the bare `login` segment.
  it('keeps the dashboard login path bare (no platform prefix)', () => {
    expect(AUTH_ROUTES.dashboard.login).toBe('login')
  })

  // Platform login lives under the `platform/` controller, so its
  // value carries the `platform/` segment.
  it('keeps the platform login path under the platform/ segment', () => {
    expect(AUTH_ROUTES.platform.login).toBe('platform/login')
  })
})

// ---------------------------------------------------------------------------
// AuthClientError — runtime contract
// ---------------------------------------------------------------------------

/**
 * `AuthClientError` is the only runtime class exported from the
 * shared subpath. It must behave like a real `Error` so that consumer
 * code can use `instanceof` and standard error-handling idioms.
 */
describe('shared barrel — AuthClientError', () => {
  // Verifies prototype chain, property assignment, and the
  // documented contract that `code` is `undefined` when no body is
  // provided. This is the construction smoke test.
  it('produces a real Error instance with the documented properties', () => {
    const err = new AuthClientError('boom', 401)

    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(AuthClientError)
    expect(err.name).toBe('AuthClientError')
    expect(err.message).toBe('boom')
    expect(err.status).toBe(401)
    expect(err.code).toBeUndefined()
    expect(err.body).toBeUndefined()
  })

  // Verifies the security-review fix: `toJSON` must NOT serialize the
  // `body` property because some servers echo request DTO fields into
  // their error responses, and a structured logger that calls
  // `JSON.stringify(error)` would otherwise persist those fields.
  it('toJSON() omits the raw body to avoid logging sensitive request echoes', () => {
    const err = new AuthClientError('forbidden', 403, {
      message: 'forbidden',
      error: 'Forbidden',
      statusCode: 403,
      code: 'auth.forbidden'
    })

    const serialized = err.toJSON()

    expect(serialized).toEqual({
      name: 'AuthClientError',
      message: 'forbidden',
      status: 403,
      code: 'auth.forbidden'
    })
    expect((serialized as Record<string, unknown>)['body']).toBeUndefined()
  })

  // Verifies that when JSON.stringify is invoked on the error (the
  // common path inside structured loggers), the resulting string
  // does NOT contain the body payload — the same guarantee as the
  // direct `toJSON()` call but exercised through the JSON.stringify
  // contract.
  it('JSON.stringify(error) does not leak the body payload', () => {
    const err = new AuthClientError('forbidden', 403, {
      message: 'forbidden',
      error: 'Forbidden',
      statusCode: 403,
      code: 'auth.forbidden'
    })

    const json = JSON.stringify(err)

    expect(json).not.toContain('body')
    expect(json).toContain('"code":"auth.forbidden"')
  })
})

// ---------------------------------------------------------------------------
// Type-only smoke test
// ---------------------------------------------------------------------------

/**
 * Compile-time assertion: the listed types are exported and assignable.
 * The function is never called — its mere presence proves the imports
 * resolve. If any of these types vanish from the barrel, this file
 * fails to type-check, which fails the test run before any
 * assertion runs.
 */
function _typeSmoke(
  user: AuthUserClient,
  platformUser: AuthPlatformUserClient,
  result: AuthResult,
  loginResult: LoginResult,
  platformResult: PlatformAuthResult,
  platformLoginResult: PlatformLoginResult,
  challenge: MfaChallengeResult,
  errorBody: AuthErrorResponse,
  dashboardPayload: DashboardJwtPayload,
  platformPayload: PlatformJwtPayload,
  mfaPayload: MfaTempPayload,
  anyPayload: AuthJwtPayload,
  contextKind: AuthContextKind,
  cookieNames: AuthCookieNames,
  tokenDelivery: TokenDeliveryMode
): void {
  void user
  void platformUser
  void result
  void loginResult
  void platformResult
  void platformLoginResult
  void challenge
  void errorBody
  void dashboardPayload
  void platformPayload
  void mfaPayload
  void anyPayload
  void contextKind
  void cookieNames
  void tokenDelivery
}

/**
 * The runtime side of the barrel only needs a tiny placeholder so
 * that Jest does not flag the suite as test-less and so `_typeSmoke`
 * is referenced (silencing the unused-symbol lint).
 */
describe('shared barrel — type smoke', () => {
  // Confirms the helper is importable and its identity has not been
  // tree-shaken away (defense-in-depth against an aggressive bundler
  // future-config).
  it('keeps the type-only helper reachable', () => {
    expect(typeof _typeSmoke).toBe('function')
  })
})
