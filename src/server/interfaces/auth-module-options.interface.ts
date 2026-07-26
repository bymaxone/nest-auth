/**
 * @fileoverview Main configuration contract for {@link BymaxAuthModule}.
 *
 * Defines `BymaxAuthModuleOptions` and all nested option groups consumed by
 * `resolveOptions()` at module initialisation time.
 *
 * @layer Interface
 */
import type {
  InjectionToken,
  ModuleMetadata,
  OptionalFactoryDependency,
  Provider
} from '@nestjs/common'
import type { Request } from 'express'

import type { AuthUser } from './user-repository.interface'

/**
 * Main configuration interface for BymaxAuthModule.
 *
 * Passed to `BymaxAuthModule.registerAsync()`. All groups except `jwt` and
 * `roles` are optional — unconfigured features are not registered in the
 * NestJS container (zero overhead).
 *
 * @remarks
 * Only the asynchronous registration entry point (`registerAsync`) is exposed
 * by the module. A synchronous `register()` is intentionally omitted because
 * the module always validates the resolved options at startup, which fits the
 * `useFactory` flow used by virtually every NestJS app (e.g. injecting
 * `ConfigService`).
 *
 * @example
 * ```ts
 * BymaxAuthModule.registerAsync({
 *   useFactory: () => ({
 *     jwt: { secret: process.env.JWT_SECRET! },
 *     roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } }
 *   })
 * })
 * ```
 */
export interface BymaxAuthModuleOptions {
  /**
   * JWT signing configuration.
   * `secret` is required and must be at least 32 characters with sufficient entropy.
   */
  jwt: {
    /**
     * JWT signing secret. **Required.**
     *
     * Security requirements:
     * - Minimum 32 characters
     * - Shannon entropy >= 3.5 bits/char (no repetitive patterns)
     * - Recommended: `crypto.randomBytes(32).toString('base64')` (~44 chars, ~5.9 bits/char)
     *
     * `resolveOptions()` validates this at module startup and throws if requirements are not met.
     * The secret value is never logged — only its length and entropy are reported in error messages.
     *
     * @throws {Error} When the value fails validation at module initialisation.
     */
    secret: string

    /**
     * Access token expiration expressed as a time string (e.g. `'15m'`, `'1h'`).
     * Default: `'15m'`
     */
    accessExpiresIn?: string

    /**
     * Access token cookie `Max-Age` in milliseconds.
     * Default: `900_000` (15 minutes, matching `accessExpiresIn`)
     */
    accessCookieMaxAgeMs?: number

    /**
     * Refresh token lifetime in days.
     * Default: `7`
     */
    refreshExpiresInDays?: number

    /**
     * JWT signing algorithm. Only `'HS256'` is supported.
     * Default: `'HS256'`
     *
     * @remarks
     * Asymmetric algorithms (RS256, ES256) are intentionally unsupported to prevent
     * algorithm confusion attacks. This value is pinned in all guards via `algorithms: ['HS256']`.
     */
    algorithm?: 'HS256'

    /**
     * Grace window in seconds during which the old refresh token remains valid
     * after rotation. Prevents race conditions on concurrent requests.
     * Default: `30`
     */
    refreshGraceWindowSeconds?: number
  }

  /**
   * Password hashing configuration (scrypt parameters).
   * All fields have secure defaults — only change if you understand the security implications.
   */
  password?: {
    /**
     * scrypt CPU/memory cost factor (N). Must be a power of 2.
     * Default: `32768` (2^15). Minimum enforced by `resolveOptions()`: `16384` (2^14).
     * Values below `16384` are rejected at startup — do not lower this for production workloads.
     *
     * @throws {Error} When the value fails validation at module initialisation.
     */
    costFactor?: number

    /**
     * scrypt block size parameter (r).
     * Default: `8`
     */
    blockSize?: number

    /**
     * scrypt parallelization parameter (p).
     * Default: `1`
     */
    parallelization?: number
  }

  /**
   * Token delivery mode.
   *
   * - `'cookie'`  — HTTP-only cookies (recommended for web/SPA with same-origin API)
   * - `'bearer'`  — tokens returned in response body; guards extract from `Authorization: Bearer`
   *                 (recommended for React Native, mobile, or cookie-hostile clients)
   * - `'both'`    — sets cookies AND returns tokens in body; guards accept either
   *                 (useful when the same backend serves both web and mobile)
   *
   * Default: `'cookie'`
   */
  tokenDelivery?: 'cookie' | 'bearer' | 'both'

  /**
   * Whether to set the `Secure` flag on auth cookies.
   *
   * When `true`, cookies are only sent over HTTPS. When `false`, cookies are
   * sent over HTTP as well (useful for local development).
   *
   * Default: `process.env['NODE_ENV'] === 'production'` (evaluated once at module
   * startup via `resolveOptions()` — not re-evaluated per request).
   *
   * @remarks
   * Override this explicitly in staging environments that do not set
   * `NODE_ENV=production` but are served over HTTPS, to ensure cookies are
   * marked Secure regardless of the environment variable.
   */
  secureCookies?: boolean

  /**
   * HTTP cookie configuration.
   * Ignored when `tokenDelivery: 'bearer'`.
   */
  cookies?: {
    /** Cookie name for the access token. Default: `'access_token'` */
    accessTokenName?: string

    /** Cookie name for the refresh token. Default: `'refresh_token'` */
    refreshTokenName?: string

    /**
     * Cookie name for the session signal (non-httpOnly, readable by JS to detect login state).
     * Default: `'has_session'`
     */
    sessionSignalName?: string

    /**
     * `Path` attribute for the refresh token cookie. Restricts cookie to the refresh endpoint.
     * Default: `'/auth'`
     *
     * @remarks
     * A warning is logged at startup if `routePrefix` differs from `'auth'` and this is not set.
     */
    refreshCookiePath?: string

    /**
     * `Path` attribute for the short-lived `mfa_temp_token` cookie planted
     * by the OAuth callback (lib v1.0.7+) and cleared by the MFA challenge
     * controller. Defaults to `/${routePrefix}/mfa` — correct when the
     * lib's routes are mounted at the root path (no Nest global prefix).
     *
     * Set this explicitly when the consumer calls `app.setGlobalPrefix(...)`
     * because the library cannot observe the global prefix at module
     * construction time. For example, with `setGlobalPrefix('api')` and
     * default `routePrefix: 'auth'`, the real challenge URL is
     * `/api/auth/mfa/challenge` — but `Path=/auth/mfa` will NOT be sent
     * by the browser (RFC 6265 prefix-match). Set this to `'/api/auth/mfa'`
     * so the cookie scopes to the actual challenge endpoint.
     *
     * Must start with `/` and exactly match the directory portion of the
     * real `/mfa/*` route path. Validated at startup.
     *
     * @throws {Error} When the value fails validation at module initialisation.
     *
     * @example
     * ```ts
     * // App calls `app.setGlobalPrefix('api')` and uses default routePrefix:
     * { cookies: { mfaTempCookiePath: '/api/auth/mfa' } }
     * ```
     */
    mfaTempCookiePath?: string

    /**
     * Resolves cookie domains from the request's hostname.
     * Useful for multi-domain support (e.g. `api.example.com` and `app.example.com`).
     *
     * @param requestDomain - The hostname extracted from the incoming request.
     * @returns Array of domain strings where cookies should be set (e.g. `['.example.com']`).
     */
    resolveDomains?: (requestDomain: string) => string[]

    /**
     * `SameSite` attribute applied to every cookie issued by the module
     * (access token, refresh token, session signal). Default: `'lax'`.
     *
     * Trade-offs:
     * - `'lax'` (default): cookies travel on top-level cross-site GET navigations.
     *   This is the standard posture for browser auth — OAuth redirects from a
     *   provider (Google, GitHub, …) back to the app deliver the auth cookies on
     *   the first navigation, which is exactly what users expect after sign-in.
     *   Aligns with Chromium's behavior for cookies that omit `SameSite`.
     * - `'strict'`: cookies are withheld on every cross-site request, including
     *   the OAuth return-trip. Choose this only when the app does not use
     *   third-party identity providers and the extra CSRF margin justifies the
     *   broken OAuth flow.
     * - `'none'`: cookies are sent on every cross-site request. The browser
     *   requires `Secure` for `SameSite=None`, so the resolver throws at startup
     *   when this combination would be unset (`secureCookies` must be `true`).
     *   Pick this for embedded scenarios (iframes, third-party widgets).
     */
    sameSite?: 'lax' | 'strict' | 'none'

    /**
     * Origins allowed to make state-changing requests that carry the session cookie.
     * Default: `[]`.
     *
     * Each entry is a full origin — scheme, host and, when non-default, port
     * (`'https://app.example.com'`, `'http://localhost:3000'`) — compared verbatim against the
     * request's `Origin` header. No wildcards: an origin allowlist that matches by pattern is
     * one typo away from allowing an attacker-controlled subdomain.
     *
     * This only matters with `sameSite: 'none'`. Under `'lax'` or `'strict'` the browser does
     * not send the cookie cross-site at all, so there is nothing to authorize; the resolver
     * warns when the two settings disagree, because a `'none'` deployment with an empty list
     * rejects every cross-site call and one with a list but `'lax'` never uses it.
     *
     * @example
     * ```ts
     * { cookies: { sameSite: 'none', trustedOrigins: ['https://app.example.com'] } }
     * ```
     */
    trustedOrigins?: string[]
  }

  /**
   * Per-IP rate limiting of the auth routes, enforced by the library itself.
   */
  rateLimit?: {
    /**
     * Whether the library enforces the per-route limits in `AUTH_THROTTLE_CONFIGS`.
     * Default: `true`.
     *
     * Those numbers used to be advisory — they took effect only if the host wired
     * `ThrottlerModule` and registered its guard, and a deployment that did not ran every auth
     * route unlimited without being told. The library now enforces them itself, backed by the
     * same Redis counter as the brute-force lockout, so the limit also holds across instances.
     *
     * Set `false` when the same limits are already enforced at the edge (an API gateway, a
     * WAF, or a host-side `ThrottlerModule`) and counting twice is not wanted.
     */
    enabled?: boolean
  }

  /**
   * Multi-factor authentication (MFA/TOTP) configuration.
   * When provided, `encryptionKey` and `issuer` are required.
   */
  mfa?: {
    /**
     * AES-256-GCM encryption key for TOTP secrets. **Required if MFA is configured.**
     *
     * Must decode from base64 to exactly 32 bytes.
     * Generate with: `crypto.randomBytes(32).toString('base64')` (44 chars).
     *
     * `resolveOptions()` validates this at startup and throws if the decoded length is wrong.
     *
     * @throws {Error} When the value fails validation at module initialisation.
     */
    encryptionKey: string

    /**
     * Issuer name displayed in authenticator apps (e.g. `'My App'`, `'Acme Corp'`).
     * **Required if MFA is configured.**
     */
    issuer: string

    /**
     * Number of recovery codes generated when MFA is enabled.
     * Default: `8`
     */
    recoveryCodeCount?: number

    /**
     * TOTP validation window — number of 30-second periods to accept on either side of now.
     * Default: `1` (accepts codes from the previous and next 30-second window)
     */
    totpWindow?: number
  }

  /**
   * Session management configuration.
   * Sessions are disabled by default — enabling adds Redis-backed session tracking.
   */
  sessions?: {
    /**
     * Enables session management (concurrent session limits, device tracking, alerts).
     * Default: `false`
     */
    enabled?: boolean

    /**
     * Default maximum number of concurrent sessions per user.
     * Default: `5`. When `maxSessionsResolver` is provided, this value is ignored.
     */
    defaultMaxSessions?: number

    /**
     * Per-user session limit resolver. When provided, overrides `defaultMaxSessions`.
     * Allows different limits per plan or role.
     *
     * @param user - The authenticated user
     * @returns Maximum number of concurrent sessions for this user
     */
    maxSessionsResolver?: (user: AuthUser) => number | Promise<number>

    /**
     * Eviction strategy when the session limit is reached.
     * `'fifo'` removes the oldest session to make room for the new one.
     * Default: `'fifo'`
     *
     * @remarks
     * Under FIFO eviction, an attacker who establishes a new session will silently
     * evict a legitimate user's session with no visible signal. Implement the
     * `onSessionEvicted` hook in your `IAuthHooks` class to detect and alert on
     * unexpected evictions, which may indicate an account takeover attempt.
     */
    evictionStrategy?: 'fifo'
  }

  /**
   * Brute-force login protection configuration.
   * Uses Redis-backed attempt counters with automatic expiry.
   */
  bruteForce?: {
    /**
     * Maximum number of failed login attempts before lockout.
     * Default: `10`
     */
    maxAttempts?: number

    /**
     * Sliding window duration in seconds for attempt counting.
     * Default: `900` (15 minutes)
     */
    windowSeconds?: number
  }

  /**
   * Password reset flow configuration.
   */
  passwordReset?: {
    /**
     * Reset method.
     * - `'token'` — sends a signed URL with an embedded token (link via email)
     * - `'otp'`   — sends a short numeric code (OTP via email)
     *
     * Default: `'token'`
     */
    method?: 'token' | 'otp'

    /**
     * TTL for reset tokens in seconds.
     * Default: `3600` (1 hour)
     */
    tokenTtlSeconds?: number

    /**
     * TTL for OTP codes in seconds.
     * Default: `600` (10 minutes)
     */
    otpTtlSeconds?: number

    /**
     * Length of the numeric OTP code.
     * Must be between 4 and 8 (inclusive) to stay within `Number.MAX_SAFE_INTEGER`
     * for `crypto.randomInt`. Values outside this range are rejected by `resolveOptions()`
     * at startup with a descriptive error.
     * Default: `6`
     *
     * @throws {Error} When the value fails validation at module initialisation.
     */
    otpLength?: number
  }

  /**
   * Email verification configuration.
   */
  emailVerification?: {
    /**
     * When `true`, users must verify their email before they can log in.
     * Default: `false`
     */
    required?: boolean

    /**
     * TTL for email verification OTP codes in seconds.
     * Default: `600` (10 minutes)
     */
    otpTtlSeconds?: number
  }

  /**
   * Platform administration module configuration.
   * When enabled, registers platform admin endpoints and guards.
   */
  platform?: {
    /**
     * Enables platform admin login, guards, and controllers.
     * Requires `roles.platformHierarchy` to be defined.
     * Default: `false`
     */
    enabled?: boolean
  }

  /**
   * User invitation system configuration.
   */
  invitations?: {
    /**
     * Enables the invitation system (send, accept, revoke invitations).
     * Default: `false`
     */
    enabled?: boolean

    /**
     * TTL for invitation tokens in seconds.
     * Default: `172800` (48 hours)
     */
    tokenTtlSeconds?: number
  }

  /**
   * Role hierarchy configuration. **Required.**
   *
   * The hierarchy must be fully denormalized: each role lists ALL roles it transitively includes.
   * `hasRole()` performs a single-level lookup — it does NOT traverse the graph recursively.
   *
   * @example
   * ```ts
   * // OWNER includes ADMIN, MEMBER, and VIEWER transitively
   * roles: {
   *   hierarchy: {
   *     OWNER:  ['ADMIN', 'MEMBER', 'VIEWER'],
   *     ADMIN:  ['MEMBER', 'VIEWER'],
   *     MEMBER: ['VIEWER'],
   *     VIEWER: [],
   *   },
   * }
   * ```
   */
  roles: {
    /**
     * Dashboard/tenant role hierarchy. **Required.**
     * Must not be an empty object — `resolveOptions()` throws if it is.
     */
    hierarchy: Record<string, string[]>

    /**
     * Platform admin role hierarchy.
     * Required when `platform.enabled = true`.
     */
    platformHierarchy?: Record<string, string[]>
  }

  /**
   * Account statuses that block login access.
   * Users with any of these statuses receive `ACCOUNT_LOCKED` / `ACCOUNT_BANNED` errors.
   * Default: `['BANNED', 'INACTIVE', 'SUSPENDED']`
   */
  blockedStatuses?: string[]

  /**
   * Redis key namespace prefix.
   * All Redis keys managed by this module are prefixed with `{redisNamespace}:`.
   * Default: `'auth'`
   */
  redisNamespace?: string

  /**
   * OAuth provider configurations.
   * Each provider block is optional — only configured providers are registered.
   */
  oauth?: {
    /**
     * URL the browser is redirected to after a successful OAuth callback.
     *
     * When set, the OAuth callback endpoint issues a `302` to this URL after
     * delivering tokens (cookies are still set via the same response). When
     * omitted, the callback returns a JSON body — appropriate for API/SPA
     * consumers that XHR/fetch the callback URL, but it leaves browser users
     * staring at a JSON page. Set this for any consumer where the OAuth flow
     * is initiated by a full-page browser navigation.
     *
     * Requires `tokenDelivery: 'cookie'` or `'both'` — bearer-only delivery is
     * incompatible with a redirect because the access token would be discarded
     * in the redirect response body. The module throws at startup if the
     * combination is misconfigured.
     *
     * In production (`NODE_ENV === 'production'`), the URL must use HTTPS or
     * be a relative path (starts with `/`) — same posture as `callbackUrl`.
     *
     * @throws {Error} When the value fails validation at module initialisation.
     *
     * @example
     * ```typescript
     * successRedirectUrl: 'https://app.example.com/dashboard'
     * // or, for same-origin deployments:
     * successRedirectUrl: '/dashboard'
     * ```
     */
    successRedirectUrl?: string

    /**
     * URL the browser is redirected to when an OAuth callback completes for
     * an MFA-enabled user — BEFORE any session tokens are issued.
     *
     * Resolves a critical UX gap for the OAuth + MFA combination: today, an
     * MFA-enabled user who signs in via OAuth would receive session cookies
     * with `mfaVerified: false`, which the global `MfaRequiredGuard` rejects
     * on every subsequent request — leaving the user locked out with no
     * surfaced path forward. With this option set, the lib instead plants a
     * short-lived `mfa_temp_token` HttpOnly cookie (Path scoped to the MFA
     * challenge endpoint, 5-minute TTL matching the underlying JWT) and
     * redirects the browser to the
     * configured URL where the consumer collects the TOTP/recovery code and
     * POSTs to `/auth/mfa/challenge` to complete the flow.
     *
     * When omitted, the callback returns a JSON body
     * `{ mfaRequired: true, mfaTempToken }` instead — appropriate for SPA
     * consumers that drive the redirect client-side.
     *
     * Same security posture as `successRedirectUrl`: must be a non-empty
     * string, and in production it must use HTTPS or be a same-origin path
     * (`/...`). Independent of `tokenDelivery` because the MFA temp token
     * always travels via the dedicated cookie/JSON channel — bearer mode is
     * accepted here.
     *
     * @example
     * ```typescript
     * mfaRedirectUrl: 'https://app.example.com/auth/mfa-challenge'
     * // or, for same-origin deployments:
     * mfaRedirectUrl: '/auth/mfa-challenge'
     * ```
     */
    mfaRedirectUrl?: string

    /**
     * URL the browser is redirected to when an OAuth callback fails with an
     * `AuthException` (e.g. invalid state, plugin error, hook rejected).
     *
     * Symmetric polish for `successRedirectUrl`: today, an OAuth failure
     * propagates as a raw JSON 401/500 response, which leaves browser users
     * looking at machine-readable output instead of a friendly error page.
     * When set, the controller redirects to the configured URL and appends
     * `?error=<code>` (e.g. `?error=oauth_failed`) so the destination page
     * can branch on the failure reason. Existing query parameters on the URL
     * are preserved (uses the `URL` constructor).
     *
     * Only `AuthException` errors trigger the redirect — unexpected
     * exceptions (programmer errors, infrastructure failures) propagate so
     * they are surfaced to monitoring instead of silently swallowed.
     *
     * Same security posture as `successRedirectUrl`: must be a non-empty
     * string, and in production it must use HTTPS or be a same-origin path.
     *
     * @example
     * ```typescript
     * errorRedirectUrl: 'https://app.example.com/auth/error'
     * // or, for same-origin deployments:
     * errorRedirectUrl: '/auth/error'
     * ```
     */
    errorRedirectUrl?: string

    /**
     * Google OAuth 2.0 configuration.
     * All three fields are required to enable Google login.
     */
    google?: {
      /** Google OAuth client ID from Google Cloud Console. */
      clientId: string
      /**
       * Google OAuth client secret from Google Cloud Console.
       * @remarks Never log this value. Treat with the same care as `jwt.secret`.
       * The consuming `resolveOptions()` implementation must redact this field
       * before any diagnostic logging.
       */
      clientSecret: string
      /** Absolute URL for the OAuth callback (must match Google Console configuration). */
      callbackUrl: string
      /**
       * OAuth scopes to request from Google.
       * Defaults to `['openid', 'email', 'profile']` when not specified.
       *
       * @example
       * ```typescript
       * scope: ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/calendar.readonly']
       * ```
       */
      scope?: string[]
    }
  }

  /**
   * Route prefix applied to all endpoints registered by this module.
   * Default: `'auth'`
   *
   * @example
   * With `routePrefix: 'auth'`, routes become `/auth/login`, `/auth/register`, etc.
   */
  routePrefix?: string

  /**
   * Tenant ID resolver function.
   *
   * When provided, the module resolves the tenant ID from the request object and
   * **ignores** any `tenantId` field in the request body. This prevents tenant
   * spoofing where a client sends a different tenant's ID.
   *
   * @param req - The Express request object
   * @returns The tenant ID string, or a Promise resolving to it
   *
   * @throws {Error} When the resolver returns an empty string or throws.
   *
   * @remarks
   * The resolver must return a non-empty string or throw — returning `undefined`,
   * `null`, or an empty string is treated as a misconfiguration and the request
   * is rejected. Never use `as string` casts on header values, as they silently
   * produce `undefined` when the header is absent.
   *
   * @example
   * ```ts
   * // Resolve from subdomain
   * tenantIdResolver: (req) => {
   *   const id = req.hostname.split('.')[0]
   *   if (!id) throw new Error('Cannot resolve tenant from hostname')
   *   return id
   * }
   * // Resolve from header (safe extraction — no type assertion)
   * tenantIdResolver: (req) => {
   *   const id = req.headers['x-tenant-id']
   *   if (typeof id !== 'string' || id.length === 0) throw new Error('Missing or invalid x-tenant-id header')
   *   return id
   * }
   * ```
   */
  tenantIdResolver?: (req: Request) => string | Promise<string>

  /**
   * Granular control over which controllers are registered.
   * Allows disabling endpoints that are not needed for a specific application.
   */
  controllers?: {
    /** Enables `AuthController` (register, login, logout, refresh, me). Default: `true` */
    auth?: boolean

    /**
     * Enables `MfaController`, `MfaService`, and `MfaRequiredGuard`.
     *
     * **Opt-in** — must be set to `true` explicitly **on the `registerAsync()` call**,
     * not inside `useFactory`. The factory is evaluated asynchronously after the module
     * is built; this field is the synchronous activation switch.
     *
     * When set to `true`, the `mfa` group (`encryptionKey`, `issuer`) **must** also be
     * present in the `useFactory` return value — omitting it causes a startup error.
     *
     * Default: `false`
     */
    mfa?: boolean

    /** Enables `PasswordResetController`. Default: `true` */
    passwordReset?: boolean

    /** Enables `SessionController`. Default: `true` when `sessions.enabled = true`. */
    sessions?: boolean

    /** Enables `PlatformAuthController`. Default: `true` when `platform.enabled = true`. */
    platform?: boolean

    /**
     * Enables `OAuthController` and `OAuthService`.
     *
     * **Opt-in** — requires the `oauth` group to be configured in the `useFactory` return
     * value. Omitting the `oauth` group causes a startup error when this flag is `true`.
     *
     * Default: `false`
     */
    oauth?: boolean

    /** Enables `InvitationController`. Default: `true` when `invitations.enabled = true`. */
    invitations?: boolean
  }

  /**
   * TTL in seconds for the user status Redis cache.
   * Status is cached per user to avoid a database query on every authenticated request.
   * Default: `60`
   */
  userStatusCacheTtlSeconds?: number
}

/**
 * Async registration options for `BymaxAuthModule.registerAsync()`.
 *
 * Follows the standard NestJS async module pattern — use with `useFactory`
 * to inject dependencies (e.g. `ConfigService`) into the options factory.
 *
 * @example
 * ```ts
 * BymaxAuthModule.registerAsync({
 *   imports: [ConfigModule],
 *   useFactory: (config: ConfigService) => ({
 *     jwt: { secret: config.get('JWT_SECRET') },
 *     roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
 *   }),
 *   inject: [ConfigService],
 * })
 * ```
 */
export interface AuthModuleAsyncOptions {
  /** NestJS modules to import before the factory runs. */
  imports?: ModuleMetadata['imports']

  /**
   * Factory function that produces `BymaxAuthModuleOptions`.
   * Receives injected dependencies as arguments.
   */
  useFactory: (...args: unknown[]) => BymaxAuthModuleOptions | Promise<BymaxAuthModuleOptions>

  /** Injection tokens or providers to inject into `useFactory`. */
  inject?: (InjectionToken | OptionalFactoryDependency)[]

  /** Additional providers available within the async options scope. */
  extraProviders?: Provider[]

  /**
   * Synchronous controller registration override.
   *
   * Controls which built-in controllers are registered. Because `useFactory` is
   * resolved asynchronously after the `DynamicModule` is built, this field allows
   * consumer to disable controllers at registration time without waiting for the
   * async factory.
   *
   * @example
   * ```ts
   * BymaxAuthModule.registerAsync({
   *   useFactory: ...,
   *   controllers: { auth: false } // disable AuthController
   * })
   * ```
   */
  controllers?: BymaxAuthModuleOptions['controllers']
}
