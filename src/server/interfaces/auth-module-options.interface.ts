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
 * Passed to `BymaxAuthModule.register()` or `BymaxAuthModule.registerAsync()`.
 * All groups except `jwt` and `roles` are optional — unconfigured features are
 * not registered in the NestJS container (zero overhead).
 *
 * @example
 * ```ts
 * BymaxAuthModule.register({
 *   jwt: { secret: process.env.JWT_SECRET },
 *   roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
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
     * Resolves cookie domains from the request's hostname.
     * Useful for multi-domain support (e.g. `api.example.com` and `app.example.com`).
     *
     * @param requestDomain - The hostname extracted from the incoming request.
     * @returns Array of domain strings where cookies should be set (e.g. `['.example.com']`).
     */
    resolveDomains?: (requestDomain: string) => string[]
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
  platformAdmin?: {
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
     * Required when `platformAdmin.enabled = true`.
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

    /** Enables `PlatformAuthController`. Default: `true` when `platformAdmin.enabled = true`. */
    platformAuth?: boolean

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
