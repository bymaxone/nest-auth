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
 * Passed to `BymaxAuthModule.registerAsync()`. All groups except `jwt`,
 * `roles` and `rateLimit` are optional — unconfigured features are not
 * registered in the NestJS container (zero overhead). `rateLimit` is required
 * because it is on unless turned off, and while it is on the deployment has to
 * name which address keys the limit — see {@link BymaxAuthRateLimitOptions}.
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
/**
 * How the client IP that keys the per-route limit is derived.
 *
 * - `'peer'` — the socket peer address, read directly from the connection. Never consults
 *   `X-Forwarded-For`, so a spoofed header cannot buy an attacker a fresh budget.
 * - `'trusted-proxy'` — Express's `req.ip`, which honours the app's `trust proxy` setting and
 *   therefore the forwarding headers it admits.
 */
export type ClientIpSource = 'peer' | 'trusted-proxy'

/**
 * Per-IP rate limiting, as a discriminated union on `enabled`.
 *
 * The limiter is on unless it is turned off, and while it is on the deployment must say which
 * address keys it. Neither value can be the default, because each is a working limiter in one
 * deployment and no limiter at all in the other: `'peer'` behind any proxy reads the proxy's
 * address for every client, so all of them share one bucket and a single caller sending a
 * handful of logins can lock out the whole user base with no credential; `'trusted-proxy'` on a
 * directly exposed app reads whatever the caller wrote in `X-Forwarded-For`, and a limiter whose
 * key the attacker picks enforces nothing. Both look like a working limiter at runtime, and
 * nothing detects the mismatch.
 *
 * The union is what makes that a compile error rather than a startup one. `resolveOptions`
 * still checks it — the type binds a TypeScript consumer and nobody else, and this is a
 * published package that is also called from JavaScript and configured from JSON.
 */
export type BymaxAuthRateLimitOptions =
  | {
      /**
       * Whether the library enforces the per-route limits in `AUTH_THROTTLE_CONFIGS`.
       * Default: `true`.
       *
       * Those numbers used to be advisory — they took effect only if the host wired
       * `ThrottlerModule` and registered its guard, and a deployment that did not ran every auth
       * route unlimited without being told. The library now enforces them itself, backed by the
       * same Redis counter as the brute-force lockout, so the limit also holds across instances.
       */
      readonly enabled?: true
      /** Required while the limiter is on. See {@link ClientIpSource}. */
      readonly clientIpSource: ClientIpSource
    }
  | {
      /**
       * Set `false` when the same limits are already enforced at the edge (an API gateway, a
       * WAF, or a host-side `ThrottlerModule`) and counting twice is not wanted.
       */
      readonly enabled: false
      /** Never read while the limiter is off, so it need not be stated. */
      readonly clientIpSource?: ClientIpSource
    }

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
     * Secrets retired by a rotation, accepted for **verification only**. Default: none.
     *
     * Rotating `jwt.secret` without this signs every outstanding token out at once, and
     * invalidates every stored recovery-code digest — those are keyed by an HMAC derived from
     * the secret, so a rotation would lock users out of the codes they printed and filed.
     * Listing the previous secret here keeps both readable while tokens issued under it drain,
     * so a rotation is a rollout rather than a mass logout.
     *
     * Signing always uses `jwt.secret`. Entries here are only ever tried after it, and only to
     * verify, so a rotation is one-way: nothing new is ever produced under a retired secret.
     *
     * Remove an entry once the longest-lived thing signed under it has expired — every entry is
     * a key that still opens the door. Each is validated exactly like `jwt.secret`: a weak
     * previous secret is as forgeable as a weak current one.
     */
    previousSecrets?: string[]

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
     * Hard cap on how long one login can be extended by rotation, in days.
     * Default: `0` — no cap.
     *
     * `refreshExpiresInDays` bounds how long a single refresh token lives, not how long a
     * *session* lives: a client that rotates every fifteen minutes renews that lifetime
     * indefinitely, so a session established once can outlive the laptop it was established
     * on. This caps the whole lineage — the family's birth time is stamped at login and
     * carried through every rotation, and once the cap is passed the rotation is refused and
     * the user signs in again.
     *
     * Left off by default because switching it on ends sessions that are already older than
     * the cap. Pick a value the product can justify asking a user to re-authenticate at (30
     * or 90 days are common), and set it deliberately.
     *
     * Sessions written before this existed carry no birth time and are not capped; they age
     * out under `refreshExpiresInDays` like any other.
     */
    absoluteSessionLifetimeDays?: number

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
     * The `iss` claim stamped on every token this backend mints, and required on every token
     * it verifies.
     *
     * Absent by default, so an existing deployment is unchanged. When set, a token carrying a
     * different issuer — or none at all — is rejected. That is the whole point: a verifier
     * that accepts an unstamped token gives an attacker a way to opt out of the check.
     *
     * Both backends sharing a deployment must be configured with the same value, or they stop
     * accepting each other's tokens. Turning it on invalidates the access tokens already in
     * flight; the window is one access-token lifetime and clients recover by refreshing, since
     * the refresh token is opaque and carries no claims.
     */
    issuer?: string

    /**
     * The `aud` claim, with the same semantics as {@link issuer}.
     *
     * Names who the token is *for*. With HS256 the verifier can also sign, so audience binding
     * is what stops a token minted for one service being replayed at another that trusts the
     * same secret.
     */
    audience?: string

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
     * Default: `131072` (2^17), the minimum OWASP recommends for scrypt alongside `r=8, p=1`.
     * Minimum enforced by `resolveOptions()`: `16384` (2^14). Values below that are rejected at
     * startup — do not lower this for production workloads.
     *
     * The default costs roughly 128 MiB and ~100 ms per hash on a modern core. That is the
     * point: it is what makes an offline attack on a leaked hash expensive. Budget for it —
     * every login and registration pays it once, and a host that cannot afford the memory
     * should lower `costFactor` deliberately, having read what it is buying, rather than
     * inherit a weaker default that never announced itself.
     *
     * @throws {Error} When the value fails validation at module initialisation.
     */
    costFactor?: number

    /**
     * Minimum password length the deployment accepts. Default: `15`.
     *
     * NIST SP 800-63B-4 §3.1.1.1 requires 15 characters for a password used as a SINGLE
     * authentication factor, and permits 8 only when the password is part of multi-factor
     * authentication. MFA in this library is opt-in per user, so the default deployment is
     * single-factor and 15 is the number that applies. Lower it to 8 — the structural floor the
     * DTOs enforce, and the lowest the standard allows under any circumstance — only in a
     * deployment that makes MFA mandatory.
     *
     * @remarks
     * `costFactor` sets the price of one guess; this sets how many guesses there are. Only the
     * second is what an offline attacker actually runs out of, and the breach and common-password
     * screens remove passwords that are already *known*, not short ones nobody has seen yet.
     *
     * Deliberately not paired with any composition rule: the same clause says verifiers SHALL
     * NOT impose them, and none of the password DTOs carries one.
     *
     * @throws {Error} When the value is not an integer in `[8, 128]`.
     */
    minLength?: number

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

    /**
     * Extra words the default password checker should refuse, on top of the ones it ships.
     *
     * ASVS v5 §6.2.11 asks for a "documented list of context specific words" — the deployment's
     * own product, company, and domain names, which are exactly the words its users reach for
     * and which no general corpus contains. Entries are reduced the same way a candidate is
     * (lowercased, leet undone, trailing digits dropped), so listing `Acme` also refuses
     * `Acme2024!` and `@cme123` without anyone having to think of them.
     *
     * Ignored when a custom `BYMAX_AUTH_BREACH_CHECKER` is supplied — that provider owns the
     * decision entirely.
     *
     * Default: `[]`
     */
    blocklist?: readonly string[]
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
   * The deployment environment, supplied explicitly.
   *
   * This is the ONLY input that answers "is this production". The library never reads the
   * ambient `process.env`, and it is secure by default: an unset value is `'production'`, so
   * `secureCookies` resolves to `true` and the production-gated OAuth-redirect checks apply
   * unless the host opts into `'development'` or `'test'`.
   *
   * Default: `'production'`.
   *
   * @remarks
   * This replaces reading `process.env['NODE_ENV'] === 'production'`. That test decided cookie
   * `Secure`, OAuth callback HTTPS enforcement and three redirect validations, and it failed
   * open on every near miss — unset, `'staging'`, `'prod'`, or `'production '` with a trailing
   * space each silently took the insecure branch. Whether a deployment is production is
   * something the deployer knows and the process environment only hints at, so it is now passed
   * in rather than sniffed. Matches `Environment` in rust-auth.
   */
  environment?: 'production' | 'development' | 'test'

  /**
   * Whether to set the `Secure` flag on auth cookies.
   *
   * When `true`, cookies are only sent over HTTPS. When `false`, cookies are
   * sent over HTTP as well (useful for local development).
   *
   * Default: `true`, unless {@link BymaxAuthModuleOptions.environment} is
   * `'development'` or `'test'`. Evaluated once at module startup via
   * `resolveOptions()` — not re-evaluated per request.
   *
   * @remarks
   * Set this explicitly to `true` in a non-production environment that is nonetheless served
   * over HTTPS, so the cookies are marked `Secure` there too.
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
   *
   * Required, and shaped so the compiler asks the question the module would otherwise only ask
   * at startup: a deployment that leaves the limiter on must name the client-IP source, and one
   * that turns it off need not. Nothing that compiles today stops compiling for a reason that
   * would not already have refused to boot.
   */
  rateLimit: BymaxAuthRateLimitOptions

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
     * Keys retired by a rotation, accepted for **decryption only**. Default: none.
     *
     * A TOTP secret is stored encrypted under `encryptionKey` and the ciphertext records no key
     * identifier, so changing that key without this makes every stored secret undecryptable —
     * every enrolled user's authenticator stops matching, at once, with no way back. Listing
     * the previous key keeps those secrets readable, and each one is re-encrypted under the
     * current key the next time its owner passes a challenge, so the rotation drains on its own.
     *
     * Encryption always uses `encryptionKey`; entries here are only ever tried after it, and
     * only to decrypt. AES-GCM authenticates, so a wrong key fails unambiguously rather than
     * returning garbage — trying them in order is safe.
     *
     * Remove an entry once no stored secret is still under it. Each is validated exactly like
     * the current key.
     */
    previousEncryptionKeys?: string[]

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

    /*
     * There is no eviction-strategy option: reaching the limit always evicts the oldest
     * session. A knob with one possible value configures nothing, and the option that used to
     * be here only looked like a choice.
     *
     * The caveat it carried is real and still applies: eviction is silent, so an attacker who
     * opens a session pushes a legitimate one out with no signal to its owner. Implement
     * `onSessionEvicted` in your `IAuthHooks` to detect and alert on unexpected evictions,
     * which may indicate an account takeover.
     */
  }

  /**
   * Brute-force login protection configuration.
   * Uses Redis-backed attempt counters with automatic expiry.
   */
  bruteForce?: {
    /**
     * Maximum number of failed login attempts before lockout.
     * Default: `5` — aligned with the per-IP throttle default; raising it widens the
     * credential brute-force window. Bounded to `1..=100` at startup.
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
     * Default: `600` (10 minutes), matching OWASP guidance for time-sensitive credential
     * recovery. Values beyond 1800 meaningfully widen the window for stolen-email replay.
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
     * Default: `true` — secure by default. A deployment that accepts unverified addresses
     * must opt out explicitly with `emailVerification.required: false`.
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
   * Address-change configuration.
   *
   * The flow itself is switched on by `controllers.emailChange`; this group only tunes it, so
   * it can be omitted entirely.
   */
  emailChange?: {
    /**
     * TTL for the address-change verification token in seconds.
     *
     * Default: `3600` (1 hour). Shorter than an invitation because the recipient is a user
     * who just asked for the change and is waiting on the message — and because the token
     * points at the account's recovery credential, so a link sitting in a mailbox for two
     * days is a longer window than the flow needs.
     */
    tokenTtlSeconds?: number
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
   * Because a configured resolver makes the body's value dead weight, `tenantId` is optional on
   * every DTO that carries it and a client may omit it entirely. With no resolver configured the
   * body is the only thing that can name a tenant, and a request naming none is refused with
   * `auth.validation` — the deployment has to choose one of the two, and neither choice is
   * guessed on its behalf.
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

    /**
     * Enables `SessionController`. **Opt-in** — `Default: false`. Also requires
     * `sessions.enabled: true`; setting one without the other is a startup error.
     */
    sessions?: boolean

    /**
     * Enables `PlatformAuthController`. **Opt-in** — `Default: false`. Also requires
     * `platform.enabled: true`; setting one without the other is a startup error.
     */
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

    /**
     * Enables `InvitationController`. **Opt-in** — `Default: false`. Also requires
     * `invitations.enabled: true`; setting one without the other is a startup error.
     */
    invitations?: boolean

    /**
     * Enables `EmailChangeController` and `EmailChangeService`. **Opt-in** — `Default: false`.
     *
     * Requires the configured {@link IEmailProvider} to implement
     * `sendEmailChangeVerification`: the flow cannot deliver its token without it, and the
     * module refuses to boot rather than mint tokens nobody receives.
     */
    emailChange?: boolean
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
