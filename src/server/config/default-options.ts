/**
 * Default configuration values for @bymax-one/nest-auth.
 *
 * These defaults are merged with the consumer-supplied options by `resolveOptions()`.
 * All values here are secure production defaults — changing them requires understanding
 * the security implications documented in the JSDoc of each field in
 * `BymaxAuthModuleOptions`.
 */

/**
 * Default values for every optional configuration group.
 *
 * Grouped identically to `BymaxAuthModuleOptions` so that `resolveOptions()` can
 * do a shallow per-group spread: `{ ...DEFAULT_OPTIONS.jwt, ...userOptions.jwt }`.
 *
 * @remarks
 * Do NOT use `JSON.parse(JSON.stringify(...))` to clone this object — function-valued
 * properties (`maxSessionsResolver`, `tenantIdResolver`, `resolveDomains`) would be
 * lost. Always spread or shallow-copy per group.
 */
export const DEFAULT_OPTIONS = {
  jwt: {
    accessExpiresIn: '15m',
    // accessCookieMaxAgeMs must be kept consistent with accessExpiresIn (900 s = 900_000 ms).
    // If you shorten accessExpiresIn, reduce accessCookieMaxAgeMs by the same ratio to avoid
    // browser cookies outliving the JWT exp claim.
    accessCookieMaxAgeMs: 900_000,
    refreshExpiresInDays: 7,
    algorithm: 'HS256' as const,
    // Security trade-off: 30 s grace window allows token rotation under slow mobile networks.
    // It also extends the replay window for a stolen refresh token by 30 s beyond expiry.
    // Do not increase this value without a documented justification.
    refreshGraceWindowSeconds: 30
  },

  password: {
    costFactor: 32_768,
    blockSize: 8,
    parallelization: 1
  },

  tokenDelivery: 'cookie' as const,

  cookies: {
    accessTokenName: 'access_token',
    refreshTokenName: 'refresh_token',
    sessionSignalName: 'has_session',
    refreshCookiePath: '/auth'
  },

  mfa: {
    recoveryCodeCount: 8,
    totpWindow: 1
  },

  sessions: {
    enabled: false,
    defaultMaxSessions: 5,
    evictionStrategy: 'fifo' as const
  },

  bruteForce: {
    // 5 attempts per 15-minute window aligns with the IP-level throttle default (5/min).
    // Raising this above 5 meaningfully increases the credential brute-force window.
    maxAttempts: 5,
    windowSeconds: 900
  },

  passwordReset: {
    method: 'token' as const,
    // 3600 s (1 h) is the conservative upper bound for production.
    // Security-sensitive deployments should use 600–1800 s (10–30 min) per OWASP guidance.
    tokenTtlSeconds: 3_600,
    otpTtlSeconds: 600,
    otpLength: 6
  },

  emailVerification: {
    // Default true — secure by default. Applications that allow unverified addresses
    // must opt out explicitly via emailVerification.required: false.
    required: true,
    otpTtlSeconds: 600
  },

  platform: {
    enabled: false
  },

  invitations: {
    enabled: false,
    // 48 h (172_800 s) — limits the window during which a forwarded or leaked invitation
    // link can be accepted by an unintended recipient. Do not increase beyond 7 days.
    tokenTtlSeconds: 172_800
  },

  controllers: {
    // auth and passwordReset are opt-out (enabled by default).
    // All other controllers are opt-in (disabled by default) — they require
    // explicit feature configuration before they can be safely enabled.
    // These defaults only affect the resolved options object exposed via
    // BYMAX_AUTH_OPTIONS; the module's feature flags are read from
    // AuthModuleAsyncOptions.controllers directly, not from resolved options.
    auth: true,
    mfa: false,
    passwordReset: true,
    sessions: false,
    platform: false,
    oauth: false,
    invitations: false
  },

  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],

  redisNamespace: 'auth',

  routePrefix: 'auth',

  // Security trade-off: a 60 s cache TTL means a banned/suspended user can continue
  // making authenticated requests for up to 60 s after a status change in the database.
  // Lowering this value reduces revocation latency but increases Redis read pressure.
  userStatusCacheTtlSeconds: 60
} as const
