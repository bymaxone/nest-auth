/**
 * resolveOptions — merge consumer options with defaults and validate security invariants.
 *
 * Called once at module startup (inside the async factory). Throws descriptive errors
 * if security-critical invariants are violated so that misconfigured deployments fail
 * fast rather than silently using weak settings.
 */

import { DEFAULT_OPTIONS } from './default-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

// ---------------------------------------------------------------------------
// ResolvedOptions — BymaxAuthModuleOptions with all defaults applied
// ---------------------------------------------------------------------------

/**
 * Resolved configuration object returned by `resolveOptions()`.
 *
 * All optional fields that have defaults are required here — the consumer is
 * guaranteed to receive a fully-populated configuration object with no undefined
 * values for defaulted fields. Groups whose entire top-level key is optional
 * (mfa, oauth) remain optional — when provided, their sub-fields are fully resolved.
 *
 * Defined as a `type` alias (not `interface extends`) to avoid TypeScript's
 * interface-extension compatibility check with `exactOptionalPropertyTypes`,
 * which rejects intersection widening of optional function properties.
 */
export type ResolvedOptions = Omit<
  BymaxAuthModuleOptions,
  | 'jwt'
  | 'password'
  | 'tokenDelivery'
  | 'cookies'
  | 'sessions'
  | 'bruteForce'
  | 'passwordReset'
  | 'emailVerification'
  | 'platformAdmin'
  | 'invitations'
  | 'controllers'
  | 'blockedStatuses'
  | 'redisNamespace'
  | 'routePrefix'
  | 'userStatusCacheTtlSeconds'
  | 'secureCookies'
  | 'mfa'
> & {
  jwt: Required<BymaxAuthModuleOptions['jwt']>
  password: Required<NonNullable<BymaxAuthModuleOptions['password']>>
  tokenDelivery: NonNullable<BymaxAuthModuleOptions['tokenDelivery']>
  cookies: Required<Omit<NonNullable<BymaxAuthModuleOptions['cookies']>, 'resolveDomains'>> &
    Pick<NonNullable<BymaxAuthModuleOptions['cookies']>, 'resolveDomains'>
  sessions: Required<Omit<NonNullable<BymaxAuthModuleOptions['sessions']>, 'maxSessionsResolver'>> &
    Pick<NonNullable<BymaxAuthModuleOptions['sessions']>, 'maxSessionsResolver'>
  bruteForce: Required<NonNullable<BymaxAuthModuleOptions['bruteForce']>>
  passwordReset: Required<NonNullable<BymaxAuthModuleOptions['passwordReset']>>
  emailVerification: Required<NonNullable<BymaxAuthModuleOptions['emailVerification']>>
  platformAdmin: Required<NonNullable<BymaxAuthModuleOptions['platformAdmin']>>
  invitations: Required<NonNullable<BymaxAuthModuleOptions['invitations']>>
  controllers: Required<NonNullable<BymaxAuthModuleOptions['controllers']>>
  blockedStatuses: string[]
  redisNamespace: string
  routePrefix: string
  userStatusCacheTtlSeconds: number
  /** `true` if auth cookies should carry the `Secure` flag. */
  secureCookies: boolean
  /** When provided, all sub-fields are resolved with defaults applied. */
  mfa?: Required<NonNullable<BymaxAuthModuleOptions['mfa']>>
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Computes the Shannon entropy of a string in bits per character.
 *
 * Used as a first-order filter to detect `jwt.secret` values with extremely
 * low character-frequency diversity (e.g. all-same character, simple 2-char
 * alternation). It does NOT detect sequential or enumerable patterns — a secret
 * composed of all unique characters arranged alphabetically passes this check.
 * The entropy gate is a necessary but not sufficient signal for randomness;
 * the primary protection is that secrets should be generated with
 * `crypto.randomBytes(32).toString('base64')`.
 */
function shannonEntropy(value: string): number {
  const freq = new Map<string, number>()
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1)
  }
  return [...freq.values()].reduce((sum, count) => {
    const p = count / value.length
    return sum - p * Math.log2(p)
  }, 0)
}

// ---------------------------------------------------------------------------
// resolveOptions
// ---------------------------------------------------------------------------

/**
 * Merges consumer-supplied options with secure defaults and validates all
 * security-critical invariants.
 *
 * @param userOptions - The options passed to `BymaxAuthModule.register()` or
 *   returned by the `useFactory` in `registerAsync()`.
 * @returns A fully-resolved options object with all defaults applied.
 * @throws If any required field is missing or any security invariant is violated.
 *
 * @remarks
 * Called once at module initialization. Errors thrown here prevent the NestJS
 * application from starting, ensuring misconfigured deployments fail fast.
 */
export function resolveOptions(userOptions: BymaxAuthModuleOptions): ResolvedOptions {
  validateJwt(userOptions.jwt)
  validateMfaEncryptionKey(userOptions.mfa)
  validateRolesHierarchy(userOptions.roles)
  validatePlatformAdmin(userOptions.platformAdmin, userOptions.roles)
  validatePasswordResetOtpLength(userOptions.passwordReset)
  validatePasswordCostFactor(userOptions.password)
  validateOAuthProviders(userOptions.oauth)
  validateRefreshCookiePath(userOptions.routePrefix, userOptions.cookies)
  validateRefreshGraceWindow(userOptions.jwt)

  // Destructure mfa out so the base spread does not inject the raw optional-field shape.
  // mfa is re-added below with defaults applied.
  const { mfa: _mfa, ...userOptionsWithoutMfa } = userOptions

  const resolved: ResolvedOptions = {
    ...userOptionsWithoutMfa,

    jwt: {
      ...DEFAULT_OPTIONS.jwt,
      ...userOptions.jwt
    },

    password: {
      ...DEFAULT_OPTIONS.password,
      ...userOptions.password
    },

    tokenDelivery: userOptions.tokenDelivery ?? DEFAULT_OPTIONS.tokenDelivery,

    cookies: {
      ...DEFAULT_OPTIONS.cookies,
      ...userOptions.cookies
    },

    sessions: {
      ...DEFAULT_OPTIONS.sessions,
      ...userOptions.sessions
    },

    bruteForce: {
      ...DEFAULT_OPTIONS.bruteForce,
      ...userOptions.bruteForce
    },

    passwordReset: {
      ...DEFAULT_OPTIONS.passwordReset,
      ...userOptions.passwordReset
    },

    emailVerification: {
      ...DEFAULT_OPTIONS.emailVerification,
      ...userOptions.emailVerification
    },

    platformAdmin: {
      ...DEFAULT_OPTIONS.platformAdmin,
      ...userOptions.platformAdmin
    },

    invitations: {
      ...DEFAULT_OPTIONS.invitations,
      ...userOptions.invitations
    },

    controllers: {
      ...DEFAULT_OPTIONS.controllers,
      ...userOptions.controllers
    },

    blockedStatuses: [...(userOptions.blockedStatuses ?? DEFAULT_OPTIONS.blockedStatuses)],

    redisNamespace: userOptions.redisNamespace ?? DEFAULT_OPTIONS.redisNamespace,

    routePrefix: userOptions.routePrefix ?? DEFAULT_OPTIONS.routePrefix,

    userStatusCacheTtlSeconds:
      userOptions.userStatusCacheTtlSeconds ?? DEFAULT_OPTIONS.userStatusCacheTtlSeconds,

    // Evaluated once at startup — not re-evaluated per request.
    secureCookies: userOptions.secureCookies ?? process.env['NODE_ENV'] === 'production',

    ...(userOptions.mfa !== undefined && {
      mfa: { ...DEFAULT_OPTIONS.mfa, ...userOptions.mfa } as Required<
        NonNullable<BymaxAuthModuleOptions['mfa']>
      >
    })
  }

  return resolved
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function validateJwt(jwt: BymaxAuthModuleOptions['jwt']): void {
  if (!jwt) {
    throw new Error(
      `[BymaxAuthModule] jwt configuration is required. ` + `Provide at least jwt.secret.`
    )
  }
  validateJwtSecret(jwt.secret)
  validateJwtAlgorithm(jwt.algorithm)
}

function validateJwtSecret(secret: string): void {
  if (secret.length < 32) {
    throw new Error(
      `[BymaxAuthModule] jwt.secret must be at least 32 characters long. ` +
        `Generate a secure secret with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }

  const entropy = shannonEntropy(secret)
  if (entropy < 3.5) {
    throw new Error(
      `[BymaxAuthModule] jwt.secret has insufficient entropy (${entropy.toFixed(2)} bits/char, ` +
        `minimum: 3.5 bits/char). The secret appears to contain repetitive or predictable patterns. ` +
        `Generate a secure secret with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }
}

function validateJwtAlgorithm(algorithm: BymaxAuthModuleOptions['jwt']['algorithm']): void {
  if (algorithm !== undefined && algorithm !== 'HS256') {
    throw new Error(
      `[BymaxAuthModule] jwt.algorithm must be 'HS256' — only HS256 is supported. ` +
        `Asymmetric algorithms are intentionally unsupported to prevent algorithm confusion attacks.`
    )
  }
}

/** Valid base64 characters only: A-Z, a-z, 0-9, +, /, and up to two = padding characters. */
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/

function validateMfaEncryptionKey(mfa: BymaxAuthModuleOptions['mfa']): void {
  if (mfa === undefined) return

  if (!mfa.encryptionKey) {
    throw new Error(
      `[BymaxAuthModule] mfa.encryptionKey is required when the 'mfa' group is configured. ` +
        `Generate one with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }

  if (!BASE64_RE.test(mfa.encryptionKey) || mfa.encryptionKey.length % 4 !== 0) {
    throw new Error(
      `[BymaxAuthModule] mfa.encryptionKey must be valid base64 (standard alphabet, optional = padding). ` +
        `Generate one with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }

  const decoded = Buffer.from(mfa.encryptionKey, 'base64')
  if (decoded.length !== 32) {
    throw new Error(
      `[BymaxAuthModule] mfa.encryptionKey must decode from base64 to exactly 32 bytes ` +
        `for AES-256-GCM (decoded: ${decoded.length} bytes). ` +
        `Generate one with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }

  if (!mfa.issuer) {
    throw new Error(
      `[BymaxAuthModule] mfa.issuer is required when the 'mfa' group is configured. ` +
        `It is displayed in authenticator apps (e.g. 'My App').`
    )
  }
}

function validateRolesHierarchy(roles: BymaxAuthModuleOptions['roles']): void {
  if (!roles?.hierarchy) {
    throw new Error(
      `[BymaxAuthModule] roles.hierarchy is required. ` +
        `Define at least one role (e.g. { hierarchy: { MEMBER: [] } }).`
    )
  }

  if (Object.keys(roles.hierarchy).length === 0) {
    throw new Error(
      `[BymaxAuthModule] roles.hierarchy must not be an empty object. ` +
        `Define at least one role (e.g. { MEMBER: [] }).`
    )
  }

  // Referential integrity: every role referenced as a child must be declared as a key.
  const allRoles = new Set(Object.keys(roles.hierarchy))
  for (const [role, children] of Object.entries(roles.hierarchy)) {
    for (const child of children) {
      if (!allRoles.has(child)) {
        throw new Error(
          `[BymaxAuthModule] roles.hierarchy['${role}'] references unknown role '${child}'. ` +
            `All roles referenced as children must be declared as keys in the hierarchy.`
        )
      }
    }
  }
}

function validatePlatformAdmin(
  platformAdmin: BymaxAuthModuleOptions['platformAdmin'],
  roles: BymaxAuthModuleOptions['roles']
): void {
  if (platformAdmin?.enabled && !roles.platformHierarchy) {
    throw new Error(
      `[BymaxAuthModule] roles.platformHierarchy is required when platformAdmin.enabled is true. ` +
        `Define the platform role hierarchy (e.g. { SUPER_ADMIN: ['SUPPORT'], SUPPORT: [] }).`
    )
  }
}

function validatePasswordResetOtpLength(
  passwordReset: BymaxAuthModuleOptions['passwordReset']
): void {
  const otpLength = passwordReset?.otpLength
  if (otpLength === undefined) return

  if (otpLength < 4 || otpLength > 8) {
    throw new Error(
      `[BymaxAuthModule] passwordReset.otpLength must be between 4 and 8 inclusive ` +
        `(current: ${otpLength}). Values below 4 are too easily guessable; ` +
        `values above 8 are not required for security and degrade user experience.`
    )
  }
}

function validatePasswordCostFactor(password: BymaxAuthModuleOptions['password']): void {
  const costFactor = password?.costFactor
  if (costFactor === undefined) return

  if (costFactor < 16_384) {
    throw new Error(
      `[BymaxAuthModule] password.costFactor must be at least 16384 (2^14) ` +
        `(current: ${costFactor}). Lower values produce hashes vulnerable to brute-force attacks. ` +
        `The recommended minimum for production is 32768 (2^15).`
    )
  }

  if ((costFactor & (costFactor - 1)) !== 0) {
    throw new Error(
      `[BymaxAuthModule] password.costFactor must be a power of 2 (current: ${costFactor}).`
    )
  }
}

/** Fields required on every configured OAuth provider. */
const REQUIRED_OAUTH_FIELDS = ['clientId', 'clientSecret', 'callbackUrl'] as const

function validateOAuthProviders(oauth: BymaxAuthModuleOptions['oauth']): void {
  if (!oauth) return

  for (const [provider, config] of Object.entries(oauth) as [
    string,
    Record<string, string | undefined>
  ][]) {
    for (const field of REQUIRED_OAUTH_FIELDS) {
      // eslint-disable-next-line security/detect-object-injection -- field is from a const tuple
      if (!config[field]) {
        throw new Error(
          `[BymaxAuthModule] oauth.${provider}.${field} is required when the '${provider}' ` +
            `OAuth provider is configured.`
        )
      }
    }
  }
}

function validateRefreshCookiePath(
  routePrefix: BymaxAuthModuleOptions['routePrefix'],
  cookies: BymaxAuthModuleOptions['cookies']
): void {
  const prefix = routePrefix ?? DEFAULT_OPTIONS.routePrefix
  if (prefix !== 'auth' && !cookies?.refreshCookiePath) {
    throw new Error(
      `[BymaxAuthModule] routePrefix is '${prefix}' but cookies.refreshCookiePath is not set. ` +
        `The refresh cookie path defaults to '/auth', which will not match your routes — ` +
        `the refresh cookie will be sent on every request instead of only to the refresh endpoint. ` +
        `Set cookies.refreshCookiePath: '/${prefix}' to restrict the refresh cookie correctly.`
    )
  }
}

function validateRefreshGraceWindow(jwt: BymaxAuthModuleOptions['jwt']): void {
  const graceSeconds =
    jwt.refreshGraceWindowSeconds ?? DEFAULT_OPTIONS.jwt.refreshGraceWindowSeconds
  const refreshLifetimeSeconds =
    (jwt.refreshExpiresInDays ?? DEFAULT_OPTIONS.jwt.refreshExpiresInDays) * 86_400

  if (graceSeconds >= refreshLifetimeSeconds) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshGraceWindowSeconds (${graceSeconds} s) must be less than ` +
        `the refresh token lifetime jwt.refreshExpiresInDays * 86400 (${refreshLifetimeSeconds} s). ` +
        `A grace window equal to or longer than the token lifetime would allow grace pointers ` +
        `to outlive the refresh session they protect.`
    )
  }
}
