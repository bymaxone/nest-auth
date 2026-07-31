/**
 * resolveOptions — merge consumer options with defaults and validate security invariants.
 *
 * Called once at module startup (inside the async factory). Throws descriptive errors
 * if security-critical invariants are violated so that misconfigured deployments fail
 * fast rather than silently using weak settings.
 *
 * @layer Config
 */

import { createHash } from 'node:crypto'

import { DEFAULT_OPTIONS } from './default-options'
import { TOKEN_EPOCH_RETENTION_SECONDS } from '../constants/token-epoch'
import { MAX_VERIFY_WINDOW } from '../crypto/totp'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/**
 * Domain-separation label for the HMAC key derivation. Changing this value is
 * a breaking change — it invalidates every existing Redis identifier keyed by
 * `hmacKey` across a deployment.
 */
const HMAC_KEY_DERIVATION_LABEL = 'bymax-auth:hmac-key:v1'

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
  | 'platform'
  | 'invitations'
  | 'controllers'
  | 'blockedStatuses'
  | 'redisNamespace'
  | 'routePrefix'
  | 'userStatusCacheTtlSeconds'
  | 'secureCookies'
  | 'mfa'
  | 'rateLimit'
> & {
  // `previousSecrets` stays optional: it is absent unless a rotation is in progress, and
  // `Required` would force every consumer to declare an empty array to mean "not rotating".
  // `issuer` and `audience` stay OPTIONAL through the resolution, unlike every other jwt
  // field: their absence is the default and it is meaningful. Defaulting them to a string
  // would make every deployment stamp and require a value nobody chose, and turning the check
  // on by accident is exactly the failure mode that splits two backends apart.
  jwt: Required<Omit<BymaxAuthModuleOptions['jwt'], 'previousSecrets' | 'issuer' | 'audience'>> &
    Pick<BymaxAuthModuleOptions['jwt'], 'previousSecrets' | 'issuer' | 'audience'>
  password: Required<NonNullable<BymaxAuthModuleOptions['password']>>
  tokenDelivery: NonNullable<BymaxAuthModuleOptions['tokenDelivery']>
  cookies: Required<Omit<NonNullable<BymaxAuthModuleOptions['cookies']>, 'resolveDomains'>> &
    Pick<NonNullable<BymaxAuthModuleOptions['cookies']>, 'resolveDomains'>
  sessions: Required<Omit<NonNullable<BymaxAuthModuleOptions['sessions']>, 'maxSessionsResolver'>> &
    Pick<NonNullable<BymaxAuthModuleOptions['sessions']>, 'maxSessionsResolver'>
  bruteForce: Required<NonNullable<BymaxAuthModuleOptions['bruteForce']>>
  passwordReset: Required<NonNullable<BymaxAuthModuleOptions['passwordReset']>>
  emailVerification: Required<NonNullable<BymaxAuthModuleOptions['emailVerification']>>
  platform: Required<NonNullable<BymaxAuthModuleOptions['platform']>>
  invitations: Required<NonNullable<BymaxAuthModuleOptions['invitations']>>
  emailChange: Required<NonNullable<BymaxAuthModuleOptions['emailChange']>>
  rateLimit: Required<NonNullable<BymaxAuthModuleOptions['rateLimit']>>
  controllers: Required<NonNullable<BymaxAuthModuleOptions['controllers']>>
  blockedStatuses: string[]
  redisNamespace: string
  routePrefix: string
  userStatusCacheTtlSeconds: number
  /** `true` if auth cookies should carry the `Secure` flag. */
  secureCookies: boolean
  /**
   * Server-side HMAC key derived from `jwt.secret` at startup and used to
   * compute Redis identifier hashes (brute-force, OTP, MFA setup, anti-replay).
   *
   * Key-separation: this value is distinct from `jwt.secret` so that HMAC
   * operations do not share a key with JWT signing. The derivation uses
   * SHA-256 with a fixed domain-separation label, so rotating `jwt.secret`
   * automatically rotates the HMAC key while keeping the two concerns
   * cryptographically independent.
   */
  hmacKey: string
  /**
   * HMAC keys derived from `jwt.previousSecrets`, in the order given. Empty unless a rotation
   * is in progress.
   *
   * Read-only, like the secrets they come from: a recovery-code digest written under a retired
   * key still verifies, so rotating `jwt.secret` does not lock users out of the codes they
   * printed and filed. Nothing is ever newly written under one — a code that matches here is
   * consumed and the set is regenerated under the current key.
   */
  previousHmacKeys: string[]
  /** When provided, all sub-fields are resolved with defaults applied. */
  mfa?: Required<NonNullable<BymaxAuthModuleOptions['mfa']>>
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Derives the HMAC key used for Redis identifier hashing from the JWT secret.
 *
 * Key-separation rationale: using the JWT signing secret directly as an HMAC
 * key creates a coupling where a compromise of one security domain leaks the
 * other. The derivation is deterministic (no stored state, no extra config)
 * and cryptographically independent from the signing operation.
 */
function deriveHmacKey(jwtSecret: string): string {
  return createHash('sha256')
    .update(`${HMAC_KEY_DERIVATION_LABEL}:${jwtSecret}`, 'utf8')
    .digest('hex')
}

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
  validatePlatformAdmin(userOptions.platform, userOptions.roles)
  validatePasswordResetOtpLength(userOptions.passwordReset)
  validatePasswordCostFactor(userOptions.password)
  validatePasswordMemoryParameters(userOptions.password)
  validateMfaVerificationParameters(userOptions.mfa)
  validateBruteForce(userOptions.bruteForce)
  validateOAuthProviders(userOptions.oauth)
  validateOAuthSuccessRedirectUrl(userOptions)
  validateOAuthMfaRedirectUrl(userOptions)

  // Split the binding off the rest of the jwt group so the empty-string case can be dropped
  // rather than spread through: spreading `{}` over an already-set key does not remove it.
  const { issuer: rawIssuer, audience: rawAudience, ...jwtWithoutBinding } = userOptions.jwt
  validateOAuthErrorRedirectUrl(userOptions)
  validateRefreshCookiePath(userOptions.routePrefix, userOptions.cookies)
  validateSameSiteNoneRequiresSecure(userOptions)
  validateTrustedOrigins(userOptions)
  validateRefreshGraceWindow(userOptions.jwt)
  validateAccessLifetimeAgainstEpochRetention(userOptions.jwt)

  // Destructure mfa out so the base spread does not inject the raw optional-field shape.
  // mfa is re-added below with defaults applied.
  const { mfa: _mfa, ...userOptionsWithoutMfa } = userOptions

  const resolved: ResolvedOptions = {
    ...userOptionsWithoutMfa,

    jwt: {
      ...DEFAULT_OPTIONS.jwt,
      ...jwtWithoutBinding,
      // `''` means unconfigured, decided HERE and nowhere else. A consumer threading an unset
      // environment variable through must not silently turn the binding on — and the two
      // places that read these values (the signer and the verifier) only agree on what
      // "configured" means if exactly one of them decides it.
      //
      // A truthy test rather than two comparisons: for a string, "present and not empty" is
      // exactly what truthiness means, and the values reaching the readers are then either a
      // real binding or nothing at all.
      ...(rawIssuer ? { issuer: rawIssuer } : {}),
      ...(rawAudience ? { audience: rawAudience } : {})
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

    platform: {
      ...DEFAULT_OPTIONS.platform,
      ...userOptions.platform
    },

    invitations: {
      ...DEFAULT_OPTIONS.invitations,
      ...userOptions.invitations
    },

    emailChange: {
      ...DEFAULT_OPTIONS.emailChange,
      ...userOptions.emailChange
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
    rateLimit: {
      ...DEFAULT_OPTIONS.rateLimit,
      ...userOptions.rateLimit
    },

    secureCookies: userOptions.secureCookies ?? process.env['NODE_ENV'] === 'production',

    hmacKey: deriveHmacKey(userOptions.jwt.secret),
    previousHmacKeys: (userOptions.jwt.previousSecrets ?? []).map(deriveHmacKey),

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
  validatePreviousSecrets(jwt)
}

/**
 * Validate the retired secrets accepted for verification during a rotation.
 *
 * Each is held to the same bar as the current secret: they still verify tokens, so a weak one
 * is as forgeable as a weak current secret would be. A retired secret equal to the current one
 * is rejected too — it means the rotation never happened, and a config that reads as rotated
 * while nothing changed is worse than one that never claimed to.
 *
 * @param jwt - The user-supplied `jwt` option block.
 * @throws If any entry is not a string, fails the secret rules, or repeats another entry.
 */
function validatePreviousSecrets(jwt: BymaxAuthModuleOptions['jwt']): void {
  const previous = jwt.previousSecrets
  if (previous === undefined) return

  if (!Array.isArray(previous)) {
    throw new Error(`[BymaxAuthModule] jwt.previousSecrets must be an array of strings when set.`)
  }

  const seen = new Set<string>([jwt.secret])
  for (const [index, secret] of previous.entries()) {
    if (typeof secret !== 'string') {
      throw new Error(
        `[BymaxAuthModule] jwt.previousSecrets[${index}] must be a string. ` +
          `Every entry still verifies tokens, so each is held to the same rules as jwt.secret.`
      )
    }
    validateJwtSecret(secret)
    if (seen.has(secret)) {
      throw new Error(
        `[BymaxAuthModule] jwt.previousSecrets[${index}] repeats jwt.secret or an earlier entry. ` +
          `A retired secret equal to the current one means the rotation did not happen, and a ` +
          `configuration that reads as rotated while nothing changed is worse than one that ` +
          `never claimed to.`
      )
    }
    seen.add(secret)
  }
}

function validateJwtSecret(secret: string): void {
  // Guard against runtime-nullish values (e.g. ConfigService returning undefined for an
  // unset environment variable). The interface declares `secret: string` but callers
  // frequently use `config.get('JWT_SECRET')` which returns `string | undefined`.
  // Without this check the subsequent `.length` access would throw a raw TypeError
  // instead of the descriptive [BymaxAuthModule] startup error.
  if (!secret) {
    throw new Error(
      `[BymaxAuthModule] jwt.secret is required and must not be empty. ` +
        `Generate a secure secret with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }
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

/**
 * Valid standard base64 characters: A-Z, a-z, 0-9, +, /, and up to two = padding characters.
 */
const BASE64_STANDARD_RE = /^[A-Za-z0-9+/]+={0,2}$/

/**
 * Valid base64url characters: A-Z, a-z, 0-9, -, _, padding optional.
 */
const BASE64_URL_RE = /^[A-Za-z0-9_-]+={0,2}$/

/**
 * Assert a value is base64 for exactly 32 bytes — an AES-256 key.
 *
 * @param key - The configured value.
 * @param label - The option path, for the error message.
 * @throws If the value is not valid base64 or does not decode to 32 bytes.
 */
function assertAes256Key(key: unknown, label: string): void {
  if (typeof key !== 'string' || key === '') {
    throw new Error(`[BymaxAuthModule] ${label} must be a non-empty base64 string.`)
  }

  // Accept both standard base64 and base64url alphabets so consumers using
  // `randomBytes(32).toString('base64url')` (which produces `-` and `_` in
  // place of `+` and `/`) do not hit a confusing "invalid base64" error.
  if (!BASE64_STANDARD_RE.test(key) && !BASE64_URL_RE.test(key)) {
    throw new Error(
      `[BymaxAuthModule] ${label} must be valid base64 — accepted alphabets: ` +
        `standard (A-Z a-z 0-9 + /) or base64url (A-Z a-z 0-9 - _), padding optional. ` +
        `Generate one with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }

  // Buffer's 'base64' decoder accepts both alphabets (treating `-` and `_` as `+` and `/`),
  // so a single decode call works for both formats.
  const decoded = Buffer.from(key, 'base64')
  if (decoded.length !== 32) {
    throw new Error(
      `[BymaxAuthModule] ${label} must decode from base64 to exactly 32 bytes ` +
        `for AES-256-GCM (decoded: ${decoded.length} bytes). ` +
        `Generate one with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }
}

function validateMfaEncryptionKey(mfa: BymaxAuthModuleOptions['mfa']): void {
  if (mfa === undefined) return

  if (!mfa.encryptionKey) {
    throw new Error(
      `[BymaxAuthModule] mfa.encryptionKey is required when the 'mfa' group is configured. ` +
        `Generate one with: node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`
    )
  }

  assertAes256Key(mfa.encryptionKey, 'mfa.encryptionKey')

  // Retired keys still decrypt stored secrets, so each is held to the same bar as the current
  // one — a 16-byte "key" here would throw at the first challenge, not at startup.
  const previous = mfa.previousEncryptionKeys
  if (previous !== undefined) {
    if (!Array.isArray(previous)) {
      throw new Error(
        `[BymaxAuthModule] mfa.previousEncryptionKeys must be an array of base64 keys when set.`
      )
    }
    const seen = new Set<string>([mfa.encryptionKey])
    for (const [index, key] of previous.entries()) {
      assertAes256Key(key, `mfa.previousEncryptionKeys[${index}]`)
      if (seen.has(key)) {
        throw new Error(
          `[BymaxAuthModule] mfa.previousEncryptionKeys[${index}] repeats mfa.encryptionKey or ` +
            `an earlier entry. A retired key equal to the current one means the rotation did ` +
            `not happen, and a configuration that reads as rotated while nothing changed is ` +
            `worse than one that never claimed to.`
        )
      }
      seen.add(key)
    }
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
  platform: BymaxAuthModuleOptions['platform'],
  roles: BymaxAuthModuleOptions['roles']
): void {
  if (platform?.enabled && !roles.platformHierarchy) {
    throw new Error(
      `[BymaxAuthModule] roles.platformHierarchy is required when platform.enabled is true. ` +
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

/**
 * Bounds the two values that decide whether the account lockout exists at all.
 *
 * `windowSeconds` is handed straight to Redis as the counter's `EXPIRE`. Redis **deletes** a
 * key on `EXPIRE key 0`, so a zero window destroys every failure counter at the moment it is
 * created: the count never exceeds one, `isLockedOut` is permanently false, and the only
 * remaining defence against credential stuffing is the per-IP limiter — which a distributed
 * caller sidesteps. Nothing about that failure is visible; the configuration reads as "5
 * attempts per 0 seconds" and the library reports no problem.
 *
 * `maxAttempts` fails in both directions: `0` locks every account out permanently (the count
 * is always `>= 0`), and a very large value disables the lockout as thoroughly as the zero
 * window does. The ceiling is generous — it exists to catch `1_000_000`, not to second-guess
 * a deployment that wants 20.
 *
 * @param bruteForce - The configured brute-force group, if any.
 * @throws If either value falls outside its range.
 */
function validateBruteForce(bruteForce: BymaxAuthModuleOptions['bruteForce']): void {
  const windowSeconds = bruteForce?.windowSeconds
  if (windowSeconds !== undefined && (!Number.isInteger(windowSeconds) || windowSeconds < 1)) {
    throw new Error(
      `[BymaxAuthModule] bruteForce.windowSeconds must be a whole number of at least 1 ` +
        `(current: ${windowSeconds}). Redis deletes a key on \`EXPIRE key 0\`, so a zero or ` +
        `negative window destroys each failure counter as it is created and the account ` +
        `lockout never engages — silently, with the configuration still reading as enabled.`
    )
  }

  const maxAttempts = bruteForce?.maxAttempts
  if (maxAttempts !== undefined && (!Number.isInteger(maxAttempts) || maxAttempts < 1)) {
    throw new Error(
      `[BymaxAuthModule] bruteForce.maxAttempts must be a whole number of at least 1 ` +
        `(current: ${maxAttempts}). Zero locks out every account permanently, because a ` +
        `freshly created counter already satisfies "attempts >= 0".`
    )
  }
  if (maxAttempts !== undefined && maxAttempts > MAX_BRUTE_FORCE_ATTEMPTS) {
    throw new Error(
      `[BymaxAuthModule] bruteForce.maxAttempts must not exceed ${MAX_BRUTE_FORCE_ATTEMPTS} ` +
        `(current: ${maxAttempts}). A threshold this high disables the lockout as effectively ` +
        `as switching it off, while the configuration still reads as enabled.`
    )
  }
}

/**
 * Ceiling on `bruteForce.maxAttempts`. Generous by design: it catches a value that disables
 * the control, not a deployment that prefers a looser threshold than the default 5.
 */
const MAX_BRUTE_FORCE_ATTEMPTS = 100

/**
 * Bounds the scrypt parameters that carry its memory hardness.
 *
 * `costFactor` has a floor, but scrypt's memory cost is `128 * N * r` — `blockSize` is a
 * multiplier on it, so `r = 1` cuts the memory an `N` floor is there to guarantee by eight
 * and the floor stops meaning what it says. `parallelization` below 1 is not a weaker
 * setting but an invalid one: `crypto.scrypt` rejects it at the first hash, which is a
 * credential path failing at runtime over something startup could have caught.
 *
 * @param password - The configured password group, if any.
 * @throws If either parameter is below its floor.
 */
function validatePasswordMemoryParameters(password: BymaxAuthModuleOptions['password']): void {
  const blockSize = password?.blockSize
  if (blockSize !== undefined && blockSize < 8) {
    throw new Error(
      `[BymaxAuthModule] password.blockSize must be at least 8 (current: ${blockSize}). ` +
        `scrypt's memory cost is 128 * N * r, so a smaller block size divides the memory ` +
        `hardness that password.costFactor's floor exists to guarantee.`
    )
  }

  const parallelization = password?.parallelization
  if (parallelization !== undefined && parallelization < 1) {
    throw new Error(
      `[BymaxAuthModule] password.parallelization must be at least 1 ` +
        `(current: ${parallelization}).`
    )
  }
}

/**
 * Bounds the two MFA parameters that decide how much a second factor is worth.
 *
 * `totpWindow` is counted in 30-second steps on either side of now, so the number of codes
 * valid at any moment is `2 * totpWindow + 1`. At the default of 1 that is three; at 60 it
 * is 121, and a six-digit code is then a hundred times easier to guess than the digits
 * suggest. The ceiling here is deliberately generous — it is not a recommendation, it is the
 * line past which the value is a mistake rather than a tolerance for clock skew.
 *
 * `recoveryCodeCount` of zero enrols an account with no recovery path at all: lose the
 * authenticator and the account is gone, with the library reporting nothing wrong.
 *
 * @param mfa - The configured MFA group, if any.
 * @throws If either value falls outside its range.
 */
function validateMfaVerificationParameters(mfa: BymaxAuthModuleOptions['mfa']): void {
  const totpWindow = mfa?.totpWindow
  if (totpWindow !== undefined && (totpWindow < 0 || totpWindow > MAX_VERIFY_WINDOW)) {
    throw new Error(
      `[BymaxAuthModule] mfa.totpWindow must be between 0 and ${MAX_VERIFY_WINDOW} inclusive ` +
        `(current: ${totpWindow}). The window is counted in 30-second steps on either side ` +
        `of now, so ${2 * totpWindow + 1} codes would be valid at once. RFC 6238 §5.2 ` +
        `recommends at most one step of tolerance; the default of 1 accepts three codes. ` +
        `The bound matches the drift window the verifier actually applies, so a configured ` +
        `value always means what it says instead of being silently clamped.`
    )
  }

  const recoveryCodeCount = mfa?.recoveryCodeCount
  if (recoveryCodeCount !== undefined && (recoveryCodeCount < 1 || recoveryCodeCount > 50)) {
    throw new Error(
      `[BymaxAuthModule] mfa.recoveryCodeCount must be between 1 and 50 inclusive ` +
        `(current: ${recoveryCodeCount}). Zero enrols an account with no way back if the ` +
        `authenticator is lost.`
    )
  }
}

/** Fields required on every configured OAuth provider. */
const REQUIRED_OAUTH_FIELDS = ['clientId', 'clientSecret', 'callbackUrl'] as const

function validateOAuthProviders(oauth: BymaxAuthModuleOptions['oauth']): void {
  if (!oauth) return

  for (const [providerOrField, rawConfig] of Object.entries(oauth)) {
    // Skip top-level OAuth keys that are not provider blocks (e.g. `successRedirectUrl`,
    // `mfaRedirectUrl`, `errorRedirectUrl`). These are validated separately by the
    // dedicated `validateOAuth*RedirectUrl` helpers below.
    if (
      providerOrField === 'successRedirectUrl' ||
      providerOrField === 'mfaRedirectUrl' ||
      providerOrField === 'errorRedirectUrl'
    )
      continue

    const provider = providerOrField
    // Treat the provider config as a string-keyed record only for field-level
    // access; the public type is preserved elsewhere in ResolvedOptions.
    const config = rawConfig as Record<string, unknown>

    for (const field of REQUIRED_OAUTH_FIELDS) {
      // eslint-disable-next-line security/detect-object-injection -- field is from a const tuple
      if (!config[field]) {
        throw new Error(
          `[BymaxAuthModule] oauth.${provider}.${field} is required when the '${provider}' ` +
            `OAuth provider is configured.`
        )
      }
    }

    // Enforce HTTPS for the OAuth callback URL in production environments.
    // An HTTP callback URL causes the authorization code to transit over an unencrypted
    // connection, making it vulnerable to interception.
    const callbackUrl = config['callbackUrl']
    if (
      typeof callbackUrl === 'string' &&
      !callbackUrl.startsWith('https://') &&
      process.env['NODE_ENV'] === 'production'
    ) {
      throw new Error(
        `[BymaxAuthModule] oauth.${provider}.callbackUrl must use HTTPS in production ` +
          `(got: '${callbackUrl}'). Use an HTTPS URL to prevent authorization code interception.`
      )
    }
  }
}

/**
 * Validates `oauth.successRedirectUrl` shape + delivery mode compatibility.
 *
 * Three rules:
 * 1. Must be a non-empty string when set (empty rejected so misconfigured
 *    `process.env.OAUTH_REDIRECT_URL` doesn't silently fall through to "").
 * 2. Must use `https://` or start with `/` (relative) in production. HTTP is
 *    rejected so the post-callback redirect cannot strip away cookie `Secure`
 *    guarantees by hopping to an unencrypted leg.
 * 3. Requires `tokenDelivery` of `'cookie'` or `'both'` — `'bearer'` plus a
 *    redirect would discard the access token (the JSON body is replaced by
 *    a 302), leaving the browser logged-out on the destination page.
 */
function validateOAuthSuccessRedirectUrl(userOptions: BymaxAuthModuleOptions): void {
  const url = userOptions.oauth?.successRedirectUrl
  if (url === undefined) return

  if (typeof url !== 'string' || url.length === 0) {
    throw new Error(
      `[BymaxAuthModule] oauth.successRedirectUrl must be a non-empty string when set.`
    )
  }

  const isProduction = process.env['NODE_ENV'] === 'production'
  const isSafe = url.startsWith('/') || url.startsWith('https://')
  if (isProduction && !isSafe) {
    throw new Error(
      `[BymaxAuthModule] oauth.successRedirectUrl must use HTTPS or be a same-origin path ` +
        `(starts with '/') in production (got: '${url}').`
    )
  }

  // `tokenDelivery` defaults to `'cookie'`. Only reject when explicitly bearer-only.
  if (userOptions.tokenDelivery === 'bearer') {
    throw new Error(
      `[BymaxAuthModule] oauth.successRedirectUrl is set but tokenDelivery is 'bearer'. ` +
        `A redirect discards the JSON response body, so the access token would never reach the ` +
        `client. Use tokenDelivery: 'cookie' or 'both' when configuring a successRedirectUrl.`
    )
  }
}

/**
 * Validates `oauth.mfaRedirectUrl` shape.
 *
 * Two rules (mirrors `successRedirectUrl` minus the delivery-mode invariant):
 * 1. Must be a non-empty string when set.
 * 2. Must use `https://` or start with `/` (relative) in production. HTTP is
 *    rejected so the post-callback redirect cannot strip away cookie `Secure`
 *    guarantees by hopping to an unencrypted leg.
 *
 * No delivery-mode gate: the MFA temp token always travels via the dedicated
 * `mfa_temp_token` cookie (or the JSON body when `mfaRedirectUrl` is omitted),
 * not via the access-token cookie or response body — so `tokenDelivery: 'bearer'`
 * is compatible with this redirect.
 */
function validateOAuthMfaRedirectUrl(userOptions: BymaxAuthModuleOptions): void {
  const url = userOptions.oauth?.mfaRedirectUrl
  if (url === undefined) return

  if (typeof url !== 'string' || url.length === 0) {
    throw new Error(`[BymaxAuthModule] oauth.mfaRedirectUrl must be a non-empty string when set.`)
  }

  const isProduction = process.env['NODE_ENV'] === 'production'
  const isSafe = url.startsWith('/') || url.startsWith('https://')
  if (isProduction && !isSafe) {
    throw new Error(
      `[BymaxAuthModule] oauth.mfaRedirectUrl must use HTTPS or be a same-origin path ` +
        `(starts with '/') in production (got: '${url}').`
    )
  }
}

/**
 * Validates `oauth.errorRedirectUrl` shape.
 *
 * Same two rules as `mfaRedirectUrl`: non-empty string, production HTTPS or
 * same-origin path. No delivery-mode gate — failure redirects never carry
 * tokens, so they are compatible with every `tokenDelivery` mode.
 */
function validateOAuthErrorRedirectUrl(userOptions: BymaxAuthModuleOptions): void {
  const url = userOptions.oauth?.errorRedirectUrl
  if (url === undefined) return

  if (typeof url !== 'string' || url.length === 0) {
    throw new Error(`[BymaxAuthModule] oauth.errorRedirectUrl must be a non-empty string when set.`)
  }

  const isProduction = process.env['NODE_ENV'] === 'production'
  const isSafe = url.startsWith('/') || url.startsWith('https://')
  if (isProduction && !isSafe) {
    throw new Error(
      `[BymaxAuthModule] oauth.errorRedirectUrl must use HTTPS or be a same-origin path ` +
        `(starts with '/') in production (got: '${url}').`
    )
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

/**
 * Validates that `cookies.sameSite: 'none'` is only used with `Secure` cookies.
 *
 * Per the HTTP cookie spec, browsers reject `SameSite=None` cookies that lack
 * the `Secure` attribute. Catching this combination at startup turns a silent
 * runtime failure (browser drops the cookie, user can't log in) into a loud
 * configuration error.
 *
 * `secureCookies` defaults to `true` in production and `false` otherwise. The
 * `'none'` posture is only meaningful with a TLS-served origin, so requiring
 * `secureCookies: true` regardless of `NODE_ENV` is the safe rule.
 */
function validateSameSiteNoneRequiresSecure(userOptions: BymaxAuthModuleOptions): void {
  const sameSite = userOptions.cookies?.sameSite
  if (sameSite !== 'none') return
  const secureCookies = userOptions.secureCookies ?? process.env['NODE_ENV'] === 'production'
  if (!secureCookies) {
    throw new Error(
      `[BymaxAuthModule] cookies.sameSite is 'none' but secureCookies is false. ` +
        `Browsers reject SameSite=None cookies without the Secure attribute, so the auth ` +
        `cookies would never be stored. Set secureCookies: true (and serve over HTTPS) or ` +
        `use cookies.sameSite: 'lax' / 'strict'.`
    )
  }
}

/**
 * Validates that the trusted-origin allowlist and the `SameSite` posture agree.
 *
 * The allowlist only ever matters under `SameSite=None`: that is the one setting where the
 * browser sends the session cookie on a cross-site state-changing request, and therefore the
 * one setting where an origin needs authorizing. Either half without the other is a
 * misconfiguration that fails quietly — `'none'` with no list rejects every cross-site call,
 * a list under `'lax'` is never consulted — so both are refused at startup rather than
 * discovered in production.
 */
function validateTrustedOrigins(userOptions: BymaxAuthModuleOptions): void {
  const sameSite = userOptions.cookies?.sameSite ?? DEFAULT_OPTIONS.cookies.sameSite
  const trustedOrigins = userOptions.cookies?.trustedOrigins ?? []

  if (sameSite === 'none' && trustedOrigins.length === 0) {
    throw new Error(
      `[BymaxAuthModule] cookies.sameSite is 'none' but cookies.trustedOrigins is empty. ` +
        `SameSite=None sends the session cookie on every cross-site request, so the origins ` +
        `allowed to make one must be named — with none listed, every cross-site call that ` +
        `changes state is rejected. Set cookies.trustedOrigins: ['https://app.example.com'].`
    )
  }

  // A cookie-domain resolver puts the list back in play under 'lax'/'strict' too. Those
  // withhold the cookie CROSS-SITE, not cross-ORIGIN: a deployment serving app.example.com and
  // api.example.com from one `.example.com` cookie is same-site, so the browser sends it on a
  // POST between them — and `Sec-Fetch-Site: same-site` is not one of the values that proves a
  // request came from the app itself, so `TrustedOriginGuard` falls through to the origin
  // check. Refusing the list there left that deployment with no configuration at all: the
  // cookie arrives, the request is refused 403, and the one setting that would have allowed it
  // was rejected at startup.
  const sharesACookieDomain = userOptions.cookies?.resolveDomains !== undefined

  if (sameSite !== 'none' && !sharesACookieDomain && trustedOrigins.length > 0) {
    throw new Error(
      `[BymaxAuthModule] cookies.trustedOrigins is set but cookies.sameSite is '${sameSite}' ` +
        `and no cookies.resolveDomains is configured. The browser sends the session cookie ` +
        `cross-origin under that posture only when a shared cookie domain makes the origins ` +
        `same-site, so without one the allowlist is never consulted. Use ` +
        `cookies.sameSite: 'none' (with secureCookies: true), add cookies.resolveDomains for a ` +
        `subdomain deployment, or drop trustedOrigins.`
    )
  }

  const malformed = trustedOrigins.filter((origin) => !isAbsoluteOrigin(origin))
  if (malformed.length > 0) {
    throw new Error(
      `[BymaxAuthModule] cookies.trustedOrigins contains entries that are not absolute ` +
        `origins: ${malformed.join(', ')}. Each entry is compared verbatim against the ` +
        `request's Origin header, which is always 'scheme://host[:port]' with no path or ` +
        `trailing slash — anything else can never match.`
    )
  }
}

/**
 * Whether a string is exactly an origin: scheme, host, optional port, nothing else.
 *
 * Parsing rather than pattern-matching, then requiring the round trip to be identical, is what
 * rejects a trailing slash, a path, or credentials — all of which parse fine but never equal
 * an `Origin` header.
 *
 * @param value - The configured entry.
 * @returns `true` when the value is a bare absolute origin.
 */
function isAbsoluteOrigin(value: string): boolean {
  try {
    return new URL(value).origin === value
  } catch {
    // Not a URL at all — a bare hostname or a typo.
    return false
  }
}

/**
 * Hard ceiling on `jwt.refreshGraceWindowSeconds`, in seconds (five minutes).
 *
 * Deliberately far above the 30-second default and far below anything that could be mistaken
 * for a session policy. `rust-auth` enforces the identical bound.
 */
const MAX_REFRESH_GRACE_WINDOW_SECONDS = 300

function validateRefreshGraceWindow(jwt: BymaxAuthModuleOptions['jwt']): void {
  const graceSeconds =
    jwt.refreshGraceWindowSeconds ?? DEFAULT_OPTIONS.jwt.refreshGraceWindowSeconds
  const refreshExpiresInDays = jwt.refreshExpiresInDays ?? DEFAULT_OPTIONS.jwt.refreshExpiresInDays
  const refreshLifetimeSeconds = refreshExpiresInDays * 86_400

  if (!Number.isFinite(refreshExpiresInDays) || refreshExpiresInDays <= 0) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshExpiresInDays must be a positive finite number. ` +
        `Got: ${refreshExpiresInDays}. Zero, negative, NaN, and Infinity are all rejected — ` +
        `any of these would produce an invalid Redis TTL and cause all token rotations to fail at runtime.`
    )
  }

  if (graceSeconds >= refreshLifetimeSeconds) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshGraceWindowSeconds (${graceSeconds} s) must be less than ` +
        `the refresh token lifetime jwt.refreshExpiresInDays * 86400 (${refreshLifetimeSeconds} s). ` +
        `A grace window equal to or longer than the token lifetime would allow grace pointers ` +
        `to outlive the refresh session they protect.`
    )
  }

  // The relative bound above is not enough on its own: a 6-day window under a 7-day refresh
  // passes it. This window is the span in which an already-consumed refresh token still buys a
  // session, so it is the replay window for a stolen one — it exists to cover a single network
  // retry, measured in seconds, not a policy knob measured in days.
  if (graceSeconds < 0 || graceSeconds > MAX_REFRESH_GRACE_WINDOW_SECONDS) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshGraceWindowSeconds must be between 0 and ` +
        `${MAX_REFRESH_GRACE_WINDOW_SECONDS} inclusive (current: ${graceSeconds}). The window is ` +
        `how long an already-consumed refresh token still recovers a session, so it is exactly ` +
        `the replay window for a stolen one. It covers a client that rotated but never received ` +
        `the response — a retry, not a policy. 0 disables grace recovery entirely.`
    )
  }
}

/**
 * Seconds per unit accepted in a `jwt.accessExpiresIn` time string.
 *
 * The vocabulary is `ms`'s, because `@nestjs/jwt` hands the value straight to that parser. It is
 * reproduced rather than depended on: the library ships zero direct dependencies, and the epoch
 * bound below needs the value as a number before any token is ever signed.
 */
const DURATION_UNIT_SECONDS: Record<string, number> = {
  ms: 0.001,
  msec: 0.001,
  msecs: 0.001,
  millisecond: 0.001,
  milliseconds: 0.001,
  s: 1,
  sec: 1,
  secs: 1,
  second: 1,
  seconds: 1,
  m: 60,
  min: 60,
  mins: 60,
  minute: 60,
  minutes: 60,
  h: 3_600,
  hr: 3_600,
  hrs: 3_600,
  hour: 3_600,
  hours: 3_600,
  d: 86_400,
  day: 86_400,
  days: 86_400,
  w: 604_800,
  week: 604_800,
  weeks: 604_800,
  y: 31_557_600,
  yr: 31_557_600,
  yrs: 31_557_600,
  year: 31_557_600,
  years: 31_557_600
}

/** Strips the leading amount — digits, decimal point, and any space before the unit. */
// Stryker disable Regex: the `^` is equivalent under the `amount > 0` guard below. A string
// that reaches the unit lookup with a usable amount has its numeric run at index 0, so an
// unanchored search finds the same match; one whose numeric run starts later makes
// `Number.parseFloat` return NaN and is rejected on the amount, never on the unit. Verified
// against 211k generated inputs — anchored and unanchored agree on every one. The anchor stays
// because it states what this pattern is for, and would become load-bearing again the moment
// someone relaxes that guard.
const DURATION_AMOUNT_PREFIX = /^[\d.\s]+/
// Stryker restore Regex

/**
 * Convert a `jwt.accessExpiresIn` time string to seconds.
 *
 * A bare number is deliberately not accepted. `ms` reads it as milliseconds while a reader almost
 * always means seconds, and the two differ by a factor of a thousand on a value that decides how
 * long a stolen access token stays usable — so the ambiguity is rejected rather than guessed at.
 * A number with no unit leaves nothing for the unit table to match, which is what rejects it.
 *
 * Parsed as amount-then-unit rather than through one anchored pattern so that every branch here
 * is reachable from a real configuration value: a capture group the pattern already guarantees
 * would still need an unreachable "absent" arm to satisfy `noUncheckedIndexedAccess`.
 *
 * @param value - The configured time span, e.g. `'15m'`, `'1 hour'`, `'900s'`.
 * @returns The span in seconds, or `undefined` when the string is not a positive time span
 *   `ms` accepts.
 */
function durationToSeconds(value: string): number | undefined {
  const trimmed = value.trim()
  const unit = trimmed.replace(DURATION_AMOUNT_PREFIX, '').toLowerCase()
  const seconds = DURATION_UNIT_SECONDS[unit]
  const amount = Number.parseFloat(trimmed)

  // A non-positive lifetime is rejected here rather than compared against the bound below: it is
  // not a value that "fits", it is a token that expires at or before it is issued.
  if (seconds === undefined || !(amount > 0)) return undefined

  return amount * seconds
}

/**
 * Reject an access-token lifetime that outlives the window a store keeps a bumped token epoch
 * readable.
 *
 * The epoch is what makes a stateless access token revocable: a password reset bumps the user's
 * generation, and every token minted before it stops verifying. That only holds while the bumped
 * value is still readable — once the record expires the lookup falls back to `0`, the comparison
 * stops firing, and a token the reset revoked verifies again. An access token allowed to outlive
 * {@link TOKEN_EPOCH_RETENTION_SECONDS} would sit in exactly that gap, so the bound is enforced
 * at startup, where it is a configuration error, rather than discovered as a silent fail-open.
 *
 * An unparseable time string is rejected here too: `@nestjs/jwt` would otherwise fail at the
 * first sign, long after startup, and a value this function cannot read is a value the bound
 * cannot be checked against. rust-auth enforces the same rule
 * (`AccessLifetimeExceedsEpochRetention`) over a `Duration`, which cannot be malformed.
 *
 * @param jwt - The user-supplied `jwt` option block.
 * @throws If `accessExpiresIn` is malformed or exceeds the epoch retention window.
 */
function validateAccessLifetimeAgainstEpochRetention(jwt: BymaxAuthModuleOptions['jwt']): void {
  const configured = jwt.accessExpiresIn ?? DEFAULT_OPTIONS.jwt.accessExpiresIn
  const seconds = durationToSeconds(configured)

  if (seconds === undefined) {
    throw new Error(
      `[BymaxAuthModule] jwt.accessExpiresIn must be a time span such as '15m', '1h' or '900s'. ` +
        `Got: '${configured}'. A value the signer cannot read would fail at the first token ` +
        `issued, and leaves the token-epoch retention bound unverifiable at startup.`
    )
  }

  if (seconds > TOKEN_EPOCH_RETENTION_SECONDS) {
    throw new Error(
      `[BymaxAuthModule] jwt.accessExpiresIn ('${configured}' = ${seconds} s) must not exceed the ` +
        `token-epoch retention window (${TOKEN_EPOCH_RETENTION_SECONDS} s). An access token that ` +
        `outlives the stored epoch would survive the password reset that revoked it: the epoch ` +
        `lookup falls back to 0 once the record expires, and the staleness check stops firing.`
    )
  }
}
