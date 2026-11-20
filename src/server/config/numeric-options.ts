/**
 * @fileoverview Boot-time bounds on every numeric option that decides a count, a lifetime or a window.
 *
 * A bound written as `x < min || x > max` accepts `NaN`, because a comparison with `NaN` is false in
 * both directions, and the bound it was meant to enforce is then gone without a sign: a session cap
 * that evicts nothing, an absolute lifetime that never fires, an OTP that cannot be generated. Every
 * option here is therefore tested as a whole number (or, where a fraction of a day is meaningful, as
 * a finite one) before any range is applied. `Number.isInteger` is false for `NaN`, both infinities
 * and a numeric string, which is how these values arrive from JSON, an environment variable or
 * untyped JavaScript.
 *
 * @layer Config
 */

import { DEFAULT_OPTIONS } from './default-options'
import { describeReceived } from './describe-received'
import { MAX_VERIFY_WINDOW } from '../crypto/totp'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/**
 * The longest `userStatusCacheTtlSeconds` the module accepts, in seconds (one hour).
 *
 * The cached account status is how long a suspended account keeps passing the dashboard guards, so
 * the TTL is a security bound and not a tuning knob.
 */
export const MAX_USER_STATUS_CACHE_TTL_SECONDS = 3600

/**
 * The longest Redis expiry any option may set, in seconds (ten years).
 *
 * Redis refuses an expiry whose millisecond value overflows 64 bits with "invalid expire time", on
 * every command that carries it, and a token that outlives a decade is a credential that never
 * expires. `Number.isInteger` is true for `1e300`, so the ceiling is what keeps such a value out.
 */
const MAX_REDIS_TTL_SECONDS = 315_360_000

/** The same ten years in milliseconds, for the access cookie's `Max-Age`. */
const MAX_COOKIE_MAX_AGE_MS = MAX_REDIS_TTL_SECONDS * 1000

/**
 * The most concurrent sessions per user the cap accepts. One refresh record and one index member
 * exist per session, so a cap above this is no cap, and a value near the largest integer reads as
 * "no limit" without saying so.
 */
const MAX_SESSIONS_PER_USER = 1000

/** The longest lifetime in days that `jwt.refreshExpiresInDays` and the absolute cap accept (ten years). */
const MAX_LIFETIME_DAYS = 3650

/**
 * The shortest absolute session lifetime in days that is not `0` (one hour). The token manager
 * compares a session's age with the cap at each rotation, so a smaller positive value ends every
 * session at its first rotation after that age, minutes after login.
 */
const MIN_ABSOLUTE_LIFETIME_DAYS = 1 / 24

/**
 * The largest `password.parallelization` (`p`) the module accepts. scrypt's CPU cost grows linearly with
 * it and an unauthenticated login derives a hash for an address that does not exist, so a `p` past this
 * is a request that costs seconds; Node refuses `p * r` at 2 ** 30 on the first derivation, which is
 * the first login after deploy.
 */
const MAX_SCRYPT_PARALLELIZATION = 16

/** The longest `bruteForce.windowSeconds` in seconds (one week): a longer window locks an account for a month over five typos. */
const MAX_BRUTE_FORCE_WINDOW_SECONDS = 604_800

/**
 * Refuses a value that is not a whole number inside `[min, max]`.
 *
 * @param path - The option's dotted path, for the message.
 * @param value - The configured value, if any.
 * @param min - The smallest accepted value.
 * @param max - The largest accepted value.
 * @param why - What the option bounds, for the message.
 * @throws {Error} when `value` is present and is not a safe whole number in range.
 */
function assertWholeNumber(
  path: string,
  value: unknown,
  min: number,
  max: number,
  why: string
): void {
  if (value === undefined) return
  if (Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max) return
  throw new Error(
    `[BymaxAuthModule] ${path} must be a whole number between ${min} and ${max} inclusive ` +
      `(received ${describeReceived(value)}). ${why}`
  )
}

/**
 * Bounds the lifetime caps and TTLs that are plain whole numbers of seconds, milliseconds or
 * sessions.
 *
 * @param userOptions - The user-supplied options.
 * @throws {Error} naming the first option that is not a usable number.
 */
function validateWholeNumberOptions(userOptions: BymaxAuthModuleOptions): void {
  assertWholeNumber(
    'jwt.accessCookieMaxAgeMs',
    userOptions.jwt.accessCookieMaxAgeMs,
    1000,
    MAX_COOKIE_MAX_AGE_MS,
    'It is the cookie Max-Age in milliseconds, sent in whole seconds: under 1000 it becomes ' +
      'Max-Age=0, which deletes the cookie, and NaN is ignored by the browser, so the session ' +
      'would end with the tab.'
  )
  assertWholeNumber(
    'sessions.defaultMaxSessions',
    userOptions.sessions?.defaultMaxSessions,
    1,
    MAX_SESSIONS_PER_USER,
    'It caps concurrent sessions per user, counted in whole sessions: NaN evicts no session, ' +
      'zero or a negative value evicts them all, a fraction cannot be counted, and a value ' +
      'above 1000 is no cap.'
  )
  assertWholeNumber(
    'bruteForce.windowSeconds',
    userOptions.bruteForce?.windowSeconds,
    1,
    MAX_BRUTE_FORCE_WINDOW_SECONDS,
    'It is the Redis expiry of each failure counter: Redis deletes a key on `EXPIRE key 0`, so a ' +
      'zero or negative window destroys each counter as it is created and the lockout never ' +
      'engages, silently; a window past a week locks an account for a month over a few typos.'
  )
  assertWholeNumber(
    'userStatusCacheTtlSeconds',
    userOptions.userStatusCacheTtlSeconds,
    1,
    MAX_USER_STATUS_CACHE_TTL_SECONDS,
    'It is how long a suspended account keeps passing the dashboard guards, so it has a ceiling.'
  )
}

/**
 * Bounds the five Redis expiries a feature sets, each a whole number of seconds from 1 to ten years.
 *
 * @param userOptions - The user-supplied options.
 * @throws {Error} naming the first expiry that is not usable.
 */
function validateRedisTtls(userOptions: BymaxAuthModuleOptions): void {
  const ttls: [string, unknown][] = [
    ['passwordReset.tokenTtlSeconds', userOptions.passwordReset?.tokenTtlSeconds],
    ['passwordReset.otpTtlSeconds', userOptions.passwordReset?.otpTtlSeconds],
    ['emailVerification.otpTtlSeconds', userOptions.emailVerification?.otpTtlSeconds],
    ['emailChange.tokenTtlSeconds', userOptions.emailChange?.tokenTtlSeconds],
    ['invitations.tokenTtlSeconds', userOptions.invitations?.tokenTtlSeconds]
  ]
  for (const [path, value] of ttls) {
    assertWholeNumber(
      path,
      value,
      1,
      MAX_REDIS_TTL_SECONDS,
      'It is a Redis expiry in seconds: zero or a negative deletes the record as it is written, ' +
        'and NaN, a fraction, Infinity or a value past what Redis can hold is refused by Redis on ' +
        'every request.'
    )
  }
}

/**
 * Bounds `jwt.absoluteSessionLifetimeDays`, the hard cap on how long rotation can extend a login.
 *
 * `0` switches the cap off on purpose and nothing else may. `NaN` makes the comparisons that decide
 * whether a session is too old false, and so does an overflow: past about 1e300 days
 * `days * 86_400_000` is `Infinity`, `age > Infinity` is never true, and the cap is off again. The
 * value is therefore `0` or a finite number of days from one hour to ten years. A fraction of a day
 * is a meaningful lifetime, so it is tested as finite and not as whole.
 *
 * @param jwt - The configured `jwt` group.
 * @throws {Error} when the value is present and is neither `0` nor a finite number inside the range.
 */
function validateAbsoluteSessionLifetime(jwt: BymaxAuthModuleOptions['jwt']): void {
  const days = jwt.absoluteSessionLifetimeDays
  if (
    days === undefined ||
    days === 0 ||
    (Number.isFinite(days) && days >= MIN_ABSOLUTE_LIFETIME_DAYS && days <= MAX_LIFETIME_DAYS)
  ) {
    return
  }
  throw new Error(
    `[BymaxAuthModule] jwt.absoluteSessionLifetimeDays must be 0 or between ` +
      `${MIN_ABSOLUTE_LIFETIME_DAYS.toFixed(4)} and ${MAX_LIFETIME_DAYS} days (received ${describeReceived(days)}). ` +
      `Only 0 switches the cap off; NaN, a negative or a value so large that its length in ` +
      `milliseconds overflows would skip it without being asked to, and a value under an hour ` +
      `ends every session at its first rotation after that age, minutes after login. Set 0 to ` +
      `accept unbounded sessions deliberately.`
  )
}

function validatePasswordResetOtpLength(
  passwordReset: BymaxAuthModuleOptions['passwordReset']
): void {
  const otpLength = passwordReset?.otpLength
  if (otpLength === undefined) return

  if (!Number.isInteger(otpLength) || otpLength < 4 || otpLength > 8) {
    throw new Error(
      `[BymaxAuthModule] passwordReset.otpLength must be between 4 and 8 inclusive ` +
        `(received ${describeReceived(otpLength)}). Values below 4 are too easily guessable; ` +
        `values above 8 are not required for security and degrade user experience. The value must also be a whole number: ` +
        `a comparison with NaN is false both ways, so a bound written as a range alone lets it through.`
    )
  }
}

/**
 * Bounds the two MFA parameters that decide how much a second factor is worth.
 *
 * `totpWindow` is counted in 30-second steps on either side of the current time, so the number of codes
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
  if (
    totpWindow !== undefined &&
    (!Number.isInteger(totpWindow) || totpWindow < 0 || totpWindow > MAX_VERIFY_WINDOW)
  ) {
    throw new Error(
      `[BymaxAuthModule] mfa.totpWindow must be between 0 and ${MAX_VERIFY_WINDOW} inclusive ` +
        `(received ${describeReceived(totpWindow)}). The window is counted in 30-second steps on either side ` +
        `of the current time, so ${typeof totpWindow === 'number' ? 2 * totpWindow + 1 : '2N + 1'} codes would be valid at once. RFC 6238 §5.2 ` +
        `recommends at most one step of tolerance; the default of 1 accepts three codes. ` +
        `The bound matches the drift window the verifier actually applies, so a configured ` +
        `value means what it says and is never silently clamped. It must be a ` +
        `whole number.`
    )
  }

  const recoveryCodeCount = mfa?.recoveryCodeCount
  if (
    recoveryCodeCount !== undefined &&
    (!Number.isInteger(recoveryCodeCount) || recoveryCodeCount < 1 || recoveryCodeCount > 50)
  ) {
    throw new Error(
      `[BymaxAuthModule] mfa.recoveryCodeCount must be between 1 and 50 inclusive ` +
        `(received ${describeReceived(recoveryCodeCount)}). Zero enrols an account with no way back if the ` +
        `authenticator is lost. The count must be a whole number.`
    )
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
  const refreshLifetimeSeconds =
    typeof refreshExpiresInDays === 'number' ? refreshExpiresInDays * 86_400 : Number.NaN
  const isGraceNumber = typeof graceSeconds === 'number'

  if (
    !Number.isFinite(refreshExpiresInDays) ||
    refreshExpiresInDays <= 0 ||
    refreshExpiresInDays > MAX_LIFETIME_DAYS ||
    !Number.isInteger(refreshLifetimeSeconds)
  ) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshExpiresInDays must be a positive finite number. ` +
        `It received ${describeReceived(refreshExpiresInDays)}. Zero, negative, NaN, and Infinity are all rejected — ` +
        `any of these would produce an invalid Redis TTL and cause all token rotations to fail at runtime. ` +
        `It is at most ${MAX_LIFETIME_DAYS} days, and days × 86400 must be a whole number of seconds, ` +
        `because Redis takes an integer expiry: 1.5 and 0.25 are, 1.1 is not.`
    )
  }

  if (isGraceNumber && graceSeconds >= refreshLifetimeSeconds) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshGraceWindowSeconds (${graceSeconds} s) must be less than ` +
        `the refresh token lifetime jwt.refreshExpiresInDays * 86400 (${refreshLifetimeSeconds} s). ` +
        `A grace window equal to or longer than the token lifetime would allow grace pointers ` +
        `to outlive the refresh session they protect.`
    )
  }

  // The relative bound is not enough alone: a 6-day window under a 7-day refresh passes it, yet this
  // window is the replay window for a stolen refresh token, so it is measured in seconds.
  if (
    !isGraceNumber ||
    !Number.isInteger(graceSeconds) ||
    graceSeconds < 0 ||
    graceSeconds > MAX_REFRESH_GRACE_WINDOW_SECONDS
  ) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshGraceWindowSeconds must be between 0 and ` +
        `${MAX_REFRESH_GRACE_WINDOW_SECONDS} inclusive (received ${describeReceived(graceSeconds)}). The window is ` +
        `how long an already-consumed refresh token recovers a session, so it is exactly ` +
        `the replay window for a stolen one. It covers a client that rotated but never received ` +
        `the response — a retry, not a policy. 0 disables grace recovery entirely. The value must be a whole number: Redis takes an ` +
        `integer expiry, so a fraction or NaN would fail every rotation.`
    )
  }
}

/**
 * Bounds `password.parallelization` from above. That it is a whole number of at least 1 is checked
 * by the scrypt parameter validator in `resolved-options.ts`; this function holds only the ceiling.
 *
 * @param password - The configured `password` group.
 * @throws {Error} when the value is a finite number above the ceiling.
 */
function validateScryptParallelizationCeiling(password: BymaxAuthModuleOptions['password']): void {
  const parallelization = password?.parallelization
  if (
    parallelization === undefined ||
    !Number.isFinite(parallelization) ||
    parallelization <= MAX_SCRYPT_PARALLELIZATION
  ) {
    return
  }
  throw new Error(
    `[BymaxAuthModule] password.parallelization must be at most ${MAX_SCRYPT_PARALLELIZATION} ` +
      `(received ${describeReceived(parallelization)}). scrypt's CPU cost grows linearly with it and an ` +
      `unauthenticated login derives a hash even for an address that does not exist.`
  )
}

/**
 * Runs every numeric-option bound.
 *
 * @param userOptions - The user-supplied options.
 * @throws {Error} naming the first option that is not a usable number.
 */
export function validateNumericOptions(userOptions: BymaxAuthModuleOptions): void {
  validatePasswordResetOtpLength(userOptions.passwordReset)
  validateMfaVerificationParameters(userOptions.mfa)
  validateRefreshGraceWindow(userOptions.jwt)
  validateAbsoluteSessionLifetime(userOptions.jwt)
  validateScryptParallelizationCeiling(userOptions.password)
  validateWholeNumberOptions(userOptions)
  validateRedisTtls(userOptions)
}
