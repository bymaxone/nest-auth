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
 * Refuses a value that is not a whole number inside `[min, max]`.
 *
 * @param path - The option's dotted path, for the message.
 * @param value - The configured value, if any.
 * @param min - The smallest accepted value.
 * @param max - The largest accepted value, or `undefined` for no ceiling.
 * @param why - What the option bounds, for the message.
 * @throws {Error} when `value` is present and is not a whole number in range.
 */
function assertWholeNumber(
  path: string,
  value: unknown,
  min: number,
  max: number | undefined,
  why: string
): void {
  if (value === undefined) return
  if (
    Number.isInteger(value) &&
    (value as number) >= min &&
    (max === undefined || (value as number) <= max)
  ) {
    return
  }
  const range = max === undefined ? `of at least ${min}` : `between ${min} and ${max} inclusive`
  throw new Error(
    `[BymaxAuthModule] ${path} must be a whole number ${range} (current: ${String(value)}). ${why}`
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
    1,
    undefined,
    'It is the cookie Max-Age; zero deletes the cookie and NaN is ignored by the browser, ' +
      'so the session would end with the tab.'
  )
  assertWholeNumber(
    'sessions.defaultMaxSessions',
    userOptions.sessions?.defaultMaxSessions,
    1,
    undefined,
    'It caps concurrent sessions: with NaN the comparison is false in both directions, no ' +
      'session is ever evicted, and the cap does not exist.'
  )
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
      undefined,
      'It is a Redis expiry in seconds: zero or a negative deletes the record as it is written, ' +
        'and NaN, a fraction or Infinity is refused by Redis on every request.'
    )
  }
  assertWholeNumber(
    'userStatusCacheTtlSeconds',
    userOptions.userStatusCacheTtlSeconds,
    1,
    MAX_USER_STATUS_CACHE_TTL_SECONDS,
    'It is how long a suspended account keeps passing the dashboard guards, so it has a ceiling.'
  )
}

/**
 * Bounds `jwt.absoluteSessionLifetimeDays`, the hard cap on how long rotation can extend a login.
 *
 * `0` switches the cap off on purpose and nothing else may: with `NaN` the comparisons that decide
 * whether a session is too old are false, so the cap would be skipped without being asked to. A
 * fraction of a day is a meaningful lifetime, so the value is tested as finite and not as whole.
 *
 * @param jwt - The configured `jwt` group.
 * @throws {Error} when the value is present and is not `0` or a positive finite number.
 */
function validateAbsoluteSessionLifetime(jwt: BymaxAuthModuleOptions['jwt']): void {
  const days = jwt.absoluteSessionLifetimeDays
  if (days === undefined || (Number.isFinite(days) && days >= 0)) return
  throw new Error(
    `[BymaxAuthModule] jwt.absoluteSessionLifetimeDays must be 0 or a positive finite number ` +
      `(current: ${String(days)}). Only 0 switches the cap off; NaN or a negative would skip it ` +
      `without being asked to, and Infinity is a cap that never fires. Set 0 to accept unbounded ` +
      `sessions deliberately.`
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
        `(current: ${otpLength}). Values below 4 are too easily guessable; ` +
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
        `(current: ${totpWindow}). The window is counted in 30-second steps on either side ` +
        `of the current time, so ${2 * totpWindow + 1} codes would be valid at once. RFC 6238 §5.2 ` +
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
        `(current: ${recoveryCodeCount}). Zero enrols an account with no way back if the ` +
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
  // passes it. This window is the span in which an already-consumed refresh token buys a
  // session, so it is the replay window for a stolen one — it exists to cover a single network
  // retry, measured in seconds, not a policy knob measured in days.
  if (
    !Number.isInteger(graceSeconds) ||
    graceSeconds < 0 ||
    graceSeconds > MAX_REFRESH_GRACE_WINDOW_SECONDS
  ) {
    throw new Error(
      `[BymaxAuthModule] jwt.refreshGraceWindowSeconds must be between 0 and ` +
        `${MAX_REFRESH_GRACE_WINDOW_SECONDS} inclusive (current: ${graceSeconds}). The window is ` +
        `how long an already-consumed refresh token recovers a session, so it is exactly ` +
        `the replay window for a stolen one. It covers a client that rotated but never received ` +
        `the response — a retry, not a policy. 0 disables grace recovery entirely. The value must be a whole number: Redis takes an ` +
        `integer expiry, so a fraction or NaN would fail every rotation.`
    )
  }
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
  validateWholeNumberOptions(userOptions)
}
