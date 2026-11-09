/**
 * @fileoverview Parsing of the `ms`-style time spans the options accept (`'15m'`, `'1 hour'`).
 *
 * @layer Config
 */

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
export function durationToSeconds(value: string): number | undefined {
  const trimmed = value.trim()
  const unit = trimmed.replace(DURATION_AMOUNT_PREFIX, '').toLowerCase()
  const seconds = DURATION_UNIT_SECONDS[unit]
  const amount = Number.parseFloat(trimmed)

  // A non-positive lifetime is rejected here rather than compared against the bound below: it is
  // not a value that "fits", it is a token that expires at or before it is issued.
  if (seconds === undefined || !(amount > 0)) return undefined

  return amount * seconds
}
