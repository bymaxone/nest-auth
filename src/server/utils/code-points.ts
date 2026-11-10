/**
 * @fileoverview Length bounds that count Unicode code points, as the shared contract states.
 *
 * @layer Util
 */

/**
 * Whether a string is longer than a bound, counting Unicode code points.
 *
 * The count visits every character, like the trim and the control-character test beside it at each
 * call site, so callers pass text that is already bounded: a request field the validation pipe has
 * capped, a route parameter, or a value the host supplied.
 *
 * The validation pipe counts code points (validator.js subtracts surrogate pairs), and the shared
 * contract says every length bound does. A service-side check that counted UTF-16 units instead
 * would refuse a name the pipe accepted: an emoji is one code point and two units.
 *
 * @param value - The text to measure.
 * @param max - The longest length accepted, in code points.
 * @returns `true` when the text has more than `max` code points.
 */
export function exceedsCodePoints(value: string, max: number): boolean {
  return codePointLength(value) > max
}

/**
 * Whether a string is shorter than a floor, counting Unicode code points.
 *
 * @param value - The text to measure.
 * @param min - The shortest length accepted, in code points.
 * @returns `true` when the text has fewer than `min` code points.
 */
export function isShorterThanCodePoints(value: string, min: number): boolean {
  return codePointLength(value) < min
}

/**
 * Counts the Unicode code points of a string.
 *
 * @param value - The text to measure.
 * @returns The number of code points; a surrogate pair counts once.
 */
export function codePointLength(value: string): number {
  let count = 0
  for (const _ of value) count += 1
  return count
}
