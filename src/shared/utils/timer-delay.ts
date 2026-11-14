/**
 * @fileoverview The delay a timer can be given: the largest one `setTimeout` and `setInterval` honor.
 *
 * @layer Utility
 */

/**
 * The largest delay, in milliseconds, a timer takes as given: a signed 32-bit integer. Node
 * replaces a larger one, `NaN` and `Infinity` with 1 ms, and a browser wraps it, so an option that
 * reaches a timer unchecked can turn a "never" into a loop that fires every millisecond.
 */
export const MAX_TIMER_DELAY_MS = 2_147_483_647

/**
 * Whether a value is a delay a timer honors: a finite number of milliseconds from 0 to
 * {@link MAX_TIMER_DELAY_MS}.
 *
 * @param value - The option value.
 * @returns `true` when a timer can be armed with it as given.
 */
export function isTimerDelay(value: unknown): value is number {
  return typeof value === 'number' && value >= 0 && value <= MAX_TIMER_DELAY_MS
}
