/**
 * @fileoverview How a refusal names the value it received.
 *
 * A number is printed, because `NaN`, `Infinity` or `1e300` is what an operator needs to see. Anything
 * else is named by its type, because the value could be a secret passed to the wrong option by
 * mistake, and a boot error is logged.
 *
 * @layer Config
 */

/**
 * Names a received option value for an error message.
 *
 * @param value - The value the host supplied.
 * @returns The number itself, or `a <type>` for anything else.
 */
export function describeReceived(value: unknown): string {
  if (typeof value === 'number') return String(value)
  if (value === null || value === undefined) return String(value)
  if (Array.isArray(value)) return 'an array'
  const kind = typeof value
  return `${kind === 'object' ? 'an' : 'a'} ${kind}`
}
