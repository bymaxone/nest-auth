/**
 * @fileoverview Named refusals for an option that must be an object or an array and is something
 * else, so a `null` or a scalar is reported by option name instead of as a raw `TypeError`.
 *
 * @layer Config
 */

import { describeReceived } from './describe-received'

/**
 * Requires `value` to be an object.
 *
 * @param label - The option's dotted path.
 * @param value - What the host passed.
 * @throws {Error} Naming the option and the type received, never the content.
 */
export function assertObject(label: string, value: unknown): void {
  if (Object(value) === value) return
  throw new Error(
    `[BymaxAuthModule] ${label} must be an object (received ${describeReceived(value)}).`
  )
}

/**
 * Requires `value` to be an array.
 *
 * @param label - The option's dotted path.
 * @param value - What the host passed.
 * @throws {Error} Naming the option and the type received, never the content.
 */
export function assertArray(label: string, value: unknown): void {
  if (Array.isArray(value)) return
  throw new Error(
    `[BymaxAuthModule] ${label} must be an array (received ${describeReceived(value)}).`
  )
}
