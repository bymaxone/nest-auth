/**
 * @fileoverview The one reader of an integer Redis answers.
 *
 * @layer Redis
 */

/**
 * Reads an integer reply. A client built with `stringNumbers` answers it as a string.
 *
 * @param reply - What the command or script answered.
 * @returns The integer, or `0` for a reply that spells none.
 */
export function integerReply(reply: unknown): number {
  const value = typeof reply === 'string' ? Number(reply) : reply
  return Number.isInteger(value) ? (value as number) : 0
}
