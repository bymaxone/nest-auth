/**
 * @fileoverview The one reader of an integer Redis answers.
 *
 * @layer Redis
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/**
 * Reads an integer reply. A client built with `stringNumbers` answers it as a string.
 *
 * A reply that spells no integer is refused rather than read as `0`: a counter at `0` is under
 * every limit.
 *
 * @param reply - What the command or script answered.
 * @returns The integer.
 * @throws {@link AuthException} `auth.internal` for a reply that spells no integer.
 */
export function integerReply(reply: unknown): number {
  // A string counts only when it is the decimal form of its number, so `''` is not `0`.
  const value = typeof reply === 'string' && `${Number(reply)}` === reply ? Number(reply) : reply
  if (Number.isInteger(value)) return value as number
  throw new AuthException(AUTH_ERROR_CODES.INTERNAL, undefined, {
    cause: new Error('Redis answered a reply that is not an integer')
  })
}
