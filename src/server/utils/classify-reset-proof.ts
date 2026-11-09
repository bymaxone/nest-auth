/**
 * @fileoverview Which proof a password reset presented, decided without spending it.
 *
 * @layer Util
 */

import type { ResetPasswordDto } from '../dto/reset-password.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

/** The proof a reset presented, and the value it carries. */
export interface ResetProof {
  kind: 'token' | 'verifiedToken' | 'otp'
  value: string
}

/**
 * Settles, from the request and the configured method alone, which proof the reset presents.
 *
 * Nothing is looked up or consumed here: a request with more than one proof, with none, or with
 * one the configured method does not accept is refused as an invalid token before anything else
 * about it is judged. That ordering is the point. A caller who holds no usable proof never reaches
 * the password policy, whose breach screen may be an outbound query, and the answer for such a
 * request does not depend on the password it carries.
 *
 * @param method - The deployment's `passwordReset.method`.
 * @param dto - The reset request.
 * @returns The one proof the method accepts.
 * @throws {AuthException} `PASSWORD_RESET_TOKEN_INVALID` for more than one proof, none, or one the
 *   method does not accept.
 */
export function classifyResetProof(
  method: 'token' | 'otp',
  dto: Pick<ResetPasswordDto, 'token' | 'otp' | 'verifiedToken'>
): ResetProof {
  const presented = (
    [
      ['token', dto.token],
      ['verifiedToken', dto.verifiedToken],
      ['otp', dto.otp]
    ] as const
  ).filter((entry): entry is readonly [ResetProof['kind'], string] => typeof entry[1] === 'string')
  const [only] = presented
  if (presented.length !== 1 || only === undefined || only[1] === '') throw invalidProof()
  const accepted = method === 'token' ? only[0] === 'token' : only[0] !== 'token'
  if (!accepted) throw invalidProof()
  return { kind: only[0], value: only[1] }
}

/** The one answer for a proof that is absent, ambiguous or not accepted by the method. */
function invalidProof(): AuthException {
  return new AuthException(AUTH_ERROR_CODES.PASSWORD_RESET_TOKEN_INVALID)
}
