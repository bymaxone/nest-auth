/**
 * @fileoverview JWT verification across a secret rotation.
 *
 * @layer Utility
 */

import type { JwtService } from '@nestjs/jwt'

import type { ResolvedOptions } from '../config/resolved-options'

/**
 * Verify a token against the current signing secret, then against any retired by a rotation.
 *
 * Rotating `jwt.secret` with nothing else in place invalidates every token in flight at once —
 * every signed-in user is signed out the moment the new configuration rolls out. Listing the
 * old secret under `jwt.previousSecrets` lets tokens issued under it keep verifying while they
 * drain, so a rotation becomes a rollout instead of a mass logout.
 *
 * The current secret is always tried first, so the common path costs exactly what it did
 * before. Retired secrets verify only — nothing is ever signed under one, which is what makes
 * the rotation one-way.
 *
 * Every failure is the same failure: the function throws whatever the last attempt threw, and
 * callers map it to one opaque error. Reporting *which* secret failed would tell an attacker
 * whether a token was forged under a key the deployment used to hold.
 *
 * @typeParam T - The expected payload shape.
 * @param jwtService - The Nest JWT service, configured with the current secret.
 * @param options - Resolved module options, for the algorithm and the retired secrets.
 * @param token - The compact JWT to verify.
 * @param options.ignoreExpiration - Accept a token whose `exp` has passed, while still
 *   requiring a valid signature under the pinned algorithm. Exactly one caller wants this:
 *   logout, which must work for a session whose access token expired while the user was away
 *   — the point of logging out is to kill the long-lived refresh credential, and refusing the
 *   request leaves it alive for its full lifetime. Reading such a token unverified instead
 *   would be worse: `jti` would be attacker-chosen, so a caller could blacklist someone
 *   else's access token by naming its id.
 * @returns The verified payload.
 * @throws Whatever `JwtService.verify` throws when no secret accepts the token.
 */
export function verifyWithRotation<T extends object>(
  jwtService: JwtService,
  options: ResolvedOptions,
  token: string,
  { ignoreExpiration = false }: { ignoreExpiration?: boolean } = {}
): T {
  const algorithms = [options.jwt.algorithm]
  // `issuer`/`audience` are REQUIREMENTS here, not hints: `jsonwebtoken` rejects a token whose
  // claim differs — and one that carries none at all. That is the point. A verifier that
  // accepted an unstamped token would give an attacker a way to opt out of the check simply by
  // omitting the claim.
  const { issuer, audience } = options.jwt
  const base = {
    algorithms,
    ignoreExpiration,
    ...(issuer !== undefined && issuer !== '' ? { issuer } : {}),
    ...(audience !== undefined && audience !== '' ? { audience } : {})
  }

  try {
    return jwtService.verify<T>(token, base)
  } catch (currentFailure: unknown) {
    const previous = options.jwt.previousSecrets ?? []
    for (const secret of previous) {
      try {
        return jwtService.verify<T>(token, { ...base, secret })
      } catch {
        // Try the next retired secret. A token nobody accepts falls out of the loop and the
        // original failure is rethrown, so the caller sees the same error it always did.
      }
    }
    throw currentFailure
  }
}
