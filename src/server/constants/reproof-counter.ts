/**
 * @fileoverview The failure counter a password re-proof is counted under.
 *
 * @layer Constant
 */

import { userSubject } from './user-subject'
import { hmacSha256 } from '../crypto/secure-token'

/** The flows that ask for the current password again and count their failures. */
export type ReproofFlow = 'change-password' | 'email-change'

/**
 * The brute-force identifier of one account's re-proof flow: `hmac_sha256(hmacKey,
 * 'reauth:{flow}:{userSubject}')`. The subject carries the tenant, so two tenants' user `1` count
 * under different identifiers and neither can lock the other out of the flow. The shared keyspace
 * contract pins the derivation for both libraries (`userSubjectDerivedKeys` and
 * `reproofCounterVectors`).
 *
 * @param flow - The flow, which keeps its counter apart from the others and from `login`.
 * @param userId - The account.
 * @param tenantId - The tenant the dashboard account belongs to.
 * @param hmacKey - The identifier-hashing key.
 * @returns The identifier to hand to the brute-force counter.
 */
export function reproofCounterId(
  flow: ReproofFlow,
  userId: string,
  tenantId: string,
  hmacKey: string
): string {
  return hmacSha256(`reauth:${flow}:${userSubject('dashboard', userId, tenantId)}`, hmacKey)
}
