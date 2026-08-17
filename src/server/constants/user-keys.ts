/**
 * The two Redis keys that name an ACCOUNT rather than a token: the session index and the token
 * epoch.
 *
 * Both are derived the same way as every other user-derived key in this library — an HMAC over
 * the tenant-scoped {@link userSubject} — and for the same two reasons.
 *
 * **The tenant, because a repository id is only unique within one.** `IUserRepository.findById`
 * takes a `tenantId` precisely because ids may not be globally unique, and a host that numbers
 * users per tenant gives every tenant a user `1`. Keyed on the bare id, deleting or suspending
 * `t1/u1` swept the sessions and bumped the token epoch of `t2/u1` — a credential-free
 * cross-tenant revocation, reachable by anyone who can get an account suspended in their own
 * tenant. The same argument the wire contract already makes for the MFA subject, one key family
 * over.
 *
 * **The HMAC, because the keyspace is shared and readable.** rust-auth reads and writes these
 * keys, so anyone with store access sees them, and a bare id there is an account identifier in
 * the clear. A user id carries too little entropy for a plain digest to hide it, which is the
 * reason the identifier preimages are HMACed and not merely hashed.
 *
 * @layer Constants
 */
import { userSubject } from './user-subject'
import { hmacSha256 } from '../crypto/secure-token'

/**
 * The Redis key holding the set of live sessions for one account on one plane.
 *
 * @param plane - The identity plane the account belongs to.
 * @param userId - The account whose sessions the index tracks.
 * @param hmacKey - The library's identifier-HMAC key.
 * @param tenantId - The tenant the dashboard account belongs to; ignored on the platform plane.
 * @returns The un-namespaced Redis key.
 */
export function sessionIndexKey(
  plane: 'dashboard' | 'platform',
  userId: string,
  hmacKey: string,
  tenantId: string | undefined
): string {
  const prefix = plane === 'platform' ? 'psess' : 'sess'
  return `${prefix}:${hmacSha256(userSubject(plane, userId, tenantId), hmacKey)}`
}

/**
 * The Redis key holding the token-epoch generation counter for one account on one plane.
 *
 * @param plane - The identity plane the account belongs to.
 * @param userId - The account whose epoch the counter tracks.
 * @param hmacKey - The library's identifier-HMAC key.
 * @param tenantId - The tenant the dashboard account belongs to; ignored on the platform plane.
 * @returns The un-namespaced Redis key.
 */
export function tokenEpochKey(
  plane: 'dashboard' | 'platform',
  userId: string,
  hmacKey: string,
  tenantId: string | undefined
): string {
  const prefix = plane === 'platform' ? 'pep' : 'ep'
  return `${prefix}:${hmacSha256(userSubject(plane, userId, tenantId), hmacKey)}`
}
