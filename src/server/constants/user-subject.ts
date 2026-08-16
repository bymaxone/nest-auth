/**
 * The subject every user-derived Redis key is HMACed over.
 *
 * One definition rather than a copy per key family, and a copy that drifts is a key that silently
 * stops matching the one rust-auth derives from the same contract. It started as the MFA subject
 * and now backs every key that names an account: the five MFA store keys, the three MFA failure
 * counters, the recent-authentication marker, the session index and the token epoch.
 *
 * @layer Constants
 */

/**
 * Builds the tenant-scoped subject for a user-derived Redis key.
 *
 * The tenant is part of the dashboard arm because the library may not assume the consumer's user
 * ids are unique ACROSS tenants — `findById` takes a tenant precisely because they may not be, and
 * a host that numbers users per tenant gives every tenant a user `1`. Keyed on `{plane}:{userId}`
 * alone, two tenants' accounts shared every MFA store key and every MFA failure counter; the
 * counters were the worst, costing a credential-free cross-tenant lockout rather than a mere
 * collision.
 *
 * The derivation is driven by the **plane**, not by whether a tenant was supplied: the platform
 * arm carries no tenant segment because its admins are cross-tenant and have none, so a caller that
 * passes one on the platform plane cannot move the preimage off `platform:{userId}` — the shape is
 * half of a byte-for-byte agreement with rust-auth. A dashboard call is guaranteed a tenant by
 * `assertPlaneTenant`, which refuses the plane/tenant mismatch before any key is derived.
 *
 * @param plane - The identity plane the subject belongs to.
 * @param userId - The account the key belongs to.
 * @param tenantId - The tenant the dashboard account belongs to; ignored on the platform plane.
 * @returns The subject string the MFA key HMACs are keyed over.
 */
export function userSubject(
  plane: 'dashboard' | 'platform',
  userId: string,
  tenantId: string | undefined
): string {
  return plane === 'platform' ? `platform:${userId}` : `dashboard:${tenantId}:${userId}`
}
