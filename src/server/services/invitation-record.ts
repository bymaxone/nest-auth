/**
 * @fileoverview The record of a pending tenant invitation, and the guard that reads it back.
 *
 * @layer Service
 */

/**
 * Stored payload for a pending invitation, kept in Redis.
 * The raw token is never stored — only its SHA-256 hash is used as the key.
 */
export interface StoredInvitation {
  /** Normalized (lowercased, trimmed) email address of the invitee. */
  email: string
  /** Role to assign upon acceptance. */
  role: string
  /** Tenant the invitee will join. */
  tenantId: string
  /** Internal ID of the user who sent the invitation. */
  inviterUserId: string
  /** ISO timestamp of when the invitation was created. */
  createdAt: string
}

/**
 * Narrows an unknown value to `StoredInvitation` at runtime.
 *
 * Used after `JSON.parse` to prevent injection of unexpected field values
 * (e.g. a tampered `role`) from a compromised or misconfigured Redis instance.
 */
export function isStoredInvitation(value: unknown): value is StoredInvitation {
  // Stryker disable next-line ConditionalExpression: non-object JSON primitives have no string fields, so the downstream field guards reject them identically when the type clause is dropped
  if (typeof value !== 'object' || value === null) return false
  const v = value as Record<string, unknown>
  return (
    typeof v['email'] === 'string' &&
    // Stryker disable next-line ConditionalExpression: equivalent — a non-string role is refused downstream by `Object.hasOwn(hierarchy, role)` and by `hasRole`, which compares by identity, so no non-string value can reach an account. Kept as the contract this guard states.
    typeof v['role'] === 'string' &&
    // Stryker disable next-line ConditionalExpression: equivalent — a non-string tenantId is refused downstream by `inviter.tenantId === invitation.tenantId`, a strict comparison against a string that no non-string can satisfy. Kept for the same reason as the role clause.
    typeof v['tenantId'] === 'string' &&
    typeof v['inviterUserId'] === 'string' &&
    typeof v['createdAt'] === 'string'
  )
}
