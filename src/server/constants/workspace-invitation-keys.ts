/**
 * @fileoverview The Redis keys of workspace invitations, and the subjects the HMAC'd ones are
 * derived from.
 *
 * The preimages are length-prefixed in UTF-8 bytes, like the workspace subjects, and the key shapes
 * are byte-shared with rust-auth through `conformance/wire-contract.json`.
 *
 * @layer Constants
 */

import { workspaceSubject } from './workspace-keys'
import { hmacSha256, sha256 } from '../crypto/secure-token'

/**
 * Prefixes one identifier with its length in UTF-8 bytes, so two different tuples never share a
 * preimage. Bytes, because Rust counts UTF-8 bytes where JavaScript counts UTF-16 units.
 */
function lengthPrefixed(value: string): string {
  return `${Buffer.byteLength(value, 'utf8')}:${value}`
}

/**
 * The subject of one pending invitation: a workspace and the address it invited.
 *
 * The address comes last and carries no prefix, so nothing can follow it and the preimage stays
 * injective.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace.
 * @param email - The invitee, already normalized.
 * @returns `wie:{len(tenant)}:{tenant}:{len(workspace)}:{workspace}:{email}`.
 */
export function invitationEmailSubject(
  tenantId: string,
  workspaceId: string,
  email: string
): string {
  return `wie:${lengthPrefixed(tenantId)}:${lengthPrefixed(workspaceId)}:${email}`
}

/**
 * The subject of one inviter's creation counter inside a tenant.
 *
 * @param tenantId - The tenant the inviter belongs to.
 * @param userId - The inviter; last and unprefixed for the reason `invitationEmailSubject` gives.
 * @returns `wir:{len(tenant)}:{tenant}:{userId}`.
 */
export function inviterRateSubject(tenantId: string, userId: string): string {
  return `wir:${lengthPrefixed(tenantId)}:${userId}`
}

/**
 * The key of an invitation record. The token is a 256-bit random value, so its digest needs no key.
 *
 * @param token - The raw invitation token.
 * @returns The un-namespaced key, `winv:{sha256(token)}`.
 */
export function invitationKey(token: string): string {
  return invitationKeyOfHash(sha256(token))
}

/**
 * The key of an invitation record from the digest of its token.
 *
 * @param tokenHash - `sha256(token)`, lowercase hex.
 * @returns The un-namespaced key, `winv:{tokenHash}`.
 */
export function invitationKeyOfHash(tokenHash: string): string {
  return `winv:${tokenHash}`
}

/**
 * The key naming the live invitation of one address in one workspace. Its value is the record key
 * suffix, so a resend finds the record it replaces.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace.
 * @param email - The invitee, already normalized.
 * @param hmacKey - The library's identifier-HMAC key.
 * @returns The un-namespaced key, `winvidx:{hmac(invitationEmailSubject)}`.
 */
export function invitationIndexKey(
  tenantId: string,
  workspaceId: string,
  email: string,
  hmacKey: string
): string {
  return `winvidx:${hmacSha256(invitationEmailSubject(tenantId, workspaceId, email), hmacKey)}`
}

/**
 * The key of the set holding a workspace's pending invitation records, for listing and for the
 * pending cap. Each member is a full record key, `winv:{hash}`.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace.
 * @param hmacKey - The library's identifier-HMAC key.
 * @returns The un-namespaced key, `winvset:{hmac(workspaceSubject)}`.
 */
export function invitationSetKey(tenantId: string, workspaceId: string, hmacKey: string): string {
  return `winvset:${hmacSha256(workspaceSubject(tenantId, workspaceId), hmacKey)}`
}

/**
 * The key of an inviter's hourly creation counter.
 *
 * @param tenantId - The tenant the inviter belongs to.
 * @param userId - The inviter.
 * @param hmacKey - The library's identifier-HMAC key.
 * @returns The un-namespaced key, `winvrl:{hmac(inviterRateSubject)}`.
 */
export function inviterRateKey(tenantId: string, userId: string, hmacKey: string): string {
  return `winvrl:${hmacSha256(inviterRateSubject(tenantId, userId), hmacKey)}`
}
