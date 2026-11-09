/**
 * @fileoverview The Redis keys of the workspace-membership cache, and the subjects they are
 * derived from.
 *
 * Both subjects are length-prefixed in UTF-8 bytes and every key HMACs its subject with the
 * identifier key, for the reasons `userSubject` states. The preimages and the key shapes are
 * byte-shared with rust-auth through `conformance/wire-contract.json`.
 *
 * @layer Constants
 */

import { TOKEN_EPOCH_RETENTION_SECONDS } from './token-epoch'
import { hmacSha256 } from '../crypto/secure-token'

/**
 * How long a workspace or membership version counter stays readable, in seconds (30 days).
 *
 * A counter must outlive every cache entry written under it: a counter that expires while an
 * entry keyed by its old value is still alive would restart at `0` and make that stale entry
 * current again. The longest entry lives `WORKSPACE_MEMBERSHIP_CACHE_MAX_TTL_SECONDS`, an hour, so
 * the epoch retention is far above it, and sharing the value keeps one retention rule for every
 * counter in the keyspace.
 */
export const WORKSPACE_VERSION_RETENTION_SECONDS = TOKEN_EPOCH_RETENTION_SECONDS

/**
 * Prefixes one identifier with its length in UTF-8 bytes.
 *
 * Bytes, not `String.length`: JavaScript counts UTF-16 code units and Rust counts UTF-8 bytes, so
 * only the byte count derives the same key on both backends for a non-ASCII identifier.
 *
 * @param value - The identifier.
 * @returns `{byteLength}:{value}`.
 */
function lengthPrefixed(value: string): string {
  return `${Buffer.byteLength(value, 'utf8')}:${value}`
}

/**
 * The subject of a workspace: the preimage the workspace version counter is keyed on.
 *
 * A workspace id is unique only inside its tenant, and the length prefix keeps the pair
 * injective over the identifiers this library accepts.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace, unique within the tenant.
 * @returns `wsp:{len(tenant)}:{tenant}:{len(workspace)}:{workspace}`.
 */
export function workspaceSubject(tenantId: string, workspaceId: string): string {
  return `wsp:${lengthPrefixed(tenantId)}:${lengthPrefixed(workspaceId)}`
}

/**
 * The subject of one membership: the preimage the membership version counter and the cache entry
 * are keyed on.
 *
 * The user id comes last and carries no prefix, so nothing can follow it and the preimage stays
 * injective.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace.
 * @param userId - The member.
 * @returns `wms:{len(tenant)}:{tenant}:{len(workspace)}:{workspace}:{userId}`.
 */
export function membershipSubject(tenantId: string, workspaceId: string, userId: string): string {
  return `wms:${lengthPrefixed(tenantId)}:${lengthPrefixed(workspaceId)}:${userId}`
}

/**
 * The Redis key of a workspace's version counter, bumped when the whole workspace changes state.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace.
 * @param hmacKey - The library's identifier-HMAC key.
 * @returns The un-namespaced key, `wsv:{hmac(workspaceSubject)}`.
 */
export function workspaceVersionKey(
  tenantId: string,
  workspaceId: string,
  hmacKey: string
): string {
  return `wsv:${hmacSha256(workspaceSubject(tenantId, workspaceId), hmacKey)}`
}

/**
 * The Redis key of one membership's version counter, bumped when that membership changes.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace.
 * @param userId - The member.
 * @param hmacKey - The library's identifier-HMAC key.
 * @returns The un-namespaced key, `wmv:{hmac(membershipSubject)}`.
 */
export function membershipVersionKey(
  tenantId: string,
  workspaceId: string,
  userId: string,
  hmacKey: string
): string {
  return `wmv:${hmacSha256(membershipSubject(tenantId, workspaceId, userId), hmacKey)}`
}

/**
 * The part of a membership cache key before the two versions.
 *
 * The full key is `{base}:{workspaceVersion}:{membershipVersion}`: the versions read BEFORE the
 * repository are part of the name, so an entry written after a concurrent change lands under a key
 * nobody reads.
 *
 * @param tenantId - The tenant the workspace lives in.
 * @param workspaceId - The workspace.
 * @param userId - The member.
 * @param hmacKey - The library's identifier-HMAC key.
 * @returns The un-namespaced key base, `wm:{hmac(membershipSubject)}`.
 */
export function membershipCacheKeyBase(
  tenantId: string,
  workspaceId: string,
  userId: string,
  hmacKey: string
): string {
  return `wm:${hmacSha256(membershipSubject(tenantId, workspaceId, userId), hmacKey)}`
}
