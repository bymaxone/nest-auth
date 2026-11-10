/**
 * @fileoverview Where workspace invitations live in Redis: the record, the index that names an
 * address's live invitation, and the set a workspace lists its pending ones from.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import {
  invitationIndexKey,
  invitationKeyOfHash,
  invitationSetKey
} from '../constants/workspace-invitation-keys'
import type { StoredWorkspaceInvitation } from '../interfaces/workspace-invitation.interface'
import type { WorkspaceRef } from '../interfaces/workspace-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { isStoredWorkspaceName } from '../utils/workspace-name'

/** A pending invitation with the key it is stored under and the seconds it has left. */
export interface PendingInvitation {
  /** The record key, `winv:{hash}`. */
  key: string
  /** The stored record. */
  record: StoredWorkspaceInvitation
  /** Seconds until the record expires. */
  ttlSeconds: number
}

/**
 * Publishes a record in one step: only while the address's index still holds the key the writer
 * read (`ARGV[5]`, empty meaning none), and, when `ARGV[4]` is not `0`, only while the pending set
 * holds fewer members than that. It writes the record, points the index at it, lists it, and
 * retires the record it replaces (`KEYS[4]`, `ARGV[5]`). A writer that read a stale index, or finds
 * the workspace full, writes nothing, and no state exists in which an index names a record that is
 * not yet written. Returns 1 published, 0 index moved, 2 workspace full.
 */
const PUBLISH_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current == false then current = '' end
if current ~= ARGV[5] then
  return 0
end
if tonumber(ARGV[4]) > 0 and redis.call('SCARD', KEYS[3]) >= tonumber(ARGV[4]) then
  return 2
end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SADD', KEYS[3], ARGV[1])
redis.call('EXPIRE', KEYS[3], ARGV[3])
if ARGV[5] ~= '' then
  redis.call('DEL', KEYS[4])
  redis.call('SREM', KEYS[3], ARGV[5])
end
return 1`

/** Deletes the index only while it still names the given record key. */
const RELEASE_INDEX_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`

/** Reads and writes workspace invitation records; it makes no authorization decision. */
@Injectable()
export class WorkspaceInvitationStore {
  private readonly hmacKey: string

  constructor(
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    this.hmacKey = options.hmacKey
  }

  /**
   * Reads the record under a token's digest.
   *
   * @param tokenHash - `sha256(token)`.
   * @returns The record, or `null` when absent, expired, or not a record this library wrote.
   */
  async readByHash(tokenHash: string): Promise<StoredWorkspaceInvitation | null> {
    return this.readKey(invitationKeyOfHash(tokenHash))
  }

  /**
   * Reads what an address's index names in a workspace.
   *
   * @param ref - The workspace.
   * @param email - The invitee, normalized.
   * @returns `null` when the address has no index; otherwise the record key the index names and its
   *   record, which is `null` when the record has expired or been deleted under a live index.
   */
  async readByEmail(
    ref: WorkspaceRef,
    email: string
  ): Promise<{ key: string; record: StoredWorkspaceInvitation | null } | null> {
    const key = await this.redis.get(this.indexKey(ref, email))
    return key === null ? null : { key, record: await this.readKey(key) }
  }

  /**
   * Writes a record, points the address's index at it and lists it as pending, retiring the record
   * the index named when it was read, all in one step.
   *
   * It writes only while the index still holds `expectedKey`, and, when `limit` is not `0`, only
   * while the workspace holds fewer than `limit` pending invitations.
   *
   * @param ref - The workspace.
   * @param email - The invitee, normalized.
   * @param key - The new record key, `winv:{hash}`.
   * @param record - What to store.
   * @param ttlSeconds - How long the record and the index live; the set lives as long as its
   *   longest member.
   * @param limit - The most pending invitations the workspace may hold, or `0` for no limit.
   * @param expectedKey - The record key the index held when the caller read it, or `null` for no
   *   index. A key whose record is already gone is retired all the same.
   * @returns `published`; `lost` when the index no longer holds `expectedKey`; or `full` when the
   *   workspace holds `limit`. Nothing is written unless `published`.
   */
  async publish(
    ref: WorkspaceRef,
    email: string,
    key: string,
    record: StoredWorkspaceInvitation,
    ttlSeconds: number,
    limit: number,
    expectedKey: string | null
  ): Promise<'published' | 'lost' | 'full'> {
    // Members whose record expired still count in the set, so they are dropped before it is counted.
    if (limit > 0) await this.pending(ref)
    const outcome = await this.redis.eval(
      PUBLISH_SCRIPT,
      [this.indexKey(ref, email), key, this.setKey(ref), expectedKey ?? key],
      [key, JSON.stringify(record), String(ttlSeconds), String(limit), expectedKey ?? '']
    )
    return outcome === 1 ? 'published' : outcome === 2 ? 'full' : 'lost'
  }

  /**
   * Deletes a record, its place in the pending set, and the index when it still names the record.
   *
   * @param ref - The workspace.
   * @param email - The invitee, normalized.
   * @param key - The record key.
   * @returns Whether the index still named this record. `false` means another writer had already
   *   moved or deleted it; the record's own key is gone either way.
   */
  async remove(ref: WorkspaceRef, email: string, key: string): Promise<boolean> {
    await this.redis.del(key)
    await this.redis.srem(this.setKey(ref), key)
    const released = await this.redis.eval(RELEASE_INDEX_SCRIPT, [this.indexKey(ref, email)], [key])
    return released === 1
  }

  /**
   * Lists a workspace's pending invitations, dropping set members whose record is gone.
   *
   * @param ref - The workspace.
   * @returns Each live record with its remaining lifetime.
   */
  async pending(ref: WorkspaceRef): Promise<PendingInvitation[]> {
    const set = this.setKey(ref)
    const live: PendingInvitation[] = []
    const dead: string[] = []
    for (const key of await this.redis.smembers(set)) {
      const record = await this.readKey(key)
      if (record === null) dead.push(key)
      else live.push({ key, record, ttlSeconds: await this.redis.ttl(key) })
    }
    await this.redis.pruneDeadMembers(set, dead)
    return live
  }

  private indexKey(ref: WorkspaceRef, email: string): string {
    return invitationIndexKey(ref.tenantId, ref.workspaceId, email, this.hmacKey)
  }

  private setKey(ref: WorkspaceRef): string {
    return invitationSetKey(ref.tenantId, ref.workspaceId, this.hmacKey)
  }

  private async readKey(key: string): Promise<StoredWorkspaceInvitation | null> {
    const raw = await this.redis.get(key)
    if (raw === null) return null
    try {
      return parseRecord(JSON.parse(raw))
    } catch {
      return null
    }
  }
}

/**
 * Narrows parsed JSON to a record, so a foreign value under the key reads as absent. A non-object
 * has none of the fields, and `null` throws at the destructuring: both are treated as absent, the
 * throw through `readKey`'s catch. Do not add a `typeof` or `null` branch here; it changes no answer.
 *
 * The two kinds are exclusive: a member record has an inviter and no workspace name, a bootstrap
 * record has a workspace name and no inviter, and any other combination is not a record.
 */
function parseRecord(value: unknown): StoredWorkspaceInvitation | null {
  const fields = value as Record<string, unknown>
  const { kind, email, role, tenantId, workspaceId, createdAt, resendCount } = fields
  const { inviterUserId, workspaceName } = fields
  if (
    typeof email !== 'string' ||
    typeof role !== 'string' ||
    typeof tenantId !== 'string' ||
    typeof workspaceId !== 'string' ||
    typeof createdAt !== 'string' ||
    typeof resendCount !== 'number'
  ) {
    return null
  }
  const base = { email, role, tenantId, workspaceId, createdAt, resendCount }
  if (kind === 'member' && typeof inviterUserId === 'string' && workspaceName === undefined) {
    return { kind, ...base, inviterUserId }
  }
  if (kind === 'bootstrap' && inviterUserId === undefined && isStoredWorkspaceName(workspaceName)) {
    return { kind, ...base, workspaceName }
  }
  return null
}
