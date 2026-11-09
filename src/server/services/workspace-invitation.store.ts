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
 * Sets the index to a new record key only while it still holds the key the caller read (an empty
 * `ARGV[1]` meaning absent), so two writers for one address cannot both succeed.
 */
const CLAIM_INDEX_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if (current == false and ARGV[1] == '') or current == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
  return 1
end
return 0`

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
   * Makes an address's index name a new record, but only while it still names `expectedKey`.
   *
   * @param ref - The workspace.
   * @param email - The invitee, normalized.
   * @param expectedKey - The record key the caller read, or `null` for none.
   * @param newKey - The record key to name.
   * @param ttlSeconds - How long the index lives.
   * @returns `false` when another writer moved the index first.
   */
  async claimIndex(
    ref: WorkspaceRef,
    email: string,
    expectedKey: string | null,
    newKey: string,
    ttlSeconds: number
  ): Promise<boolean> {
    const claimed = await this.redis.eval(
      CLAIM_INDEX_SCRIPT,
      [this.indexKey(ref, email)],
      [expectedKey ?? '', newKey, String(ttlSeconds)]
    )
    return claimed === 1
  }

  /**
   * Writes a record and lists it as pending for its workspace.
   *
   * @param ref - The workspace.
   * @param key - The record key, `winv:{hash}`.
   * @param record - What to store.
   * @param ttlSeconds - How long it lives; the set lives as long as its longest member.
   */
  async write(
    ref: WorkspaceRef,
    key: string,
    record: StoredWorkspaceInvitation,
    ttlSeconds: number
  ): Promise<void> {
    await this.redis.set(key, JSON.stringify(record), ttlSeconds)
    const set = this.setKey(ref)
    await this.redis.sadd(set, key)
    await this.redis.expire(set, ttlSeconds)
  }

  /**
   * Deletes a record, its place in the pending set, and the index when it still names the record.
   *
   * @param ref - The workspace.
   * @param email - The invitee, normalized.
   * @param key - The record key.
   */
  async remove(ref: WorkspaceRef, email: string, key: string): Promise<void> {
    await this.redis.del(key)
    await this.redis.srem(this.setKey(ref), key)
    await this.redis.eval(RELEASE_INDEX_SCRIPT, [this.indexKey(ref, email)], [key])
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
 */
function parseRecord(value: unknown): StoredWorkspaceInvitation | null {
  const { email, role, tenantId, workspaceId, inviterUserId, createdAt, resendCount } =
    value as Record<string, unknown>
  if (
    typeof email !== 'string' ||
    typeof role !== 'string' ||
    typeof tenantId !== 'string' ||
    typeof workspaceId !== 'string' ||
    typeof inviterUserId !== 'string' ||
    typeof createdAt !== 'string' ||
    typeof resendCount !== 'number'
  ) {
    return null
  }
  return { email, role, tenantId, workspaceId, inviterUserId, createdAt, resendCount }
}
