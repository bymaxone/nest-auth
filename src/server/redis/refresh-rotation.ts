/**
 * @fileoverview What a refresh rotation takes and what it answers.
 *
 * @layer Infrastructure
 */

/** The rotation bundle `AuthRedisService.rotateRefreshSession` consumes. */
export interface RefreshRotationParams {
  /** Which identity plane is rotating; selects the whole prefix set. */
  kind: 'dashboard' | 'platform'
  /** The tenant the rotating session belongs to; part of the index key on the dashboard plane. */
  tenantId: string | undefined
  /** SHA-256 of the presented (old) refresh token. */
  oldHash: string
  /** SHA-256 of the freshly minted refresh token. */
  newHash: string
  /** Serialized session record to store under the new hash. */
  newSessionJson: string
  /** Family of the presented session; `''` when it belongs to no lineage. */
  familyId: string
  /**
   * Owner of the session being rotated, for the per-user session index the script now
   * maintains itself. Taken from the record the caller pre-read, which is what makes it the
   * real owner: the script touches this index only on the live-rotation path, and that path
   * is unreachable unless that pre-read found the session.
   */
  userId: string
  /** Refresh-session lifetime in seconds. */
  refreshTtl: number
  /** Grace-pointer lifetime in seconds; `0` writes no pointer. */
  graceTtl: number
}

/** What `AuthRedisService.rotateRefreshSession` found for the presented token. */
export type RefreshRotationOutcome =
  | { kind: 'rotated'; sessionJson: string }
  | { kind: 'grace'; sessionJson: string }
  | { kind: 'reused'; familyId: string }
  | { kind: 'invalid' }
