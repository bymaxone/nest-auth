/**
 * @fileoverview Orders and pages a workspace's pending invitations.
 *
 * @layer Utility
 */

import type {
  MemberInvitationRecord,
  WorkspaceInvitationView
} from '../interfaces/workspace-invitation.interface'
import type { PendingInvitation } from '../services/workspace-invitation.store'

/** Page size when the caller names none. */
const DEFAULT_LIMIT = 50

/** The largest page a caller may ask for. */
const MAX_LIMIT = 100

/** One page of invitations and where the next one starts. */
export interface InvitationPage {
  /** The invitations of this page, oldest first. */
  items: WorkspaceInvitationView[]
  /** Pass it back as the cursor for the next page; `null` on the last one. */
  nextCursor: string | null
}

/** A pending invitation that a workspace member issued; only those are listed. */
type PendingMemberInvitation = PendingInvitation & { record: MemberInvitationRecord }

/** Whether a pending invitation is a member invitation. */
function isMemberInvitation(pending: PendingInvitation): pending is PendingMemberInvitation {
  return pending.record.kind === 'member'
}

/** The position of an invitation in the order: when it was issued, then its record key. */
function positionOf(pending: PendingInvitation): string {
  return `${pending.record.createdAt}|${pending.key}`
}

/**
 * Turns the pending invitations into one page, ordered by issue time and then record key so the
 * order is total.
 *
 * @param pending - Every pending invitation of the workspace.
 * @param page - The cursor, a position previously returned, and the size asked for.
 * @param now - The instant the remaining lifetimes are measured from.
 * @returns The page.
 */
export function pageInvitations(
  pending: PendingInvitation[],
  page: { cursor?: string; limit?: number },
  now: number
): InvitationPage {
  const limit = Math.min(Math.max(page.limit ?? DEFAULT_LIMIT, 1), MAX_LIMIT)
  const ordered = pending
    .filter(isMemberInvitation)
    .sort((a, b) => positionOf(a).localeCompare(positionOf(b)))
  const { cursor } = page
  const after = cursor === undefined ? ordered : ordered.filter((p) => positionOf(p) > cursor)
  const slice = after.slice(0, limit)
  const last = slice.at(-1)
  return {
    items: slice.map((p) => ({
      email: p.record.email,
      role: p.record.role,
      inviterUserId: p.record.inviterUserId,
      createdAt: p.record.createdAt,
      expiresAt: new Date(now + Math.max(p.ttlSeconds, 0) * 1_000).toISOString(),
      resendCount: p.record.resendCount
    })),
    nextCursor: after.length > limit && last !== undefined ? positionOf(last) : null
  }
}
