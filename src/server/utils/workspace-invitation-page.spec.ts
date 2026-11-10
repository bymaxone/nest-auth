/**
 * @fileoverview Tests for ordering and paging a workspace's pending invitations.
 *
 * @layer Test
 */

import { pageInvitations } from './workspace-invitation-page'
import type { PendingInvitation } from '../services/workspace-invitation.store'

const NOW = Date.parse('2026-01-10T12:00:00.000Z')

function pending(
  email: string,
  createdAt: string,
  key = `winv:${email}`,
  ttlSeconds = 100
): PendingInvitation {
  return {
    key,
    ttlSeconds,
    record: {
      kind: 'member',
      email,
      role: 'viewer',
      tenantId: 't1',
      workspaceId: 'w1',
      inviterUserId: 'u1',
      createdAt,
      resendCount: 2
    }
  }
}

const A = pending('a@x.io', '2026-01-01T00:00:00.000Z')
const B = pending('b@x.io', '2026-01-02T00:00:00.000Z')
const C = pending('c@x.io', '2026-01-03T00:00:00.000Z')

function emails(page: ReturnType<typeof pageInvitations>): string[] {
  return page.items.map((item) => item.email)
}

describe('pageInvitations', () => {
  it('orders by issue time whatever order the set returned them in', () => {
    expect(emails(pageInvitations([C, A, B], {}, NOW))).toEqual(['a@x.io', 'b@x.io', 'c@x.io'])
  })

  it('breaks a tie on the record key', () => {
    const x = pending('x@x.io', A.record.createdAt, 'winv:2')
    const y = pending('y@x.io', A.record.createdAt, 'winv:1')

    expect(emails(pageInvitations([x, y], {}, NOW))).toEqual(['y@x.io', 'x@x.io'])
  })

  it('shapes each item with its expiry measured from now, and never exposes the key', () => {
    const [item] = pageInvitations([A], {}, NOW).items

    expect(item).toEqual({
      email: 'a@x.io',
      role: 'viewer',
      inviterUserId: 'u1',
      createdAt: '2026-01-01T00:00:00.000Z',
      expiresAt: new Date(NOW + 100_000).toISOString(),
      resendCount: 2
    })
  })

  it('reports an invitation that has no time left as expiring now', () => {
    const [item] = pageInvitations(
      [pending('a@x.io', A.record.createdAt, 'winv:a', -2)],
      {},
      NOW
    ).items

    expect(item?.expiresAt).toBe(new Date(NOW).toISOString())
  })

  it('pages with a cursor that is the position of the last item', () => {
    const first = pageInvitations([A, B, C], { limit: 2 }, NOW)
    const second = pageInvitations([A, B, C], { limit: 2, cursor: first.nextCursor ?? '' }, NOW)

    expect(emails(first)).toEqual(['a@x.io', 'b@x.io'])
    expect(first.nextCursor).toBe(`${B.record.createdAt}|${B.key}`)
    expect(emails(second)).toEqual(['c@x.io'])
    expect(second.nextCursor).toBeNull()
  })

  it('points the cursor at the last item of a page longer than two', () => {
    const D = pending('d@x.io', '2026-01-04T00:00:00.000Z')
    const E = pending('e@x.io', '2026-01-05T00:00:00.000Z')

    const page = pageInvitations([A, B, C, D, E], { limit: 3 }, NOW)

    expect(page.nextCursor).toBe(`${C.record.createdAt}|${C.key}`)
  })

  it('has no next page when the page ends exactly at the last item', () => {
    expect(pageInvitations([A, B], { limit: 2 }, NOW).nextCursor).toBeNull()
  })

  it('answers an empty page for an empty workspace', () => {
    expect(pageInvitations([], {}, NOW)).toEqual({ items: [], nextCursor: null })
  })

  it('defaults to 50, and bounds a requested size to 1..100', () => {
    const many = Array.from({ length: 120 }, (_, i) =>
      pending(`u${String(i).padStart(3, '0')}@x.io`, new Date(NOW + i * 1_000).toISOString())
    )

    expect(pageInvitations(many, {}, NOW).items).toHaveLength(50)
    expect(pageInvitations(many, { limit: 1_000 }, NOW).items).toHaveLength(100)
    expect(pageInvitations(many, { limit: 0 }, NOW).items).toHaveLength(1)
    expect(pageInvitations(many, { limit: -5 }, NOW).items).toHaveLength(1)
  })

  it('lists only member invitations', () => {
    const boot: PendingInvitation = {
      key: 'winv:boot',
      ttlSeconds: 10,
      record: {
        kind: 'bootstrap',
        email: 'o@x.io',
        role: 'owner',
        tenantId: 't1',
        workspaceId: 'w1',
        createdAt: A.record.createdAt,
        resendCount: 0,
        workspaceName: 'Acme'
      }
    }

    expect(emails(pageInvitations([boot, A], {}, NOW))).toEqual(['a@x.io'])
  })
})
