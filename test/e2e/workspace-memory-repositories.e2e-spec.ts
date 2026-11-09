/**
 * @fileoverview Pins the in-memory repositories the workspace e2e suites rely on.
 *
 * @layer Test
 */

import { membershipKey, memoryRepositories } from './workspace-memory-repositories'

describe('workspace memory repositories', () => {
  it('keeps two memberships apart when their identifiers share the delimiter character', async () => {
    // Arrange: ('a/b', 'c') and ('a', 'b/c') would collide under a '/'-joined key
    const { memberships, seedMember } = memoryRepositories()
    seedMember('a/b', 'c', 'admin')
    seedMember('a', 'b/c', 'member')

    // Act
    const first = await memberships.find({ tenantId: 't1', workspaceId: 'a/b', userId: 'c' })
    const second = await memberships.find({ tenantId: 't1', workspaceId: 'a', userId: 'b/c' })

    // Assert
    expect(first?.role).toBe('admin')
    expect(second?.role).toBe('member')
    expect(membershipKey('a/b', 'c')).not.toBe(membershipKey('a', 'b/c'))
  })

  it('refuses a status change whose expected deletion deadline is no longer the stored one', async () => {
    // Arrange: a workspace scheduled for deletion at one instant
    const { workspaces } = memoryRepositories()
    const ref = { tenantId: 't1', workspaceId: 'w1' }
    await workspaces.createWithOwner({
      ...ref,
      name: 'Acme',
      ownerUserId: 'u1',
      ownerRole: 'owner',
      audit: { type: 'workspace.created', ...ref, actorUserId: 'u1', at: new Date(0).toISOString() }
    } as never)
    const scheduled = new Date(1_000)
    const audit = { type: 'workspace.deleted', ...ref, actorUserId: null, at: '' } as never
    await workspaces.updateStatus({
      ...ref,
      status: 'pending_deletion',
      expectedStatus: 'active',
      deletionScheduledAt: scheduled,
      audit
    })

    // Act: a finalizer that read an earlier schedule, then one that read the current one
    const stale = await workspaces.updateStatus({
      ...ref,
      status: 'deleted',
      expectedStatus: 'pending_deletion',
      expectedDeletionScheduledAt: new Date(500),
      deletionScheduledAt: null,
      audit
    })
    const current = await workspaces.updateStatus({
      ...ref,
      status: 'deleted',
      expectedStatus: 'pending_deletion',
      expectedDeletionScheduledAt: new Date(1_000),
      deletionScheduledAt: null,
      audit
    })

    // Assert
    expect(stale).toBe('status_conflict')
    expect(current).toBe('ok')
  })
})
