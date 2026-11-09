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
})
