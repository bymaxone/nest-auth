/**
 * @fileoverview Tests for the wire shapes of the workspace read routes.
 *
 * @layer Test
 */

import type {
  AuthMembership,
  MembershipWithWorkspace
} from '../interfaces/membership-repository.interface'
import type { AuthWorkspace } from '../interfaces/workspace-repository.interface'
import {
  toAccessResponse,
  toMembersResponse,
  toMyWorkspacesResponse,
  toWorkspaceView
} from './workspace-views'

const WORKSPACE: AuthWorkspace = {
  id: 'w1',
  tenantId: 't1',
  name: 'Acme',
  status: 'active',
  createdAt: new Date('2026-01-02T03:04:05.000Z'),
  deletionScheduledAt: null
}

const MEMBER: AuthMembership = {
  tenantId: 't1',
  workspaceId: 'w1',
  userId: 'u1',
  role: 'editor',
  status: 'active',
  invitedByUserId: 'u0',
  createdAt: new Date('2026-02-03T04:05:06.000Z'),
  updatedAt: new Date('2026-03-04T05:06:07.000Z')
}

describe('toWorkspaceView', () => {
  it('answers the fields a caller needs, with dates as ISO strings, and not the tenant', () => {
    expect(toWorkspaceView(WORKSPACE)).toEqual({
      id: 'w1',
      name: 'Acme',
      status: 'active',
      createdAt: '2026-01-02T03:04:05.000Z',
      deletionScheduledAt: null
    })
  })

  it('answers a scheduled deletion as an ISO string', () => {
    const view = toWorkspaceView({
      ...WORKSPACE,
      status: 'pending_deletion',
      deletionScheduledAt: new Date('2026-05-06T07:08:09.000Z')
    })

    expect(view).toMatchObject({
      status: 'pending_deletion',
      deletionScheduledAt: '2026-05-06T07:08:09.000Z'
    })
  })
})

describe('toAccessResponse', () => {
  it('pairs the workspace with the role', () => {
    expect(toAccessResponse({ workspace: WORKSPACE, role: 'owner' })).toEqual({
      workspace: toWorkspaceView(WORKSPACE),
      role: 'owner'
    })
  })
})

describe('toMyWorkspacesResponse', () => {
  it('lists each membership as its workspace and role, with the cursor and last active id', () => {
    const item: MembershipWithWorkspace = { ...MEMBER, workspace: WORKSPACE }

    expect(
      toMyWorkspacesResponse({ items: [item], nextCursor: 'c1', lastActiveWorkspaceId: 'w9' })
    ).toEqual({
      items: [{ workspace: toWorkspaceView(WORKSPACE), role: 'editor' }],
      nextCursor: 'c1',
      lastActiveWorkspaceId: 'w9'
    })
  })

  it('keeps a null cursor and a null last active id', () => {
    expect(
      toMyWorkspacesResponse({ items: [], nextCursor: null, lastActiveWorkspaceId: null })
    ).toEqual({
      items: [],
      nextCursor: null,
      lastActiveWorkspaceId: null
    })
  })
})

describe('toMembersResponse', () => {
  it('answers each member without the tenant, the workspace or the update instant', () => {
    expect(toMembersResponse({ items: [MEMBER], nextCursor: 'c2' })).toEqual({
      items: [
        {
          userId: 'u1',
          role: 'editor',
          status: 'active',
          invitedByUserId: 'u0',
          createdAt: '2026-02-03T04:05:06.000Z'
        }
      ],
      nextCursor: 'c2'
    })
  })

  it('keeps a null cursor and a null inviter', () => {
    expect(
      toMembersResponse({ items: [{ ...MEMBER, invitedByUserId: null }], nextCursor: null })
    ).toMatchObject({ items: [{ invitedByUserId: null }], nextCursor: null })
  })
})
