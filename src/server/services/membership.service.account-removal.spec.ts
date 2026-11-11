/**
 * @fileoverview Tests for removing every membership of an account that is being deleted: the
 * sole-owner refusal, the removal in every status, the audit and cache bump per removal, and the
 * recovery when a bump fails after the commit.
 *
 * @layer Test
 */

import { build, code, detailsOf } from './__tests__/membership-service-harness'
import { CONTEXT, NOW, workspaceRow } from './__tests__/workspace-service-harness'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { MembershipBumpFailedError } from './membership.service'

const REMOVED = [
  { workspaceId: 'w1', role: 'owner' },
  { workspaceId: 'w2', role: 'editor' }
]

describe('MembershipService.removeAllForUser', () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(NOW)
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('refuses while the account is the only owner of an active workspace, and names it', async () => {
    const { service, memberships } = build()
    memberships['listSoleOwned']?.mockResolvedValue({
      items: [workspaceRow({ id: 'w1', name: 'Acme' })],
      nextCursor: null
    })

    const failure = service.removeAllForUser('t1', 'u9', null, CONTEXT)

    await expect(code(failure)).resolves.toBe(AUTH_ERROR_CODES.LAST_OWNER)
    await expect(detailsOf(service.removeAllForUser('t1', 'u9', null, CONTEXT))).resolves.toEqual({
      workspaces: [{ id: 'w1', name: 'Acme', status: 'active' }]
    })
    expect(memberships['removeAllForUser']).not.toHaveBeenCalled()
  })

  it('does not count a workspace pending deletion, which no one can finalize early', async () => {
    const { service, memberships } = build()
    memberships['listSoleOwned']?.mockResolvedValue({
      items: [
        workspaceRow({ id: 'w1', status: 'active' }),
        workspaceRow({ id: 'w2', status: 'pending_deletion' })
      ],
      nextCursor: null
    })

    await expect(detailsOf(service.removeAllForUser('t1', 'u9', null, CONTEXT))).resolves.toEqual({
      workspaces: [{ id: 'w1', name: 'Acme', status: 'active' }]
    })
  })

  it('follows the sole-owner pages to the end', async () => {
    const { service, memberships } = build()
    memberships['listSoleOwned']
      ?.mockResolvedValueOnce({
        items: [workspaceRow({ id: 'w1', status: 'pending_deletion' })],
        nextCursor: 'c1'
      })
      .mockResolvedValueOnce({ items: [workspaceRow({ id: 'w2' })], nextCursor: null })

    await expect(code(service.removeAllForUser('t1', 'u9', null, CONTEXT))).resolves.toBe(
      AUTH_ERROR_CODES.LAST_OWNER
    )

    expect(memberships['listSoleOwned']).toHaveBeenNthCalledWith(1, {
      tenantId: 't1',
      userId: 'u9',
      ownerRole: 'owner',
      limit: 100
    })
    expect(memberships['listSoleOwned']).toHaveBeenNthCalledWith(2, {
      tenantId: 't1',
      userId: 'u9',
      ownerRole: 'owner',
      cursor: 'c1',
      limit: 100
    })
  })

  it('removes every membership with one audit template, then bumps and reports each', async () => {
    const { service, memberships, access, events } = build()
    memberships['removeAllForUser']?.mockResolvedValue({ result: 'ok', removed: REMOVED })

    const removed = await service.removeAllForUser('t1', 'u9', 'admin-1', CONTEXT)

    expect(removed).toEqual(REMOVED)
    expect(memberships['removeAllForUser']).toHaveBeenCalledWith({
      tenantId: 't1',
      userId: 'u9',
      ownerRole: 'owner',
      audit: {
        type: 'member.removed',
        tenantId: 't1',
        actorUserId: 'admin-1',
        userId: 'u9',
        at: NOW.toISOString()
      }
    })
    expect(access.invalidateMembership).toHaveBeenCalledTimes(2)
    expect(access.invalidateMembership).toHaveBeenCalledWith({
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u9'
    })
    expect(access.invalidateMembership).toHaveBeenCalledWith({
      tenantId: 't1',
      workspaceId: 'w2',
      userId: 'u9'
    })
    expect(events.emit).toHaveBeenCalledTimes(2)
    expect(events.emit).toHaveBeenCalledWith(
      {
        type: 'member.removed',
        tenantId: 't1',
        workspaceId: 'w1',
        actorUserId: 'admin-1',
        userId: 'u9',
        at: NOW.toISOString()
      },
      CONTEXT
    )
  })

  it('answers an account with no membership with nothing removed', async () => {
    const { service, access, events } = build()

    await expect(service.removeAllForUser('t1', 'u9', null, CONTEXT)).resolves.toEqual([])

    expect(access.invalidateMembership).not.toHaveBeenCalled()
    expect(events.emit).not.toHaveBeenCalled()
  })

  it('refuses without removing when the repository finds a sole owner the pre-check missed', async () => {
    const { service, memberships, access, events } = build()
    memberships['removeAllForUser']?.mockResolvedValue({
      result: 'last_owner',
      workspaceIds: ['w7']
    })

    await expect(code(service.removeAllForUser('t1', 'u9', null, CONTEXT))).resolves.toBe(
      AUTH_ERROR_CODES.LAST_OWNER
    )
    await expect(detailsOf(service.removeAllForUser('t1', 'u9', null, CONTEXT))).resolves.toEqual({
      workspaces: [{ id: 'w7' }]
    })

    expect(access.invalidateMembership).not.toHaveBeenCalled()
    expect(events.emit).not.toHaveBeenCalled()
  })

  it('reports the removed list when a bump fails, after trying every bump and sending every event', async () => {
    const { service, memberships, access, events } = build()
    memberships['removeAllForUser']?.mockResolvedValue({ result: 'ok', removed: REMOVED })
    const redis = new Error('redis down')
    access.invalidateMembership.mockRejectedValueOnce(redis).mockResolvedValueOnce(undefined)

    const failure = await service
      .removeAllForUser('t1', 'u9', null, CONTEXT)
      .catch((e: unknown) => e)

    expect(failure).toBeInstanceOf(MembershipBumpFailedError)
    expect((failure as MembershipBumpFailedError).removed).toEqual(REMOVED)
    expect((failure as MembershipBumpFailedError).failed).toEqual([REMOVED[0]])
    expect((failure as MembershipBumpFailedError).cause).toBe(redis)
    expect(access.invalidateMembership).toHaveBeenCalledTimes(2)
    expect(events.emit).toHaveBeenCalledTimes(2)
  })

  it('names the first error when several bumps fail, and lists every membership that failed', async () => {
    const { service, memberships, access } = build()
    memberships['removeAllForUser']?.mockResolvedValue({ result: 'ok', removed: REMOVED })
    const first = new Error('first')
    access.invalidateMembership
      .mockRejectedValueOnce(first)
      .mockRejectedValueOnce(new Error('second'))

    const failure = await service
      .removeAllForUser('t1', 'u9', null, CONTEXT)
      .catch((error: unknown) => error)

    expect((failure as MembershipBumpFailedError).failed).toEqual(REMOVED)
    expect((failure as MembershipBumpFailedError).cause).toBe(first)
  })
})
