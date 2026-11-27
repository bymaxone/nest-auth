/**
 * @fileoverview Unit tests for what a dashboard logout tells the host.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { logoutNotice } from './announce-logout'

const ended = { userId: 'u1', tenantId: 't1', sessionHash: 'h1' }

/** Hooks that record what they are told. */
const recording = () => ({ onSessionsRevoked: jest.fn(), afterLogout: jest.fn() })
const named = { userId: 'u1', plane: 'dashboard', reason: 'logout', sessionIds: ['h1'] }

describe('logoutNotice', () => {
  // Scenario: the delete removed the session and the logout then completes. Expected: one event as
  // soon as the delete answers, and `afterLogout` only on completion.
  it('tells the revocation once, and the logout hook on completion', async () => {
    const hooks = recording()
    const notice = logoutNotice(hooks, new Logger(), ended)

    await notice.after(Promise.resolve(true))
    expect(hooks.onSessionsRevoked.mock.calls).toStrictEqual([[{ ...named, tenantId: 't1' }]])
    expect(hooks.afterLogout).not.toHaveBeenCalled()
    notice.completed()

    expect(hooks.onSessionsRevoked).toHaveBeenCalledTimes(1)
    expect(hooks.afterLogout).toHaveBeenCalledWith(
      'u1',
      expect.objectContaining({ plane: 'dashboard', userId: 'u1', tenantId: 't1' })
    )
  })

  // Scenario: the delete removed nothing. Expected: silent until the logout completes.
  it('waits for completion when the delete removed nothing', async () => {
    const hooks = recording()
    const notice = logoutNotice(hooks, new Logger(), ended)

    await notice.after(Promise.resolve(false))
    expect(hooks.onSessionsRevoked).not.toHaveBeenCalled()
    notice.completed()

    expect(hooks.onSessionsRevoked).toHaveBeenCalledTimes(1)
  })

  // Scenario: the record named no tenant. Expected: neither hook gets the key.
  it('leaves the tenant out when the record named none', () => {
    const hooks = recording()

    logoutNotice(hooks, new Logger(), { ...ended, tenantId: undefined }).completed()

    expect(hooks.onSessionsRevoked.mock.calls).toStrictEqual([[named]])
    expect(Object.keys(hooks.afterLogout.mock.calls[0]?.[1] as object)).not.toContain('tenantId')
  })

  // Scenario: the platform plane. Expected: the event names it and `afterLogout` is not called.
  it('names the platform plane and leaves the dashboard hook alone', () => {
    const hooks = recording()

    logoutNotice(hooks, new Logger(), ended, 'platform').completed()

    expect(hooks.onSessionsRevoked.mock.calls[0]?.[0]).toMatchObject({ plane: 'platform' })
    expect(hooks.afterLogout).not.toHaveBeenCalled()
  })
})
