/**
 * @fileoverview Unit tests for what a completed dashboard logout tells the host.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { announceLogout } from './announce-logout'

const ended = { userId: 'u1', tenantId: 't1', sessionHash: 'h1' }

describe('announceLogout', () => {
  // Scenario: a logout with a tenant. Expected: both hooks are told, the event naming the session.
  it('tells both hooks', () => {
    const hooks = { onSessionsRevoked: jest.fn(), afterLogout: jest.fn() }

    announceLogout(hooks, new Logger(), ended)

    expect(hooks.onSessionsRevoked.mock.calls).toStrictEqual([
      [{ userId: 'u1', plane: 'dashboard', reason: 'logout', tenantId: 't1', sessionIds: ['h1'] }]
    ])
    expect(hooks.afterLogout).toHaveBeenCalledWith(
      'u1',
      expect.objectContaining({ plane: 'dashboard', userId: 'u1', tenantId: 't1' })
    )
  })

  // Scenario: the record named no tenant. Expected: neither hook gets the key.
  it('leaves the tenant out when the record named none', () => {
    const hooks = { onSessionsRevoked: jest.fn(), afterLogout: jest.fn() }

    announceLogout(hooks, new Logger(), { ...ended, tenantId: undefined })

    expect(Object.keys(hooks.onSessionsRevoked.mock.calls[0]?.[0] as object)).not.toContain(
      'tenantId'
    )
    expect(Object.keys(hooks.afterLogout.mock.calls[0]?.[1] as object)).not.toContain('tenantId')
  })
})
