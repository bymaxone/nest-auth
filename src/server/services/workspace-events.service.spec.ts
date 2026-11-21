/**
 * @fileoverview Tests for the workspace event fan-out: delivery to the hook, and isolation from
 * the operation when the hook is slow, throws or rejects.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { WorkspaceAuditEvent } from '../interfaces/workspace-audit.interface'
import { expectEvent } from '../__tests__/log-events'
import { CONTEXT, NOW, WORKSPACE_REF } from './__tests__/workspace-service-harness'
import { WorkspaceEventsService } from './workspace-events.service'

const EVENT: WorkspaceAuditEvent = {
  type: 'workspace.renamed',
  ...WORKSPACE_REF,
  actorUserId: 'u1',
  at: NOW.toISOString()
}

describe('WorkspaceEventsService', () => {
  let error: jest.SpyInstance

  beforeEach(() => {
    error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('hands the event and the context to the hook', () => {
    const onWorkspaceEvent = jest.fn()

    new WorkspaceEventsService({ onWorkspaceEvent } as IAuthHooks).emit(EVENT, CONTEXT)

    expect(onWorkspaceEvent).toHaveBeenCalledWith(EVENT, CONTEXT)
  })

  it('does nothing when the host defines no hook', () => {
    expect(() => new WorkspaceEventsService({} as IAuthHooks).emit(EVENT, CONTEXT)).not.toThrow()
    expect(error).not.toHaveBeenCalled()
  })

  it('does not fail the operation when the hook throws, and logs it', () => {
    const onWorkspaceEvent = jest.fn(() => {
      throw new Error('boom')
    })

    expect(() =>
      new WorkspaceEventsService({ onWorkspaceEvent } as IAuthHooks).emit(EVENT, CONTEXT)
    ).not.toThrow()

    expectEvent(error, 'AUTH_HOOK_FAILED', { hook: 'onWorkspaceEvent', how: 'threw' })
  })

  it('does not fail the operation when the hook rejects, and logs it', async () => {
    const onWorkspaceEvent = jest.fn().mockRejectedValue(new Error('boom'))

    new WorkspaceEventsService({ onWorkspaceEvent } as IAuthHooks).emit(EVENT, CONTEXT)
    await new Promise((resolve) => setImmediate(resolve))

    expectEvent(error, 'AUTH_HOOK_FAILED', { hook: 'onWorkspaceEvent', how: 'rejected' })
  })

  // The event can carry an address; the log event names the hook and how it failed and nothing
  // from the payload, whether the hook throws or rejects.
  it.each([
    [
      'throws',
      () => {
        throw new Error('boom')
      },
      'threw'
    ],
    ['rejects', () => Promise.reject(new Error('boom')), 'rejected']
  ])(
    'never writes the event payload to the log when the hook %s',
    async (_verb, onWorkspaceEvent, how) => {
      const invited: WorkspaceAuditEvent = {
        type: 'member.invited',
        ...WORKSPACE_REF,
        actorUserId: 'inviter-7',
        email: 'jane.doe@example.com',
        role: 'editor',
        at: NOW.toISOString()
      }

      new WorkspaceEventsService({ onWorkspaceEvent } as IAuthHooks).emit(invited, CONTEXT)
      await new Promise((resolve) => setImmediate(resolve))

      expect(error).toHaveBeenCalledTimes(1)
      expectEvent(error, 'AUTH_HOOK_FAILED', { hook: 'onWorkspaceEvent', how }, [
        'jane.doe@example.com',
        'inviter-7',
        'editor',
        NOW.toISOString()
      ])
    }
  )

  it('returns before a slow hook finishes', () => {
    let finished = false
    const onWorkspaceEvent = jest.fn(
      () =>
        new Promise<void>((resolve) =>
          setTimeout(() => {
            finished = true
            resolve()
          }, 1000)
        )
    )

    new WorkspaceEventsService({ onWorkspaceEvent } as IAuthHooks).emit(EVENT, CONTEXT)

    expect(finished).toBe(false)
  })
})
