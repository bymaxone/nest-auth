/**
 * @fileoverview Tests for the workspace event fan-out: delivery to the hook, and isolation from
 * the operation when the hook is slow, throws or rejects.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import type { IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { WorkspaceAuditEvent } from '../interfaces/workspace-audit.interface'
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

    expect(error).toHaveBeenCalledWith(expect.stringContaining('onWorkspaceEvent hook failed'))
  })

  it('does not fail the operation when the hook rejects, and logs it', async () => {
    const onWorkspaceEvent = jest.fn().mockRejectedValue(new Error('boom'))

    new WorkspaceEventsService({ onWorkspaceEvent } as IAuthHooks).emit(EVENT, CONTEXT)
    await new Promise((resolve) => setImmediate(resolve))

    expect(error).toHaveBeenCalledWith(expect.stringContaining('onWorkspaceEvent hook failed'))
  })

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
