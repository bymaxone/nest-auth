/**
 * @fileoverview Tests for `@CurrentWsWorkspace()` and the per-message store behind it.
 *
 * @layer Test
 */

import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants'

import { CurrentWsWorkspace } from './current-ws-workspace.decorator'
import { rememberMessageWorkspace, workspaceOfMessage } from '../utils/ws-message-workspace'

const WORKSPACE = { tenantId: 't1', workspaceId: 'w1', userId: 'u1', role: 'viewer' }

/** The function the decorator registers for a handler's first parameter. */
function factoryOf(): (data: unknown, context: unknown) => unknown {
  class Gateway {
    handle(@CurrentWsWorkspace() _workspace: unknown): void {}
  }
  const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, Gateway, 'handle') as Record<
    string,
    { factory: (data: unknown, context: unknown) => unknown }
  >
  return Object.values(args)[0]?.factory as (data: unknown, context: unknown) => unknown
}

/** A WS execution context whose message is `message`. */
function contextOf(message: unknown): unknown {
  return { switchToWs: () => ({ getData: () => message }) }
}

describe('@CurrentWsWorkspace()', () => {
  it('hands the handler the workspace its own message was admitted to', () => {
    const message = { workspaceId: 'w1' }
    rememberMessageWorkspace(message, WORKSPACE)

    expect(factoryOf()(undefined, contextOf(message))).toBe(WORKSPACE)
  })

  it('throws for a message the guard did not admit, even one with equal content', () => {
    rememberMessageWorkspace({ workspaceId: 'w1' }, WORKSPACE)

    expect(() => factoryOf()(undefined, contextOf({ workspaceId: 'w1' }))).toThrow(
      '@CurrentWsWorkspace() needs WsWorkspaceGuard on the handler.'
    )
  })
})

describe('workspaceOfMessage', () => {
  it.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'w1'],
    ['a number', 5]
  ])('answers nothing for %s', (_name, message) => {
    expect(workspaceOfMessage(message)).toBeUndefined()
  })

  it('keys a message by identity, so two messages never share an answer', () => {
    const first = { workspaceId: 'w1' }
    const second = { workspaceId: 'w1' }
    rememberMessageWorkspace(first, WORKSPACE)

    expect(workspaceOfMessage(first)).toBe(WORKSPACE)
    expect(workspaceOfMessage(second)).toBeUndefined()
  })
})
