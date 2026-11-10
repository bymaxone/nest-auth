/**
 * @fileoverview `@CurrentWsWorkspace()`: the workspace a socket message was admitted to.
 *
 * @layer Decorator
 */

import { createParamDecorator } from '@nestjs/common'
import type { ExecutionContext } from '@nestjs/common'

import type { CurrentWorkspaceContext } from './current-workspace.decorator'
import { workspaceOfMessage } from '../utils/ws-message-workspace'

/**
 * Injects the workspace `WsWorkspaceGuard` admitted THIS message to.
 *
 * A gateway handler takes its workspace from here and never from the message body: the guard is the
 * only place that checked the caller may act in it. It is per message, not per connection, so two
 * messages in flight on one socket each see their own. Throws when the handler runs without
 * `WsWorkspaceGuard`, since an id read from anywhere else would be unchecked.
 */
export const CurrentWsWorkspace = createParamDecorator(
  (_data: unknown, context: ExecutionContext): CurrentWorkspaceContext => {
    const workspace = workspaceOfMessage(context.switchToWs().getData<unknown>())
    if (workspace === undefined) {
      throw new Error('@CurrentWsWorkspace() needs WsWorkspaceGuard on the handler.')
    }
    return workspace
  }
)
