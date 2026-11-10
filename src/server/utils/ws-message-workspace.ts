/**
 * @fileoverview The membership `WsWorkspaceGuard` resolved for ONE socket message, kept with the
 * message and never with the connection.
 *
 * @layer Utility
 */

import type { CurrentWorkspaceContext } from '../decorators/current-workspace.decorator'

/**
 * Messages are keyed by identity: Nest hands the guard and the handler the same message object, so
 * the handler reads what its own message was admitted to. A connection holds many overlapping
 * messages, and a slot on the connection would be overwritten by whichever guard finished last, so
 * a handler awaiting something could read the workspace another message was admitted to.
 */
const admitted = new WeakMap<object, CurrentWorkspaceContext>()

/**
 * Records the workspace a message was admitted to.
 *
 * @param message - The message object the guard and the handler both receive.
 * @param workspace - What the guard resolved for it.
 */
export function rememberMessageWorkspace(
  message: object,
  workspace: CurrentWorkspaceContext
): void {
  admitted.set(message, workspace)
}

/**
 * Reads the workspace a message was admitted to.
 *
 * @param message - The message object.
 * @returns The workspace, or `undefined` for a message the guard did not admit.
 */
export function workspaceOfMessage(message: unknown): CurrentWorkspaceContext | undefined {
  return typeof message === 'object' && message !== null ? admitted.get(message) : undefined
}
