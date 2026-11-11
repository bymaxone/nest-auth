/**
 * `useWorkspaces()`: the caller's workspaces, the active one, and the calls that act on them.
 */

import { useContext } from 'react'

import { AuthContext } from './context'
import { WorkspacesContext, type WorkspacesContextValue } from './workspaceContext'

/** What the hook answers when no `<WorkspaceProvider>` is rendered: nothing, and no request. */
const DISABLED: WorkspacesContextValue = {
  memberships: [],
  activeWorkspace: null,
  lastActiveWorkspaceId: null,
  status: 'disabled',
  switchWorkspace: () =>
    Promise.reject(
      new Error('useWorkspaces: render a <WorkspaceProvider> inside <AuthProvider> to enable it.')
    ),
  hasWorkspaceRole: () => false,
  handleWorkspaceError: () => false,
  refresh: () => Promise.resolve()
}

/**
 * Reads the workspace state of the nearest `<WorkspaceProvider>`.
 *
 * Under a `<WorkspaceProvider>` it answers from the caller's own workspaces; without one every call
 * is inert and `status` is `disabled`, so a component can be written once and used with
 * or without the feature. `hasWorkspaceRole` is a hint for what to render, never an authority: the
 * server decides every request.
 *
 * @returns The workspace state and calls.
 * @throws {Error} When called outside an `<AuthProvider>`.
 */
export function useWorkspaces(): WorkspacesContextValue {
  if (useContext(AuthContext) === null) {
    throw new Error(
      'useWorkspaces must be called within an <AuthProvider> — wrap the consuming tree in a provider built from createAuthClient().'
    )
  }
  return useContext(WorkspacesContext) ?? DISABLED
}
