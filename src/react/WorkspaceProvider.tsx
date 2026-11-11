/**
 * The workspace half of the provider: loads the caller's workspaces after sign-in, resolves the
 * active one, switches, and tells the host when the active workspace changes or refuses the caller.
 *
 * Rendered by the host, inside `<AuthProvider>`, and by nothing else: a host that does not render it
 * makes no workspace request, and a bundler drops all of it from that host's build.
 */

import React, { useContext, useEffect, useMemo, useRef, type ReactNode } from 'react'

import { AuthContext } from './context'
import {
  type AuthWorkspacesOptions,
  WorkspacesContext,
  type WorkspacesContextValue
} from './workspaceContext'
import {
  useBroadcastReload,
  useChangeNotice,
  useRefusalHandler,
  useRoleHint,
  useSwitch,
  useWorkspaceChannel,
  useWorkspaceList,
  type WorkspaceProviderClient
} from './workspaceState'

export type { WorkspaceProviderClient } from './workspaceState'

/** Props of {@link WorkspaceProvider}: the workspace client, the host's options and the tree. */
export interface WorkspaceProviderProps extends AuthWorkspacesOptions {
  /** The result of `createWorkspaceClient`. */
  client: WorkspaceProviderClient
  children: ReactNode
}

/**
 * Provides {@link WorkspacesContext} to the tree below it.
 *
 * @param props - The client, the host's options and the tree.
 * @returns The tree inside the context.
 */
export function WorkspaceProvider({
  client,
  children,
  ...options
}: WorkspaceProviderProps): ReactNode {
  const ctx = useContext(AuthContext)
  if (ctx === null) {
    throw new Error(
      'WorkspaceProvider must be rendered within an <AuthProvider> — it follows the session the provider owns.'
    )
  }
  const optionsRef = useRef(options)
  useEffect(() => {
    optionsRef.current = options
  })
  const identity = ctx.user === null ? null : JSON.stringify([ctx.user.tenantId, ctx.user.id])
  const { loaded, setLoaded, clientRef, identityRef, statusRef, refresh } = useWorkspaceList(
    client,
    ctx.status,
    identity
  )
  const activeId = options.activeWorkspaceId ?? loaded.chosen ?? loaded.lastActiveWorkspaceId
  const activeWorkspace = useMemo(
    () => loaded.items.find((item) => item.workspace.id === activeId) ?? null,
    [loaded.items, activeId]
  )
  useChangeNotice(loaded.status, activeWorkspace, optionsRef)
  const onBroadcast = useBroadcastReload(ctx.refresh, statusRef, identityRef, refresh)
  const channelRef = useWorkspaceChannel(onBroadcast)
  const hasWorkspaceRole = useRoleHint(activeWorkspace, loaded.items, optionsRef)
  const handleWorkspaceError = useRefusalHandler(activeId, optionsRef, refresh)

  const switchWorkspace = useSwitch(clientRef, identityRef, setLoaded, channelRef)

  const value = useMemo<WorkspacesContextValue>(
    () => ({
      memberships: loaded.items,
      activeWorkspace,
      lastActiveWorkspaceId: loaded.lastActiveWorkspaceId,
      status: loaded.status,
      switchWorkspace,
      hasWorkspaceRole,
      handleWorkspaceError,
      refresh
    }),
    [loaded, activeWorkspace, switchWorkspace, hasWorkspaceRole, handleWorkspaceError, refresh]
  )

  return <WorkspacesContext.Provider value={value}>{children}</WorkspacesContext.Provider>
}
