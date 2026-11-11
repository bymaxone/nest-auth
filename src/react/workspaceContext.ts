/**
 * The workspace context of the React subpath: what `useWorkspaces()` reads and the options a host
 * passes to `<WorkspaceProvider>`, which is what switches the feature on.
 */

import { createContext } from 'react'

import type { WorkspaceAccessClient } from '@bymax-one/nest-auth/shared'

/**
 * Where the list of the caller's workspaces stands.
 *
 * `disabled` means the host rendered no `<WorkspaceProvider>`, so nothing is loaded and no request
 * is made. `idle` is the state before sign-in and after sign-out.
 */
export type WorkspacesStatus = 'disabled' | 'idle' | 'loading' | 'ready' | 'error'

/** The codes that mean the active workspace refused the caller. */
export type WorkspaceRefusalCode =
  | 'auth.workspace_not_found'
  | 'auth.insufficient_workspace_role'
  | 'auth.workspace_pending_deletion'

/** What a host passes to `<WorkspaceProvider>`, beside its `client`. */
export interface AuthWorkspacesOptions {
  /**
   * The workspace the current URL names, read by the host from its router. It outranks everything
   * else, because the workspace a request acts in travels with the request, so two tabs on two
   * workspaces each keep their own. When it is absent the active workspace is the one chosen with
   * `switchWorkspace`, then the server's `lastActiveWorkspaceId`; it is never read from
   * `localStorage`.
   */
  activeWorkspaceId?: string | undefined
  /**
   * The server's `workspaces.roles.hierarchy`, so `hasWorkspaceRole` can answer for a role that
   * includes another. It must match the server's configuration or the hints will be wrong; without
   * it only an exact role matches. Either way the answer is a hint for what to render and carries
   * no authority: the server decides every request.
   */
  hierarchy?: Readonly<Record<string, readonly string[]>> | undefined
  /**
   * Called when the active workspace changes after the first load, with the one it left and the one
   * it became (`null` when none). Clear the caches keyed by workspace here, so data of the previous
   * workspace is never rendered under the new one. A callback that throws is logged and ignored.
   */
  onWorkspaceChanged?:
    | ((previous: WorkspaceAccessClient | null, next: WorkspaceAccessClient | null) => void)
    | undefined
  /**
   * Called when `handleWorkspaceError` is given a workspace refusal that the ACTIVE workspace
   * answered, for example to redirect to a workspace picker. A refusal answered for any other
   * workspace never calls it. A callback that throws is logged and ignored.
   */
  onWorkspaceAccessLost?: ((workspaceId: string, code: WorkspaceRefusalCode) => void) | undefined
}

/** What `useWorkspaces()` returns. */
export interface WorkspacesContextValue {
  /** The caller's own workspaces and their role in each. Empty until `status` is `ready`. */
  memberships: readonly WorkspaceAccessClient[]
  /** The active workspace, or `null` when none is chosen or it is not among the memberships. */
  activeWorkspace: WorkspaceAccessClient | null
  /** The workspace the caller last switched to, as the server remembers it. */
  lastActiveWorkspaceId: string | null
  status: WorkspacesStatus
  /**
   * Records the workspace as the caller's last active one and makes it the chosen one. The server's
   * refusal rejects and changes nothing. With `activeWorkspaceId` set the URL still outranks it:
   * navigate there too.
   */
  switchWorkspace: (workspaceId: string) => Promise<void>
  /**
   * Whether the caller's role in a workspace is the given one, or includes it through `hierarchy`.
   * Answers for the active workspace, or for `workspaceId` when given. A hint, never an authority.
   */
  hasWorkspaceRole: (role: string, workspaceId?: string) => boolean
  /**
   * Hands an error caught from a call made for `workspaceId` to the provider. A workspace refusal
   * for the ACTIVE workspace reloads the list and calls `onWorkspaceAccessLost`; anything else is
   * left alone. Returns whether it was one, so a caller can stop handling it.
   */
  handleWorkspaceError: (workspaceId: string, error: unknown) => boolean
  /** Reloads the list. */
  refresh: () => Promise<void>
}

/** Provided by `<WorkspaceProvider>`; absent otherwise. */
export const WorkspacesContext = createContext<WorkspacesContextValue | null>(null)
