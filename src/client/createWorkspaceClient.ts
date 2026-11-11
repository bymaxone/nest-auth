/**
 * Typed workspace calls for the client: listing, switching, members, lifecycle and invitations.
 *
 * Thin wrappers over {@link AUTH_WORKSPACE_ROUTES}. The workspace a call acts in is always the
 * path segment, percent-encoded, never a body field or a header: that is the rule the server
 * enforces, and a client that offered another way would only produce requests the server refuses.
 * Nothing here decides access; every answer is the server's.
 */

import {
  AUTH_ROUTES,
  fillRoute,
  type AcceptedWorkspaceInvitation,
  type AuthResult,
  type WorkspaceAccessClient,
  type WorkspaceClient,
  type WorkspaceInvitationPage,
  type WorkspaceInvitationPreview,
  type WorkspaceListResult,
  type WorkspaceMemberClient,
  type WorkspaceMemberPage,
  type WorkspacePageParams
} from '@bymax-one/nest-auth/shared'

import {
  type AuthClientConfig,
  expectNoContent,
  parseJsonOrThrow,
  resolveTransport
} from './createAuthClient'

const ROUTES = AUTH_ROUTES.workspaces

/** What a password-confirmed action sends: only a host that requires re-authentication needs it. */
export interface WorkspaceReauth {
  /** The caller's password, for an account that has one. */
  password?: string
}

/** The input of an ownership transfer. */
export interface TransferOwnershipInput extends WorkspaceReauth {
  /** The member who becomes an owner. */
  userId: string
  /** The role the caller keeps after handing ownership over; omitted, the server's own default. */
  demoteSelfTo?: string
}

/** The input of an invitation to a workspace. */
export interface InviteToWorkspaceInput {
  email: string
  role: string
}

/** The input of accepting an invitation by creating the account it was addressed to. */
export interface AcceptInvitationSignupInput {
  token: string
  name: string
  password: string
}

/** What a read can be given besides its parameters. */
export interface WorkspaceRequestInit {
  /** Aborts the request when it aborts. */
  signal?: AbortSignal
}

/** The workspace calls of the typed client. */
export interface WorkspaceClientMethods {
  /**
   * Lists the caller's own workspaces, and the one they last switched to. An aborted `signal` cancels
   * the request.
   */
  listWorkspaces(
    page?: WorkspacePageParams,
    init?: WorkspaceRequestInit
  ): Promise<WorkspaceListResult>
  /** Reads a workspace and the caller's role in it. */
  getWorkspaceAccess(workspaceId: string): Promise<WorkspaceAccessClient>
  /** Records a workspace as the caller's last active one. No token changes. */
  switchWorkspace(workspaceId: string): Promise<void>
  /** Creates a workspace owned by the caller. */
  createWorkspace(name: string): Promise<WorkspaceClient>
  /** Renames a workspace. */
  renameWorkspace(workspaceId: string, name: string): Promise<WorkspaceClient>
  /** Schedules a workspace for deletion. */
  scheduleWorkspaceDeletion(workspaceId: string, reauth?: WorkspaceReauth): Promise<void>
  /** Undoes a scheduled deletion inside its grace period. */
  restoreWorkspace(workspaceId: string): Promise<void>
  /** Lists the members of a workspace. */
  listWorkspaceMembers(
    workspaceId: string,
    page?: WorkspacePageParams
  ): Promise<WorkspaceMemberPage>
  /** Changes a member's role. */
  changeWorkspaceMemberRole(
    workspaceId: string,
    userId: string,
    role: string
  ): Promise<WorkspaceMemberClient>
  /** Removes a member. */
  removeWorkspaceMember(workspaceId: string, userId: string): Promise<void>
  /** Leaves a workspace. The last owner must hand ownership over or delete it first. */
  leaveWorkspace(workspaceId: string): Promise<void>
  /** Hands ownership to another member. */
  transferWorkspaceOwnership(workspaceId: string, input: TransferOwnershipInput): Promise<void>
  /** Invites an address to a workspace. */
  inviteToWorkspace(workspaceId: string, input: InviteToWorkspaceInput): Promise<void>
  /** Lists the pending invitations of a workspace. */
  listWorkspaceInvitations(
    workspaceId: string,
    page?: WorkspacePageParams
  ): Promise<WorkspaceInvitationPage>
  /** Sends a pending invitation again under a new token. */
  resendWorkspaceInvitation(workspaceId: string, email: string): Promise<void>
  /** Withdraws a pending invitation. */
  revokeWorkspaceInvitation(workspaceId: string, email: string): Promise<void>
  /** Reads what an invitation token is for, without signing in. */
  previewWorkspaceInvitation(token: string): Promise<WorkspaceInvitationPreview>
  /** Accepts an invitation as the signed-in account it was addressed to. */
  acceptWorkspaceInvitation(token: string): Promise<AcceptedWorkspaceInvitation>
  /** Accepts an invitation by creating the account it was addressed to. */
  acceptWorkspaceInvitationSignup(
    input: AcceptInvitationSignupInput
  ): Promise<AuthResult & AcceptedWorkspaceInvitation>
}

/** Appends the cursor and the limit of a page as a query string. */
function paged(path: string, page: WorkspacePageParams | undefined): string {
  const query = new URLSearchParams()
  if (page?.cursor !== undefined) query.set('cursor', page.cursor)
  if (page?.limit !== undefined) query.set('limit', String(page.limit))
  const text = query.toString()
  return text === '' ? path : `${path}?${text}`
}

/** The two requests every call is made of: one that reads a JSON answer, one that expects none. */
interface Requests {
  json: <T>(method: string, path: string, body?: unknown, signal?: AbortSignal) => Promise<T>
  none: (method: string, path: string, body?: unknown) => Promise<void>
}

const inWorkspace = (template: string, workspaceId: string): string =>
  fillRoute(template, { workspaceId })

const ofMember = (workspaceId: string, userId: string): string =>
  fillRoute(ROUTES.member, { workspaceId, userId })

/** The calls on the caller's workspaces and on one workspace's lifecycle. */
function workspaceCalls({
  json,
  none
}: Requests): Pick<
  WorkspaceClientMethods,
  | 'listWorkspaces'
  | 'getWorkspaceAccess'
  | 'switchWorkspace'
  | 'createWorkspace'
  | 'renameWorkspace'
  | 'scheduleWorkspaceDeletion'
  | 'restoreWorkspace'
> {
  return {
    listWorkspaces: async (page, init) =>
      json('GET', paged(ROUTES.list, page), undefined, init?.signal),
    getWorkspaceAccess: async (id) => json('GET', inWorkspace(ROUTES.access, id)),
    switchWorkspace: async (id) => none('POST', inWorkspace(ROUTES.switch, id), {}),
    createWorkspace: async (name) => json('POST', ROUTES.list, { name }),
    renameWorkspace: async (id, name) => json('PATCH', inWorkspace(ROUTES.rename, id), { name }),
    scheduleWorkspaceDeletion: async (id, reauth) =>
      none('POST', inWorkspace(ROUTES.scheduleDeletion, id), { password: reauth?.password }),
    restoreWorkspace: async (id) => none('POST', inWorkspace(ROUTES.restore, id), {})
  }
}

/** The calls on the members of a workspace, and on leaving it or handing it over. */
function memberCalls({
  json,
  none
}: Requests): Pick<
  WorkspaceClientMethods,
  | 'listWorkspaceMembers'
  | 'changeWorkspaceMemberRole'
  | 'removeWorkspaceMember'
  | 'leaveWorkspace'
  | 'transferWorkspaceOwnership'
> {
  return {
    listWorkspaceMembers: async (id, page) =>
      json('GET', paged(inWorkspace(ROUTES.members, id), page)),
    changeWorkspaceMemberRole: async (id, userId, role) =>
      json('PATCH', ofMember(id, userId), { role }),
    removeWorkspaceMember: async (id, userId) => none('DELETE', ofMember(id, userId)),
    leaveWorkspace: async (id) => none('POST', inWorkspace(ROUTES.leave, id), {}),
    transferWorkspaceOwnership: async (id, input) =>
      none('POST', inWorkspace(ROUTES.transferOwnership, id), {
        userId: input.userId,
        demoteSelfTo: input.demoteSelfTo,
        password: input.password
      })
  }
}

/** The calls on invitations: a workspace's own, and the token-based ones. */
function invitationCalls({
  json,
  none
}: Requests): Pick<
  WorkspaceClientMethods,
  | 'inviteToWorkspace'
  | 'listWorkspaceInvitations'
  | 'resendWorkspaceInvitation'
  | 'revokeWorkspaceInvitation'
  | 'previewWorkspaceInvitation'
  | 'acceptWorkspaceInvitation'
  | 'acceptWorkspaceInvitationSignup'
> {
  return {
    inviteToWorkspace: async (id, input) =>
      none('POST', inWorkspace(ROUTES.invitations, id), { email: input.email, role: input.role }),
    listWorkspaceInvitations: async (id, page) =>
      json('GET', paged(inWorkspace(ROUTES.invitations, id), page)),
    resendWorkspaceInvitation: async (id, email) =>
      none('POST', inWorkspace(ROUTES.resendInvitation, id), { email }),
    revokeWorkspaceInvitation: async (id, email) =>
      none('POST', inWorkspace(ROUTES.revokeInvitation, id), { email }),
    previewWorkspaceInvitation: async (token) => json('POST', ROUTES.previewInvitation, { token }),
    acceptWorkspaceInvitation: async (token) => json('POST', ROUTES.acceptInvitation, { token }),
    acceptWorkspaceInvitationSignup: async (input) =>
      json('POST', ROUTES.acceptInvitationSignup, {
        token: input.token,
        name: input.name,
        password: input.password
      })
  }
}

/**
 * Creates the typed workspace client.
 *
 * Separate from {@link createAuthClient} on purpose: a frontend that does not use workspaces never
 * imports this, so its bundler drops all of it. Pass the same configuration as `createAuthClient`,
 * including `authFetch` when the two should share one refresh logic: a refresh in flight is then
 * shared by both rather than raced.
 *
 * @param config - The client configuration, as for `createAuthClient`.
 * @returns The workspace calls.
 */
export function createWorkspaceClient(config: AuthClientConfig): WorkspaceClientMethods {
  const { authFetch, url } = resolveTransport(config)
  const send = (
    method: string,
    path: string,
    body?: unknown,
    signal?: AbortSignal
  ): Promise<Response> =>
    // JSON.stringify answers `undefined` for no body and drops a key whose value is `undefined`, so an
    // absent option is an absent key on the wire.
    authFetch(url(path), { method, body: JSON.stringify(body), signal: signal ?? null })
  const requests: Requests = {
    json: async <T>(method: string, path: string, body?: unknown, signal?: AbortSignal) =>
      parseJsonOrThrow<T>(await send(method, path, body, signal)),
    none: async (method, path, body) => expectNoContent(await send(method, path, body))
  }
  return { ...workspaceCalls(requests), ...memberCalls(requests), ...invitationCalls(requests) }
}
