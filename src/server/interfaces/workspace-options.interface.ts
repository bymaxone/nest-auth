/**
 * @fileoverview The `workspaces` group of the module options, and the `registration` mode that
 * pairs with it.
 *
 * @layer Interface
 */

import type { TenantResolverRequest } from './auth-module-options.interface'
import type { SafeAuthUser } from './user-repository.interface'
import type { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'

/**
 * Who may create an account on their own.
 *
 * - `'open'`: anyone may register, by password or through an OAuth provider.
 * - `'invitation-only'`: sign-up is closed except through a valid invitation for that exact
 *   address. `POST /auth/register` and the OAuth `create` action answer `403
 *   auth.registration_closed`, the invitation accept routes stay open, and an OAuth flow started
 *   with a workspace invitation may create the account it was addressed to. Existing accounts
 *   keep signing in. Startup refuses the mode when workspaces and tenant invitations are both
 *   disabled, since no account could ever be created.
 */
export type RegistrationMode = 'open' | 'invitation-only'

/** A role list in which `ANY_WORKSPACE_MEMBER` stands for every active member. */
export type WorkspaceRoleList = ReadonlyArray<string | typeof ANY_WORKSPACE_MEMBER>

/** Which workspace roles may perform each workspace-level action. */
export interface WorkspacePermissionOptions {
  /** May rename the workspace. Default: the owner role. */
  manageWorkspace?: readonly string[]
  /** May schedule the workspace's deletion. Default: the owner role. */
  deleteWorkspace?: readonly string[]
  /** May invite, remove and change the role of members. Default: the owner role. */
  manageMembers?: readonly string[]
  /** May list the workspace's members. Default: every active member. */
  viewMembers?: WorkspaceRoleList
}

/**
 * Options for the opt-in workspace layer: one identity with a role in each of many workspaces.
 *
 * Workspaces live inside a tenant. The identity, its sessions and its tokens are unchanged; a
 * workspace role is resolved on each request for the workspace that request names.
 */
export interface WorkspaceOptions {
  /** Switches the feature on. Everything else here is ignored while it is `false`. */
  enabled: boolean

  /**
   * The workspace role hierarchy, denormalized like `roles.hierarchy`: each role lists every role
   * it includes. A separate hierarchy from the account-level one, read only by the workspace
   * guards.
   */
  roles: {
    /** Role to the roles it includes. Must name the owner role. */
    hierarchy: Record<string, string[]>
    /** The role that owns a workspace; it must include every other role. */
    ownerRole: string
  }

  /** Which roles may do what. */
  permissions?: WorkspacePermissionOptions

  /**
   * Whether an identity may create a workspace, as a flag or a per-user decision.
   * Default: `true`.
   */
  allowCreate?: boolean | ((user: SafeAuthUser) => boolean | Promise<boolean>)

  /**
   * Most workspaces one identity may own at a time; `0` is unlimited. Default: `0`.
   *
   * A workspace pending deletion still counts until it is finalized or restored, so an identity at
   * the limit cannot create another while one of its workspaces waits out the grace period. The
   * library checks the count before creating, which is advisory under concurrency; a host that
   * needs an exact cap enforces it inside the repository's create call, which receives this value.
   */
  maxWorkspacesPerUser?: number

  /** How long a workspace invitation stays valid, in seconds. Default: 604800 (7 days). Max: 2592000. */
  invitationTtlSeconds?: number

  /** Most pending invitations one workspace may hold. Default: `100`. */
  maxPendingInvitationsPerWorkspace?: number

  /**
   * How long a resolved membership is cached, in seconds; `0` always reads the repository.
   * Default: `60`. Max: `3600`. A host that changes memberships outside the library must call the
   * invalidation methods, or set this to `0`.
   */
  membershipCacheTtlSeconds?: number

  /** Days a deleted workspace can be restored; `0` deletes at once. Default: `14`. */
  deletionGraceDays?: number

  /**
   * Reads the target workspace from a request, for hosts that do not carry it in the route.
   * Return `undefined` when the request names none. Never read it from the body.
   */
  resolveRequestWorkspace?: (req: TenantResolverRequest) => string | undefined

  /**
   * Reads the workspace a socket message names, for `WsWorkspaceGuard`. Receives the message body
   * and nothing else: never the URL, a header or the handshake, so the workspace cannot come from
   * where a confused deputy could be steered. Without it the guard reads `data.workspaceId`.
   * A value that is not a well-formed workspace id is refused as a validation error.
   */
  resolveWsWorkspace?: (message: unknown) => unknown
}
