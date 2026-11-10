/**
 * @fileoverview Resolution and startup validation of the `workspaces` option group and the
 * `registration` mode.
 *
 * @layer Config
 */

import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type {
  RegistrationMode,
  WorkspaceOptions,
  WorkspaceRoleList
} from '../interfaces/workspace-options.interface'

/** Longest an invitation may stay valid: 30 days, in seconds. */
export const WORKSPACE_INVITATION_MAX_TTL_SECONDS = 2_592_000

/** Longest a membership may stay cached: one hour, in seconds. */
export const WORKSPACE_MEMBERSHIP_CACHE_MAX_TTL_SECONDS = 3600

/** The workspace group with every default applied. Present only while the feature is enabled. */
export interface ResolvedWorkspaceOptions {
  /** Always `true`: a disabled group resolves to nothing. */
  enabled: true
  /** The workspace role hierarchy. */
  roles: WorkspaceOptions['roles']
  /** Which roles may perform each action. */
  permissions: {
    manageWorkspace: readonly string[]
    deleteWorkspace: readonly string[]
    manageMembers: readonly string[]
    viewMembers: WorkspaceRoleList
  }
  /** Whether an identity may create a workspace. */
  allowCreate: NonNullable<WorkspaceOptions['allowCreate']>
  /** Most workspaces one identity may own; `0` is unlimited. */
  maxWorkspacesPerUser: number
  /** Seconds an invitation stays valid. */
  invitationTtlSeconds: number
  /** Most pending invitations per workspace. */
  maxPendingInvitationsPerWorkspace: number
  /** Seconds a resolved membership is cached; `0` disables the cache. */
  membershipCacheTtlSeconds: number
  /** Days a deleted workspace can be restored; `0` deletes at once. */
  deletionGraceDays: number
  /** Reads the target workspace from a request, when the host supplied one. */
  resolveRequestWorkspace?: WorkspaceOptions['resolveRequestWorkspace']
  /** Reads the target workspace from a socket message, when the host supplied one. */
  resolveWsWorkspace?: WorkspaceOptions['resolveWsWorkspace']
}

/**
 * Requires an optional whole-number setting to sit inside its range.
 *
 * @param name - The option path, for the message.
 * @param value - The configured value, if any.
 * @param min - The smallest allowed value.
 * @param max - The largest allowed value.
 * @throws {Error} Naming the option and its range.
 */
function assertIntegerInRange(name: string, value: unknown, min: number, max: number): void {
  if (value === undefined) return
  if (!Number.isInteger(value) || (value as number) < min || (value as number) > max) {
    throw new Error(`[BymaxAuthModule] ${name} must be an integer from ${min} to ${max}.`)
  }
}

/**
 * Requires the workspace role hierarchy to be well formed and the owner role to sit at its top:
 * it includes every other role, and no other role includes it.
 *
 * @param roles - The configured `workspaces.roles`.
 * @throws {Error} Naming the first offending role.
 */
function validateWorkspaceRoles(roles: WorkspaceOptions['roles'] | undefined): void {
  const hierarchy = roles?.hierarchy
  if (hierarchy === undefined || Object.keys(hierarchy).length === 0) {
    throw new Error(
      `[BymaxAuthModule] workspaces.roles.hierarchy is required and must name at least one role.`
    )
  }
  const names = new Set(Object.keys(hierarchy))
  for (const [role, included] of Object.entries(hierarchy)) {
    if (!Array.isArray(included) || included.some((name) => !names.has(name))) {
      throw new Error(
        `[BymaxAuthModule] workspaces.roles.hierarchy.${role} must list only roles that are ` +
          `keys of the hierarchy.`
      )
    }
  }
  const ownerRole = roles?.ownerRole
  if (typeof ownerRole !== 'string' || !names.has(ownerRole)) {
    throw new Error(`[BymaxAuthModule] workspaces.roles.ownerRole must be a role of the hierarchy.`)
  }
  for (const [role, included] of Object.entries(hierarchy)) {
    if (role !== ownerRole && included.includes(ownerRole)) {
      throw new Error(
        `[BymaxAuthModule] workspaces.roles.hierarchy: '${role}' must not include the owner ` +
          `role '${ownerRole}'. A role that includes the owner holds every owner permission.`
      )
    }
  }
  const ownerIncludes = new Set(hierarchy[ownerRole])
  for (const role of names) {
    if (role !== ownerRole && !ownerIncludes.has(role)) {
      throw new Error(
        `[BymaxAuthModule] workspaces.roles.ownerRole '${ownerRole}' must include every other ` +
          `role, and does not include '${role}'. The owner is the top of the hierarchy.`
      )
    }
  }
}

/**
 * Requires every role a permission names to exist in the hierarchy.
 *
 * @param permissions - The configured `workspaces.permissions`.
 * @param roles - The workspace roles.
 * @throws {Error} Naming the permission and the unknown role.
 */
function validateWorkspacePermissions(
  permissions: WorkspaceOptions['permissions'],
  roles: ReadonlySet<unknown>
): void {
  for (const [action, list] of Object.entries(permissions ?? {})) {
    if (list === undefined) continue
    for (const role of list) {
      const known = roles.has(role)
      if (!known && !(action === 'viewMembers' && role === ANY_WORKSPACE_MEMBER)) {
        throw new Error(
          `[BymaxAuthModule] workspaces.permissions.${action} names '${String(role)}', which is ` +
            `not a workspace role.`
        )
      }
    }
  }
}

/**
 * Validates the settings that are numbers, flags and functions.
 *
 * @param group - The enabled `workspaces` group.
 * @throws {Error} Naming the offending option.
 */
function validateWorkspaceTuning(group: WorkspaceOptions): void {
  assertIntegerInRange('workspaces.maxWorkspacesPerUser', group.maxWorkspacesPerUser, 0, 1_000_000)
  assertIntegerInRange(
    'workspaces.invitationTtlSeconds',
    group.invitationTtlSeconds,
    60,
    WORKSPACE_INVITATION_MAX_TTL_SECONDS
  )
  assertIntegerInRange(
    'workspaces.maxPendingInvitationsPerWorkspace',
    group.maxPendingInvitationsPerWorkspace,
    1,
    10_000
  )
  assertIntegerInRange(
    'workspaces.membershipCacheTtlSeconds',
    group.membershipCacheTtlSeconds,
    0,
    WORKSPACE_MEMBERSHIP_CACHE_MAX_TTL_SECONDS
  )
  assertIntegerInRange('workspaces.deletionGraceDays', group.deletionGraceDays, 0, 365)
  const { allowCreate, resolveRequestWorkspace, resolveWsWorkspace } = group
  if (
    allowCreate !== undefined &&
    typeof allowCreate !== 'boolean' &&
    typeof allowCreate !== 'function'
  ) {
    throw new Error(`[BymaxAuthModule] workspaces.allowCreate must be a boolean or a function.`)
  }
  if (resolveRequestWorkspace !== undefined && typeof resolveRequestWorkspace !== 'function') {
    throw new Error(`[BymaxAuthModule] workspaces.resolveRequestWorkspace must be a function.`)
  }
  if (resolveWsWorkspace !== undefined && typeof resolveWsWorkspace !== 'function') {
    throw new Error(`[BymaxAuthModule] workspaces.resolveWsWorkspace must be a function.`)
  }
}

/**
 * Resolves the `registration` mode.
 *
 * `'invitation-only'` closes the password sign-up route and the OAuth create action; an account
 * then comes into being only through an invitation. It needs a way to hand one out, so it is
 * refused when neither workspaces nor tenant invitations are enabled: no account could ever be
 * created.
 *
 * @param userOptions - The options as supplied.
 * @returns The mode in force.
 * @throws {Error} For an unknown mode, or for `'invitation-only'` with workspaces and tenant
 *   invitations both disabled.
 */
export function resolveRegistration(userOptions: BymaxAuthModuleOptions): RegistrationMode {
  const mode = userOptions.registration ?? 'open'
  if (mode !== 'open' && mode !== 'invitation-only') {
    throw new Error(`[BymaxAuthModule] registration must be 'open' or 'invitation-only'.`)
  }
  if (
    mode === 'invitation-only' &&
    userOptions.workspaces?.enabled !== true &&
    userOptions.invitations?.enabled !== true
  ) {
    throw new Error(
      `[BymaxAuthModule] registration: 'invitation-only' needs workspaces.enabled: true or ` +
        `invitations.enabled: true, and both are disabled: no account could ever be created.`
    )
  }
  return mode
}

/**
 * Validates and resolves the `workspaces` group.
 *
 * Nothing is checked while the feature is off, so a host that never opts in is not asked for a
 * role hierarchy.
 *
 * @param userOptions - The options as supplied.
 * @returns The group with every default applied, or `undefined` when the feature is off.
 * @throws {Error} Naming the first offending option.
 */
export function resolveWorkspaceOptions(
  userOptions: BymaxAuthModuleOptions
): ResolvedWorkspaceOptions | undefined {
  const group = userOptions.workspaces
  if (group?.enabled !== true) return undefined

  validateWorkspaceRoles(group.roles)
  const roleNames = new Set(Object.keys(group.roles.hierarchy))
  validateWorkspacePermissions(group.permissions, roleNames)
  validateWorkspaceTuning(group)

  const owner = [group.roles.ownerRole]
  const permissions = group.permissions
  return {
    enabled: true,
    roles: group.roles,
    permissions: {
      manageWorkspace: permissions?.manageWorkspace ?? owner,
      deleteWorkspace: permissions?.deleteWorkspace ?? owner,
      manageMembers: permissions?.manageMembers ?? owner,
      viewMembers: permissions?.viewMembers ?? [ANY_WORKSPACE_MEMBER]
    },
    allowCreate: group.allowCreate ?? true,
    maxWorkspacesPerUser: group.maxWorkspacesPerUser ?? 0,
    invitationTtlSeconds: group.invitationTtlSeconds ?? 604_800,
    maxPendingInvitationsPerWorkspace: group.maxPendingInvitationsPerWorkspace ?? 100,
    membershipCacheTtlSeconds: group.membershipCacheTtlSeconds ?? 60,
    deletionGraceDays: group.deletionGraceDays ?? 14,
    ...(group.resolveRequestWorkspace === undefined
      ? {}
      : { resolveRequestWorkspace: group.resolveRequestWorkspace }),
    ...(group.resolveWsWorkspace === undefined
      ? {}
      : { resolveWsWorkspace: group.resolveWsWorkspace })
  }
}

/**
 * Refuses a module whose workspace flag and repository providers disagree.
 *
 * The feature is registered by its two repository providers and configured by
 * `workspaces.enabled`. One without the other is a half-configured feature that would either serve
 * nothing or fail on first use, so it fails at startup instead.
 *
 * @param enabled - Whether `workspaces.enabled` is true.
 * @param hasWorkspaceRepository - Whether `BYMAX_AUTH_WORKSPACE_REPOSITORY` is in `extraProviders`.
 * @param hasMembershipRepository - Whether `BYMAX_AUTH_MEMBERSHIP_REPOSITORY` is in `extraProviders`.
 * @throws {Error} Naming what is missing or what is provided without the flag.
 */
export function assertWorkspaceProviders(
  enabled: boolean,
  hasWorkspaceRepository: boolean,
  hasMembershipRepository: boolean
): void {
  if (!enabled) {
    if (hasWorkspaceRepository || hasMembershipRepository) {
      throw new Error(
        `[BymaxAuthModule] A workspace repository is provided but workspaces.enabled is not true. ` +
          `Enable workspaces in the useFactory return value, or remove the provider.`
      )
    }
    return
  }
  const missing = [
    hasWorkspaceRepository ? [] : ['BYMAX_AUTH_WORKSPACE_REPOSITORY'],
    hasMembershipRepository ? [] : ['BYMAX_AUTH_MEMBERSHIP_REPOSITORY']
  ].flat()
  if (missing.length > 0) {
    throw new Error(
      `[BymaxAuthModule] workspaces.enabled: true requires ${missing.join(' and ')} in ` +
        `extraProviders. Provide your IWorkspaceRepository and IMembershipRepository implementations.`
    )
  }
}
