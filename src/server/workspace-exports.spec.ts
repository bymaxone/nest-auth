/**
 * @fileoverview Pins that a host can reach the workspace option surface from the package entry.
 *
 * @layer Test
 */

import {
  ANY_WORKSPACE_MEMBER,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY,
  CurrentWorkspace,
  type BymaxAuthModuleOptions,
  type RegistrationMode,
  type WorkspaceOptions,
  type WorkspacePermissionOptions,
  type WorkspaceRoleList,
  MembershipService,
  WorkspaceAccessService,
  WorkspaceGuard,
  WorkspacePermission,
  WorkspaceRoles,
  WorkspaceService,
  type WorkspaceAction
} from './index'

describe('workspace exports', () => {
  it('exports the any-member marker as a symbol', () => {
    expect(typeof ANY_WORKSPACE_MEMBER).toBe('symbol')
  })

  it('exports both repository tokens as distinct symbols', () => {
    expect(typeof BYMAX_AUTH_WORKSPACE_REPOSITORY).toBe('symbol')
    expect(typeof BYMAX_AUTH_MEMBERSHIP_REPOSITORY).toBe('symbol')
    expect(BYMAX_AUTH_WORKSPACE_REPOSITORY).not.toBe(BYMAX_AUTH_MEMBERSHIP_REPOSITORY)
  })

  // The assertions are the type annotations: this file fails to compile if any of these names is
  // missing from the entry, or if the marker is not accepted in a view-members list.
  it('lets a host write the workspace options using only the entry', () => {
    const viewMembers: WorkspaceRoleList = [ANY_WORKSPACE_MEMBER, 'reviewer']
    const permissions: WorkspacePermissionOptions = { viewMembers }
    const registration: RegistrationMode = 'invitation-only'
    const workspaces: WorkspaceOptions = {
      enabled: true,
      roles: { hierarchy: { owner: ['reviewer'], reviewer: [] }, ownerRole: 'owner' },
      permissions
    }
    const options: Pick<BymaxAuthModuleOptions, 'workspaces' | 'registration'> = {
      workspaces,
      registration
    }

    expect(options.registration).toBe('invitation-only')
    expect(options.workspaces?.permissions?.viewMembers).toContain(ANY_WORKSPACE_MEMBER)
  })

  it('exports the guard, the decorators and the access service a host mounts', () => {
    expect([WorkspaceGuard, WorkspaceAccessService].map((value) => typeof value)).toEqual([
      'function',
      'function'
    ])
    expect([WorkspaceService, MembershipService].map((value) => typeof value)).toEqual([
      'function',
      'function'
    ])
    expect(typeof WorkspaceRoles).toBe('function')
    expect(typeof CurrentWorkspace).toBe('function')
  })

  it('lets a host declare a route by the action it performs', () => {
    const action: WorkspaceAction = 'manageMembers'

    expect(typeof WorkspacePermission(action)).toBe('function')
  })
})
