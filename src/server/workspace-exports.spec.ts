/**
 * @fileoverview Pins that a host can reach the workspace option surface from the package entry.
 *
 * @layer Test
 */

import {
  ANY_WORKSPACE_MEMBER,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY,
  type BymaxAuthModuleOptions,
  type RegistrationMode,
  type WorkspaceOptions,
  type WorkspacePermissionOptions,
  type WorkspaceRoleList
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
})
