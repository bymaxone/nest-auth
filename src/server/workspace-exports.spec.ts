/**
 * @fileoverview Pins that a host can reach the workspace option surface from the package entry.
 *
 * @layer Test
 */

import {
  ANY_WORKSPACE_MEMBER,
  AUTH_SECRET_MIN_LENGTH,
  AuthException,
  WORKSPACE_ID_MAX_LENGTH,
  assertWorkspaceId,
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

  // Scenario: the id bound a host reads from the entry. Expected: 128, counted in code points.
  it('exports the workspace id bound', () => {
    expect(WORKSPACE_ID_MAX_LENGTH).toBe(128)
  })

  // Scenario: ids at and beyond the bound. Expected: 128 code points are accepted, an emoji counting
  // once, and 129 are refused, so the bound moves with the constant.
  it('accepts a workspace id of the bound and refuses one past it', () => {
    expect(assertWorkspaceId('a'.repeat(WORKSPACE_ID_MAX_LENGTH))).toHaveLength(
      WORKSPACE_ID_MAX_LENGTH
    )
    expect(Array.from(assertWorkspaceId('😀'.repeat(WORKSPACE_ID_MAX_LENGTH)))).toHaveLength(
      WORKSPACE_ID_MAX_LENGTH
    )
    expect(() => assertWorkspaceId('a'.repeat(WORKSPACE_ID_MAX_LENGTH + 1))).toThrow(AuthException)
    expect(() => assertWorkspaceId('😀'.repeat(WORKSPACE_ID_MAX_LENGTH + 1))).toThrow(AuthException)
  })

  // Scenario: what is not a workspace id. Expected: each is refused with auth.validation naming the
  // field workspaceId, the refusal a handshake answers as it is.
  it.each([[''], ['   '], ['a\nb'], ['a\u0000b'], [42], [null], [undefined], [{}]])(
    'refuses the workspace id %j naming the field',
    (value) => {
      const thrown = ((): unknown => {
        try {
          return assertWorkspaceId(value)
        } catch (error) {
          return error
        }
      })()

      expect(thrown).toBeInstanceOf(AuthException)
      expect((thrown as AuthException).getResponse()).toMatchObject({
        error: { code: 'auth.validation', details: [{ field: 'workspaceId' }] }
      })
    }
  )

  // Scenario: the secret floor a host reads from the entry. Expected: 32, which the template's
  // environment schema must hold its own check to.
  it('exports the secret floor', () => {
    expect(AUTH_SECRET_MIN_LENGTH).toBe(32)
  })
})
