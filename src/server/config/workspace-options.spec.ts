/**
 * @fileoverview Tests for the `workspaces` option group, the `registration` mode and the check that
 * the flag and the repository providers agree.
 *
 * @layer Test
 */

import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type {
  WorkspaceOptions,
  WorkspacePermissionOptions
} from '../interfaces/workspace-options.interface'
import { resolveOptions } from './resolved-options'
import {
  assertWorkspaceProviders,
  resolveRegistration,
  resolveWorkspaceOptions
} from './workspace-options'

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'

/** A workspace group that is valid as written; each case changes one thing. */
const GROUP: WorkspaceOptions = {
  enabled: true,
  roles: {
    hierarchy: { owner: ['editor', 'reviewer'], editor: ['reviewer'], reviewer: [] },
    ownerRole: 'owner'
  }
}

/** Valid base options with the given workspace group, registration mode and invitations flag. */
function options(
  workspaces?: Partial<WorkspaceOptions> | undefined,
  extra: Partial<BymaxAuthModuleOptions> = {}
): BymaxAuthModuleOptions {
  return {
    jwt: { secret: SECRET },
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...(workspaces === undefined ? {} : { workspaces: { ...GROUP, ...workspaces } }),
    ...extra
  }
}

describe('resolveWorkspaceOptions', () => {
  // A host that never opts in is not asked for a role hierarchy and gets no group at all.
  it('resolves to nothing when the feature is absent or disabled', () => {
    expect(resolveWorkspaceOptions(options())).toBeUndefined()
    expect(resolveWorkspaceOptions(options({ enabled: false }))).toBeUndefined()
  })

  it('applies every default for an enabled group', () => {
    const resolved = resolveWorkspaceOptions(options({}))

    expect(resolved).toEqual({
      enabled: true,
      roles: GROUP.roles,
      permissions: {
        manageWorkspace: ['owner'],
        deleteWorkspace: ['owner'],
        manageMembers: ['owner'],
        viewMembers: [ANY_WORKSPACE_MEMBER]
      },
      allowCreate: true,
      maxWorkspacesPerUser: 0,
      invitationTtlSeconds: 604_800,
      maxPendingInvitationsPerWorkspace: 100,
      membershipCacheTtlSeconds: 60,
      deletionGraceDays: 14
    })
  })

  it('keeps the values a host sets', () => {
    const resolveRequestWorkspace = (): string | undefined => undefined
    const allowCreate = (): boolean => false

    const resolved = resolveWorkspaceOptions(
      options({
        permissions: { manageWorkspace: ['editor'], viewMembers: ['reviewer'] },
        allowCreate,
        maxWorkspacesPerUser: 3,
        invitationTtlSeconds: 3600,
        maxPendingInvitationsPerWorkspace: 5,
        membershipCacheTtlSeconds: 0,
        deletionGraceDays: 0,
        resolveRequestWorkspace
      })
    )

    expect(resolved).toMatchObject({
      permissions: {
        manageWorkspace: ['editor'],
        deleteWorkspace: ['owner'],
        viewMembers: ['reviewer']
      },
      allowCreate,
      maxWorkspacesPerUser: 3,
      invitationTtlSeconds: 3600,
      maxPendingInvitationsPerWorkspace: 5,
      membershipCacheTtlSeconds: 0,
      deletionGraceDays: 0,
      resolveRequestWorkspace
    })
  })

  describe('roles', () => {
    it.each([
      ['no hierarchy', undefined, /roles\.hierarchy is required/],
      ['an empty hierarchy', { hierarchy: {}, ownerRole: 'owner' }, /roles\.hierarchy is required/],
      [
        'a role that includes an unknown role',
        { hierarchy: { owner: ['ghost'] }, ownerRole: 'owner' },
        'workspaces.roles.hierarchy.owner must list only roles that are keys of the hierarchy.'
      ],
      [
        'a role whose inclusions are not a list',
        { hierarchy: { owner: 'editor' }, ownerRole: 'owner' },
        'workspaces.roles.hierarchy.owner must list only roles that are keys of the hierarchy.'
      ],
      [
        'an owner role outside the hierarchy',
        { hierarchy: { owner: [] }, ownerRole: 'boss' },
        /ownerRole must be a role of the hierarchy/
      ],
      [
        'a non-owner role that includes the owner role',
        { hierarchy: { owner: ['viewer'], viewer: ['owner'] }, ownerRole: 'owner' },
        /'viewer' must not include the owner role 'owner'/
      ],
      [
        'a non-owner role that includes the owner role among others',
        { hierarchy: { owner: ['a', 'b'], a: [], b: ['a', 'owner'] }, ownerRole: 'owner' },
        /'b' must not include the owner role 'owner'/
      ],
      [
        'an owner role that does not include every other role',
        { hierarchy: { owner: ['editor'], editor: [], reviewer: [] }, ownerRole: 'owner' },
        /must include every other role, and does not include 'reviewer'/
      ]
    ])('refuses %s', (_name, roles, message) => {
      expect(() =>
        resolveWorkspaceOptions(options({ roles: roles as WorkspaceOptions['roles'] }))
      ).toThrow(message)
    })

    // Listing itself adds nothing to the owner, so it is not the "role that includes the owner"
    // case the check refuses.
    it('accepts an owner role that lists itself', () => {
      expect(
        resolveWorkspaceOptions(
          options({
            roles: { hierarchy: { owner: ['owner', 'editor'], editor: [] }, ownerRole: 'owner' }
          })
        )
      ).toBeDefined()
    })

    it('accepts a single-role hierarchy whose only role owns', () => {
      expect(
        resolveWorkspaceOptions(
          options({ roles: { hierarchy: { owner: [] }, ownerRole: 'owner' } })
        )
      ).toBeDefined()
    })
  })

  describe('permissions', () => {
    it('refuses a permission that names an unknown role', () => {
      expect(() =>
        resolveWorkspaceOptions(options({ permissions: { manageMembers: ['ghost'] } }))
      ).toThrow(
        "workspaces.permissions.manageMembers names 'ghost', which is not a workspace role."
      )
    })

    it('refuses a permission entry that is not a string', () => {
      expect(() =>
        resolveWorkspaceOptions(
          options({ permissions: { manageMembers: [42] as unknown as readonly string[] } })
        )
      ).toThrow("workspaces.permissions.manageMembers names '42', which is not a workspace role.")
    })

    it('refuses the any-member marker on an action other than viewing members', () => {
      expect(() =>
        resolveWorkspaceOptions(
          options({
            permissions: { manageMembers: [ANY_WORKSPACE_MEMBER] as unknown as readonly string[] }
          })
        )
      ).toThrow(/permissions\.manageMembers names 'Symbol\(ANY_WORKSPACE_MEMBER\)'/)
    })

    it('refuses an unknown role for viewing members, marker or not', () => {
      expect(() =>
        resolveWorkspaceOptions(options({ permissions: { viewMembers: ['ghost'] } }))
      ).toThrow("workspaces.permissions.viewMembers names 'ghost', which is not a workspace role.")
    })

    it('accepts the any-member marker for viewing members', () => {
      expect(
        resolveWorkspaceOptions(options({ permissions: { viewMembers: [ANY_WORKSPACE_MEMBER] } }))
      ).toBeDefined()
    })

    // A JavaScript host can write `manageMembers: undefined`, which Object.entries still lists.
    it('treats an explicitly undefined permission as unset', () => {
      const resolved = resolveWorkspaceOptions(
        options({
          permissions: { manageMembers: undefined } as unknown as WorkspacePermissionOptions
        })
      )

      expect(resolved?.permissions.manageMembers).toEqual(['owner'])
    })
  })

  describe('tuning', () => {
    it.each([
      ['maxWorkspacesPerUser', -1, 'from 0 to 1000000'],
      ['maxWorkspacesPerUser', 1.5, 'from 0 to 1000000'],
      ['invitationTtlSeconds', 59, 'from 60 to 2592000'],
      ['invitationTtlSeconds', 2_592_001, 'from 60 to 2592000'],
      ['maxPendingInvitationsPerWorkspace', 0, 'from 1 to 10000'],
      ['maxPendingInvitationsPerWorkspace', 10_001, 'from 1 to 10000'],
      ['membershipCacheTtlSeconds', -1, 'from 0 to 3600'],
      ['membershipCacheTtlSeconds', 3601, 'from 0 to 3600'],
      ['deletionGraceDays', -1, 'from 0 to 365'],
      ['deletionGraceDays', 366, 'from 0 to 365'],
      ['deletionGraceDays', Number.NaN, 'from 0 to 365']
    ])('refuses %s = %p', (name, value, range) => {
      expect(() => resolveWorkspaceOptions(options({ [name]: value }))).toThrow(
        `workspaces.${name} must be an integer ${range}.`
      )
    })

    it.each([
      ['maxWorkspacesPerUser', 0],
      ['maxWorkspacesPerUser', 1_000_000],
      ['invitationTtlSeconds', 60],
      ['invitationTtlSeconds', 2_592_000],
      ['maxPendingInvitationsPerWorkspace', 1],
      ['maxPendingInvitationsPerWorkspace', 10_000],
      ['membershipCacheTtlSeconds', 0],
      ['membershipCacheTtlSeconds', 3600],
      ['deletionGraceDays', 0],
      ['deletionGraceDays', 365]
    ])('accepts %s = %p at its bound', (name, value) => {
      expect(resolveWorkspaceOptions(options({ [name]: value }))).toMatchObject({ [name]: value })
    })

    it('accepts allowCreate as a flag or a function and keeps it as given', () => {
      const decide = (): boolean => false

      expect(resolveWorkspaceOptions(options({ allowCreate: false }))?.allowCreate).toBe(false)
      expect(resolveWorkspaceOptions(options({ allowCreate: decide }))?.allowCreate).toBe(decide)
    })

    it('carries resolveRequestWorkspace only when the host set it', () => {
      const read = (): undefined => undefined
      const unset = resolveWorkspaceOptions(options({}))
      const set = resolveWorkspaceOptions(options({ resolveRequestWorkspace: read }))

      expect(unset).not.toHaveProperty('resolveRequestWorkspace')
      expect(set?.resolveRequestWorkspace).toBe(read)
    })

    it('refuses an allowCreate that is neither a flag nor a function', () => {
      expect(() =>
        resolveWorkspaceOptions(options({ allowCreate: 'yes' as unknown as boolean }))
      ).toThrow('workspaces.allowCreate must be a boolean or a function.')
    })

    it('refuses a resolveRequestWorkspace that is not a function', () => {
      expect(() =>
        resolveWorkspaceOptions(
          options({ resolveRequestWorkspace: 'x-workspace' as unknown as () => undefined })
        )
      ).toThrow('workspaces.resolveRequestWorkspace must be a function.')
    })
  })
})

describe('resolveRegistration', () => {
  it('defaults to open', () => {
    expect(resolveRegistration(options())).toBe('open')
  })

  it('refuses a mode that is neither open nor invitation-only', () => {
    expect(() =>
      resolveRegistration(options(undefined, { registration: 'closed' as 'open' }))
    ).toThrow("registration must be 'open' or 'invitation-only'.")
  })

  it.each([
    ['no other option', undefined, {}],
    ['workspaces enabled', {}, {}],
    ['tenant invitations enabled', undefined, { invitations: { enabled: true } }]
  ])('refuses invitation-only with %s, naming the missing enforcement', (_name, group, extra) => {
    expect(() =>
      resolveRegistration(options(group, { registration: 'invitation-only', ...extra }))
    ).toThrow(
      "[BymaxAuthModule] registration: 'invitation-only' is not enforced by this version: " +
        "remove it or set 'open'. Accepting it would leave sign-up open while it is configured closed."
    )
  })

  it('accepts an explicit open mode', () => {
    expect(resolveRegistration(options(undefined, { registration: 'open' }))).toBe('open')
  })
})

describe('resolveOptions with workspaces', () => {
  it('carries the resolved group and the registration mode', () => {
    const resolved = resolveOptions(options({ deletionGraceDays: 7 }, { registration: 'open' }))

    expect(resolved.workspaces).toMatchObject({ enabled: true, deletionGraceDays: 7 })
    expect(resolved.registration).toBe('open')
  })

  it('refuses invitation-only while resolving the module options', () => {
    expect(() =>
      resolveOptions(options({ deletionGraceDays: 7 }, { registration: 'invitation-only' }))
    ).toThrow(/registration: 'invitation-only' is not enforced by this version/)
  })

  it('has no workspace group when the feature is off, and registration open', () => {
    const resolved = resolveOptions(options())

    expect(resolved.workspaces).toBeUndefined()
    expect(resolved.registration).toBe('open')
  })
})

describe('assertWorkspaceProviders', () => {
  it('accepts a disabled feature with no repository', () => {
    expect(() => assertWorkspaceProviders(false, false, false)).not.toThrow()
  })

  it.each([
    [true, false],
    [false, true],
    [true, true]
  ])('refuses a disabled feature with a repository (workspace %p, membership %p)', (ws, mem) => {
    expect(() => assertWorkspaceProviders(false, ws, mem)).toThrow(
      'A workspace repository is provided but workspaces.enabled is not true. ' +
        'Enable workspaces in the useFactory return value, or remove the provider.'
    )
  })

  it('accepts an enabled feature with both repositories', () => {
    expect(() => assertWorkspaceProviders(true, true, true)).not.toThrow()
  })

  it.each([
    [false, true, 'BYMAX_AUTH_WORKSPACE_REPOSITORY'],
    [true, false, 'BYMAX_AUTH_MEMBERSHIP_REPOSITORY'],
    [false, false, 'BYMAX_AUTH_WORKSPACE_REPOSITORY and BYMAX_AUTH_MEMBERSHIP_REPOSITORY']
  ])('names what an enabled feature lacks (workspace %p, membership %p)', (ws, mem, named) => {
    expect(() => assertWorkspaceProviders(true, ws, mem)).toThrow(
      `requires ${named} in extraProviders. ` +
        'Provide your IWorkspaceRepository and IMembershipRepository implementations.'
    )
  })
})
