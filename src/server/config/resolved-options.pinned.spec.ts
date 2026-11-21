/**
 * @fileoverview The role hierarchy is read from the host once: the resolved options hold what was validated, not the
 * host's object, so a getter that answers differently on a later read cannot change who may grant what.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'kT3vQ8mZp1Lx9RwYb6NcHs2EdUo7GfJa5VnMiXq4tBeKy0AzWr'

/** A hierarchy whose roles are getters that count their reads and answer another list after the first. */
function countingHierarchy(reads: Record<string, number>): Record<string, string[]> {
  const hierarchy: Record<string, string[]> = {}
  for (const role of ['ADMIN', 'MEMBER'])
    Object.defineProperty(hierarchy, role, {
      enumerable: true,
      get(): string[] {
        reads[role] = (reads[role] ?? 0) + 1
        return reads[role] === 1 ? (role === 'ADMIN' ? ['MEMBER'] : []) : ['ADMIN']
      }
    })
  return hierarchy
}

function optionsWith(roles: unknown): BymaxAuthModuleOptions {
  const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
    jwt: { secret: SECRET },
    roles,
    rateLimit: { clientIpSource: 'peer' }
  }
  return given as BymaxAuthModuleOptions
}

describe('the role hierarchy of the resolved options', () => {
  // Scenario: a hierarchy whose roles are getters, read through the resolved options after they resolved. Expected: the
  // host's getters were read once each, by the resolution, and what the resolved options hold is what was validated.
  // Why: a getter that answers differently on a later read would grant, at a check, a role the validation never saw.
  it('holds what was validated and never reads the host again', () => {
    const reads: Record<string, number> = {}

    const resolved = resolveOptions(optionsWith({ hierarchy: countingHierarchy(reads) }))
    const admin = resolved.roles.hierarchy['ADMIN']
    void resolved.roles.hierarchy['ADMIN']

    expect(reads).toEqual({ ADMIN: 1, MEMBER: 1 })
    expect(admin).toEqual(['MEMBER'])
    expect(resolved.roles.hierarchy['MEMBER']).toEqual([])
  })

  // Scenario: the children of a role mutated by the host after the options resolved. Expected: the resolved options do
  // not change. Why: the list the host kept is the host's; the library holds its own copy of what it checked.
  it('holds its own copy of the children of a role', () => {
    const children = ['MEMBER']
    const resolved = resolveOptions(optionsWith({ hierarchy: { ADMIN: children, MEMBER: [] } }))

    children.push('ADMIN')

    expect(resolved.roles.hierarchy['ADMIN']).toEqual(['MEMBER'])
  })

  // Scenario: a hierarchy that is not an object, an array, and a role whose children are not a list. Expected: each is
  // refused as before, naming what is wrong. Why: pinning the hierarchy is not a new way to accept one.
  it.each([
    ['is missing, with roles undefined', undefined, 'roles.hierarchy is required'],
    ['is missing, with roles null', null, 'roles.hierarchy is required'],
    ['is null', { hierarchy: null }, 'roles.hierarchy is required'],
    ['is missing, with roles an array', [], 'roles.hierarchy is required'],
    ['is missing, with roles a string', 'ADMIN', 'roles.hierarchy is required'],
    ['is missing, with roles a number', 7, 'roles.hierarchy is required'],
    ['is not an object', { hierarchy: 'ADMIN' }, 'roles.hierarchy'],
    ['is an array', { hierarchy: ['ADMIN'] }, 'roles.hierarchy'],
    [
      'has a role whose children are not a list',
      { hierarchy: { ADMIN: 'MEMBER' } },
      "roles.hierarchy['ADMIN']"
    ]
  ])('still refuses a hierarchy that %s', (_name, roles, named) => {
    expect(() => resolveOptions(optionsWith(roles))).toThrow(named)
  })

  // Scenario: the other two hierarchies of the same kind, the platform one and the one of the workspaces, whose roles
  // are getters that count their reads and answer another list after the first, read through the resolved options
  // after they resolved. Expected: the host was read once for each role, and the resolved options hold what was
  // validated and a copy of it. Why: they are read per request by the platform guard and by the workspace checks, and a
  // getter that answers differently later would grant, at a check, what the validation never saw.
  it.each([
    ['the platform hierarchy', ['SUPER_ADMIN', 'SUPPORT'], 'SUPPORT'],
    ['the hierarchy of the workspaces', ['owner', 'editor'], 'editor']
  ] as const)(
    'holds what was validated of %s and never reads the host again',
    (name, roleNames, child) => {
      const reads: Record<string, number> = {}
      const hierarchy: Record<string, string[]> = {}
      for (const role of roleNames)
        Object.defineProperty(hierarchy, role, {
          enumerable: true,
          get(): string[] {
            reads[role] = (reads[role] ?? 0) + 1
            return reads[role] === 1 ? (role === roleNames[0] ? [child] : []) : [roleNames[0]]
          }
        })
      const roles =
        name === 'the platform hierarchy'
          ? { hierarchy: { MEMBER: [] }, platformHierarchy: hierarchy }
          : { hierarchy: { MEMBER: [] } }
      const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
        jwt: { secret: SECRET },
        roles,
        rateLimit: { clientIpSource: 'peer' },
        ...(name === 'the platform hierarchy'
          ? { platform: { enabled: true } }
          : { workspaces: { enabled: true, roles: { hierarchy, ownerRole: 'owner' } } })
      }

      const resolved = resolveOptions(given as BymaxAuthModuleOptions)
      const held =
        name === 'the platform hierarchy'
          ? resolved.roles.platformHierarchy
          : resolved.workspaces?.roles.hierarchy
      void held?.[roleNames[0]]
      void held?.[roleNames[0]]

      expect(reads).toEqual({ [roleNames[0]]: 1, [roleNames[1]]: 1 })
      expect(held?.[roleNames[0]]).toEqual([child])
      expect(held).not.toBe(hierarchy)
    }
  )

  // Scenario: a group whose hierarchy is an own getter, and a group of the workspaces that is an instance of a class
  // with the hierarchy as a getter on its prototype, each counting its reads; and options with no platform hierarchy.
  // Expected: each getter is read once, the options resolve as they would with plain data, and a hierarchy that was
  // never given is not added as a key. Why: the host's own object is read once whatever way it keeps the hierarchy, and
  // pinning must not invent an option the host left out.
  it('reads a getter of the hierarchy once, own or on a prototype, and adds no key that was absent', () => {
    let own = 0
    let inherited = 0
    class WorkspaceRoles {
      ownerRole = 'owner'
      get hierarchy(): Record<string, string[]> {
        inherited += 1
        return { owner: ['editor'], editor: [] }
      }
    }
    const roles = {
      get hierarchy(): Record<string, string[]> {
        own += 1
        return { MEMBER: [] }
      }
    }
    const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
      jwt: { secret: SECRET },
      roles,
      rateLimit: { clientIpSource: 'peer' },
      workspaces: { enabled: true, roles: new WorkspaceRoles() }
    }

    const resolved = resolveOptions(given as BymaxAuthModuleOptions)

    expect([own, inherited]).toEqual([1, 1])
    expect(resolved.roles.hierarchy).toEqual({ MEMBER: [] })
    expect(resolved.workspaces?.roles.hierarchy).toEqual({ owner: ['editor'], editor: [] })
    expect(Object.hasOwn(resolved.roles, 'platformHierarchy')).toBe(false)

    let ownOfWorkspaces = 0
    const workspaceRoles = { ownerRole: 'owner' }
    Object.defineProperty(workspaceRoles, 'hierarchy', {
      enumerable: true,
      get(): Record<string, string[]> {
        ownOfWorkspaces += 1
        return { owner: ['editor'], editor: [] }
      }
    })
    resolveOptions({
      ...(given as BymaxAuthModuleOptions),
      workspaces: { enabled: true, roles: workspaceRoles }
    } as BymaxAuthModuleOptions)
    expect(ownOfWorkspaces).toBe(1)
  })

  // Scenario: the roles of the workspaces served by a typed configuration class whose owner role AND hierarchy are
  // getters on its prototype (and the hierarchy of the account a getter too), each counting its reads. Expected: the
  // options resolve as they do with an object literal, each getter read once, and the owner role is the one served.
  // Why: a class is a supported way to write the options, and a copy that carried only own keys would drop the owner
  // role and refuse a deployment that started before.
  it('resolves workspace roles that a class serves on its prototype, each getter read once', () => {
    const reads = { ownerRole: 0, hierarchy: 0 }
    class WorkspaceRoles {
      get ownerRole(): string {
        reads.ownerRole += 1
        return 'owner'
      }
      get hierarchy(): Record<string, string[]> {
        reads.hierarchy += 1
        return { owner: ['editor'], editor: [] }
      }
    }
    const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
      jwt: { secret: SECRET },
      roles: { hierarchy: { MEMBER: [] } },
      rateLimit: { clientIpSource: 'peer' },
      workspaces: { enabled: true, roles: new WorkspaceRoles() }
    }

    const resolved = resolveOptions(given as BymaxAuthModuleOptions)

    expect(reads).toEqual({ ownerRole: 1, hierarchy: 1 })
    expect(resolved.workspaces?.roles.ownerRole).toBe('owner')
    expect(resolved.workspaces?.roles.hierarchy).toEqual({ owner: ['editor'], editor: [] })
  })

  // Scenario: the roles written as a function that carries a hierarchy, which the checks accept as a group, and the host
  // changing that hierarchy after the options resolved. Expected: the resolved roles are a copy, the host's function and
  // its hierarchy are untouched, and the change does not reach the resolved options. Why: a hierarchy the host can still
  // change after validation is the defect the pin exists to close, whatever the host wrote the group as.
  it('copies the hierarchy of a function that carries one and never writes to the function', () => {
    const hierarchy: Record<string, string[]> = { MEMBER: [] }
    const roles = Object.assign(() => undefined, { hierarchy })

    const resolved = resolveOptions(optionsWith(roles))
    hierarchy['MEMBER']?.push('ADMIN')
    hierarchy['ADMIN'] = []

    expect(resolved.roles).not.toBe(roles)
    expect(roles.hierarchy).toBe(hierarchy)
    expect(resolved.roles.hierarchy).toEqual({ MEMBER: [] })
  })

  // Scenario: each of the three hierarchies written as an object, as a function that carries the roles and as an array
  // of lists (a role named by its index), which the checks accept, and the host changing the roles and a list after the
  // options resolved. Expected: the resolved hierarchy is a plain copy that the change does not reach. Why: the pin
  // closes a hierarchy the host can still change after validation, whatever the host wrote the hierarchy as.
  it.each(
    (['roles.hierarchy', 'roles.platformHierarchy', 'workspaces.roles.hierarchy'] as const).flatMap(
      (which) =>
        (['an object', 'a function that carries the roles', 'an array of lists'] as const).map(
          (form) => [which, form] as const
        )
    )
  )('copies %s written as %s, and a later change by the host does not reach it', (which, form) => {
    const roles = which === 'workspaces.roles.hierarchy' ? ['owner', 'editor'] : ['MEMBER', 'OTHER']
    const keys = form === 'an array of lists' ? ['0', '1'] : roles
    const children = (role: string): string[] => (role === keys[0] ? [keys[1] as string] : [])
    const written: Record<string, string[]> = Object.fromEntries(
      keys.map((role) => [role, children(role)])
    )
    const hierarchy: unknown =
      form === 'an object'
        ? written
        : form === 'an array of lists'
          ? keys.map((role) => children(role))
          : Object.assign(() => undefined, written)
    const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
      jwt: { secret: SECRET },
      rateLimit: { clientIpSource: 'peer' },
      roles:
        which === 'workspaces.roles.hierarchy'
          ? { hierarchy: { MEMBER: [] } }
          : which === 'roles.hierarchy'
            ? { hierarchy }
            : { hierarchy: { MEMBER: [] }, platformHierarchy: hierarchy },
      ...(which === 'roles.platformHierarchy' ? { platform: { enabled: true } } : {}),
      ...(which === 'workspaces.roles.hierarchy'
        ? { workspaces: { enabled: true, roles: { hierarchy, ownerRole: keys[0] } } }
        : {})
    }

    const resolved = resolveOptions(given as BymaxAuthModuleOptions)
    const held =
      which === 'roles.hierarchy'
        ? resolved.roles.hierarchy
        : which === 'roles.platformHierarchy'
          ? resolved.roles.platformHierarchy
          : resolved.workspaces?.roles.hierarchy
    const before = JSON.stringify(held)
    const host = hierarchy as Record<string, string[]>
    host['ADDED'] = []
    host[keys[0] as string]?.push('ADDED')

    expect(JSON.stringify(held)).toBe(before)
    expect(Array.isArray(held)).toBe(false)
    expect(typeof held).toBe('object')
  })

  // Scenario: the workspaces written as a function that carries the settings and the roles, and the host changing the
  // roles of the hierarchy after the options resolved. Expected: the options resolve as they do with an object, and the
  // change does not reach them. Why: the options are a group like any other and a function is accepted as one.
  it('copies the workspaces written as a function, and a later change by the host does not reach it', () => {
    const hierarchy: Record<string, string[]> = { owner: ['editor'], editor: [] }
    const workspaces = Object.assign(() => undefined, {
      enabled: true,
      roles: { hierarchy, ownerRole: 'owner' }
    })
    const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
      jwt: { secret: SECRET },
      roles: { hierarchy: { MEMBER: [] } },
      rateLimit: { clientIpSource: 'peer' },
      workspaces
    }

    const resolved = resolveOptions(given as BymaxAuthModuleOptions)
    hierarchy['ADDED'] = []
    hierarchy['editor']?.push('owner')

    expect(resolved.workspaces?.roles.hierarchy).toEqual({ owner: ['editor'], editor: [] })
  })
})
