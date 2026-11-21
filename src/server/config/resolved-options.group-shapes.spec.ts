/**
 * @fileoverview Every way a host can write the group that holds a role hierarchy, against every such group: the options
 * resolve as they do for an object literal, every key of the group survives, and each getter is read once.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'kT3vQ8mZp1Lx9RwYb6NcHs2EdUo7GfJa5VnMiXq4tBeKy0AzWr'

type Values = Record<string, unknown>

/** The ways a host writes a group, each built from the same values; a getter counts its reads under its key. */
const SHAPES = {
  'an object literal': (values: Values): Values => ({ ...values }),
  'an object with no prototype': (values: Values): Values =>
    Object.assign(Object.create(null) as Values, values),
  'a class with the keys as fields': (values: Values): Values => {
    class Fields {
      constructor() {
        Object.assign(this, values)
      }
    }
    return new Fields() as Values
  },
  'a class with getters on its prototype': (
    values: Values,
    reads: Record<string, number> = {}
  ): Values => {
    class Getters {}
    for (const [key, value] of Object.entries(values))
      Object.defineProperty(Getters.prototype, key, {
        get(): unknown {
          reads[key] = (reads[key] ?? 0) + 1
          return value
        }
      })
    return new Getters() as Values
  },
  'an object with own getters': (values: Values, reads: Record<string, number> = {}): Values => {
    const group: Values = {}
    for (const [key, value] of Object.entries(values))
      Object.defineProperty(group, key, {
        enumerable: true,
        get(): unknown {
          reads[key] = (reads[key] ?? 0) + 1
          return value
        }
      })
    return group
  }
} as const

const ACCOUNT = {
  hierarchy: { MEMBER: [] },
  platformHierarchy: { SUPER_ADMIN: ['SUPPORT'], SUPPORT: [] }
}
const WORKSPACE = { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }

/** The options for a group written in a shape, and what it resolved to. */
function resolveWith(
  group: 'roles' | 'workspaces.roles',
  shape: keyof typeof SHAPES,
  reads: Record<string, number>
) {
  const written =
    group === 'roles'
      ? { roles: SHAPES[shape](ACCOUNT, reads), platform: { enabled: true } }
      : {
          roles: { hierarchy: { MEMBER: [] } },
          workspaces: { enabled: true, roles: SHAPES[shape](WORKSPACE, reads) }
        }
  const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
    jwt: { secret: SECRET },
    rateLimit: { clientIpSource: 'peer' },
    ...written
  }
  return resolveOptions(given as BymaxAuthModuleOptions)
}

describe('the group that holds a role hierarchy, in every way a host can write it', () => {
  // Scenario: the roles of the account (with the platform hierarchy) and the roles of the workspaces (with the owner
  // role), each written as a literal, with no prototype, as a class with fields, as a class with getters on its
  // prototype and as an object with own getters. Expected: every key of the group survives and equals what the literal
  // gave, the hierarchy is a copy of what the host holds, and each getter of the host was read exactly once. Why: a copy
  // that carried only own keys, or read a getter twice, would drop an option the host wrote or let a later read differ.
  it.each(
    (['roles', 'workspaces.roles'] as const).flatMap((group) =>
      (Object.keys(SHAPES) as (keyof typeof SHAPES)[]).map((shape) => [group, shape] as const)
    )
  )('%s written as %s resolves like a literal and reads each getter once', (group, shape) => {
    const reads: Record<string, number> = {}
    const resolved = resolveWith(group, shape, reads)
    const expected = group === 'roles' ? ACCOUNT : WORKSPACE
    const held: Values =
      group === 'roles'
        ? {
            hierarchy: resolved.roles.hierarchy,
            platformHierarchy: resolved.roles.platformHierarchy
          }
        : { ...resolved.workspaces?.roles }

    expect(held).toEqual(expected)
    for (const key of Object.keys(reads)) expect([key, reads[key]]).toEqual([key, 1])
    if (shape.includes('getters'))
      expect(Object.keys(reads).sort()).toEqual(Object.keys(expected).sort())
    expect(held['hierarchy']).not.toBe(expected.hierarchy)
  })

  // Scenario: each group that holds a hierarchy written as a function that carries the keys, as an array, as a string and
  // as a number. Expected: each is refused by shape, naming the group and what it was. Why: a function or an array is no
  // group of settings, so it is not read by property and not copied; it is refused before anything reads it.
  it.each(
    (['roles', 'workspaces', 'workspaces.roles'] as const).flatMap((group) =>
      (
        [
          ['a function', Object.assign(() => undefined, ACCOUNT)],
          ['an array', [ACCOUNT]],
          ['a string', 'roles'],
          ['7', 7]
        ] as const
      ).map(([what, value]) => [group, what, value] as const)
    )
  )('refuses %s written as %s', (group, what, value) => {
    const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
      jwt: { secret: SECRET },
      rateLimit: { clientIpSource: 'peer' },
      roles: group === 'roles' ? value : { hierarchy: { MEMBER: [] } },
      ...(group === 'workspaces' ? { workspaces: value } : {}),
      ...(group === 'workspaces.roles' ? { workspaces: { enabled: true, roles: value } } : {})
    }

    expect(() => resolveOptions(given as BymaxAuthModuleOptions)).toThrow(
      `${group} must be an object (received ${what})`
    )
  })
})
