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
})
