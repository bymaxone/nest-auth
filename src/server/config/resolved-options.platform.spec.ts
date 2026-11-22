/**
 * @fileoverview The hierarchy of the platform is judged as the other hierarchies are: when the platform is enabled it is
 * an object that names at least one role, whose children are lists of roles it declares.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'kT3vQ8mZp1Lx9RwYb6NcHs2EdUo7GfJa5VnMiXq4tBeKy0AzWr'

/** Valid options with the platform in the given state and the given platform hierarchy. */
function platformWith(platformHierarchy: unknown, enabled = true): BymaxAuthModuleOptions {
  const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
    jwt: { secret: SECRET },
    rateLimit: { clientIpSource: 'peer' },
    roles: { hierarchy: { MEMBER: [] }, platformHierarchy },
    platform: { enabled }
  }
  return given as BymaxAuthModuleOptions
}

describe('roles.platformHierarchy', () => {
  // Scenario: the platform enabled and the hierarchy a string, a number and true. Expected: each is refused as no object,
  // naming what it was. Why: the hierarchy of the platform decides who may do what to the whole
  // platform, and a value that is no hierarchy must not be kept because it is truthy.
  it.each([
    ['a string', 'SUPER_ADMIN', 'a string'],
    ['a number', 5, '5'],
    ['true', true, 'a boolean']
  ] as const)('is refused when it is %s', (_name, value, received) => {
    expect(() => resolveOptions(platformWith(value))).toThrow(
      `roles.platformHierarchy must be an object (received ${received})`
    )
  })

  // Scenario: the hierarchy an empty object, a function that carries no role and an array of lists (read as roles named by
  // their index); a role whose children are a string, a number, null and an object; a role that
  // names a child it does not declare. Expected: each is refused naming the role. Why: the same integrity the hierarchy of
  // the account has: every child is a role the hierarchy declares.
  it.each([
    ['is an empty object', {}, 'roles.platformHierarchy must not be an empty object'],
    [
      'is a function that carries no role',
      () => undefined,
      'roles.platformHierarchy must not be an empty object'
    ],
    [
      'is an array of lists whose children name no index',
      [['SUPPORT']],
      "roles.platformHierarchy['0'] references unknown role 'SUPPORT'"
    ],
    [
      'has a role whose children are a string',
      { SUPER_ADMIN: 'SUPPORT', SUPPORT: [] },
      "roles.platformHierarchy['SUPER_ADMIN'] must be an array (received a string)"
    ],
    [
      'has a role whose children are a number',
      { SUPER_ADMIN: 7, SUPPORT: [] },
      "roles.platformHierarchy['SUPER_ADMIN'] must be an array (received 7)"
    ],
    [
      'has a role whose children are null',
      { SUPER_ADMIN: null, SUPPORT: [] },
      "roles.platformHierarchy['SUPER_ADMIN'] must be an array (received null)"
    ],
    [
      'has a role whose children are an object',
      { SUPER_ADMIN: { SUPPORT: true }, SUPPORT: [] },
      "roles.platformHierarchy['SUPER_ADMIN'] must be an array (received an object)"
    ],
    [
      'names a child it does not declare',
      { SUPER_ADMIN: ['GHOST'], SUPPORT: [] },
      "roles.platformHierarchy['SUPER_ADMIN'] references unknown role 'GHOST'"
    ]
  ] as const)('is refused when it %s', (_name, value, message) => {
    expect(() => resolveOptions(platformWith(value))).toThrow(message)
  })

  // Scenario: a valid hierarchy, and the platform disabled with a value that is no hierarchy. Expected: the valid one
  // resolves as a copy, and nothing is checked while the platform is off. Why: the hierarchy is judged where the platform
  // is switched on, and it is a copy the host cannot change later.
  it('resolves a valid hierarchy, and is not judged while the platform is off', () => {
    const written = { SUPER_ADMIN: ['SUPPORT'], SUPPORT: [] }

    const resolved = resolveOptions(platformWith(written))
    written.SUPER_ADMIN.push('GHOST')

    expect(resolved.roles.platformHierarchy).toEqual({ SUPER_ADMIN: ['SUPPORT'], SUPPORT: [] })
    expect(() => resolveOptions(platformWith('not a hierarchy', false))).not.toThrow()
  })
})
