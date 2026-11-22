/**
 * @fileoverview A child in a role hierarchy is a role name, a string. One that is anything else is refused naming what it
 * is, and nothing it carries runs: a boot error is logged, and printing an object runs its `toString`.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'kT3vQ8mZp1Lx9RwYb6NcHs2EdUo7GfJa5VnMiXq4tBeKy0AzWr'

/** Valid options whose account and platform hierarchies are the given ones. */
function withHierarchies(hierarchy: unknown, platformHierarchy: unknown): BymaxAuthModuleOptions {
  const given: Partial<Record<keyof BymaxAuthModuleOptions, unknown>> = {
    jwt: { secret: SECRET },
    rateLimit: { clientIpSource: 'peer' },
    roles: { hierarchy, platformHierarchy },
    platform: { enabled: true }
  }
  return given as BymaxAuthModuleOptions
}

const VALID = { ADMIN: ['MEMBER'], MEMBER: [] }

/** Each hierarchy, with how to write the child in it and the path its message names. */
const HIERARCHIES = [
  ['roles.hierarchy', (child: unknown) => withHierarchies({ ADMIN: [child], MEMBER: [] }, VALID)],
  [
    'roles.platformHierarchy',
    (child: unknown) => withHierarchies(VALID, { ADMIN: [child], MEMBER: [] })
  ]
] as const

describe('a child in a role hierarchy', () => {
  // Scenario: the child of a role written as a number, null, undefined, a boolean, a bigint, a symbol, a function, an
  // array and an object whose `toString` throws, in the hierarchy of the accounts and in the one of the platform.
  // Expected: each is refused naming the path, what it received and its position, and no `toString` of it runs. Why: a
  // child is a role name; interpolating the value would run a method the host wrote, or throw a TypeError from a symbol.
  it.each(
    HIERARCHIES.flatMap(([path, write]) =>
      (
        [
          ['a number', 7, '7'],
          ['null', null, 'null'],
          ['undefined', undefined, 'undefined'],
          ['a boolean', true, 'a boolean'],
          ['a bigint', 1n, 'a bigint'],
          ['a symbol', Symbol('MEMBER'), 'a symbol'],
          ['a function', () => 'MEMBER', 'a function'],
          ['an array', ['MEMBER'], 'an array'],
          [
            'an object whose toString throws',
            {
              toString: (): string => {
                throw new Error('host toString ran')
              }
            },
            'an object'
          ]
        ] as const
      ).map(([what, child, received]) => [path, what, write(child), received] as const)
    )
  )('in %s refuses a child that is %s', (_path, _what, options, received) => {
    expect(() => resolveOptions(options)).toThrow(
      `must name roles as strings (received ${received} at position 0)`
    )
  })

  // Scenario: a child that is a string no role declares, in each hierarchy. Expected: the existing refusal naming the
  // role is kept. Why: the check on the kind comes first and must not replace the check on the declaration.
  it.each(HIERARCHIES)('keeps refusing a string nobody declares in %s', (path, write) => {
    expect(() => resolveOptions(write('GHOST'))).toThrow(
      `${path}['ADMIN'] references unknown role 'GHOST'`
    )
  })
})
