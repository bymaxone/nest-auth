/**
 * @fileoverview The lists a host writes into its options (the permissions of the workspaces, the retired secrets, the
 * retired keys of the second factor and the scopes of the API keys) are read from the host once, and what the library
 * checks is what it keeps: a later change by the host, or a getter that answers differently the second time, reaches
 * nothing.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const JWT_SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const RETIRED_SECRET = 'Zt8#vB3@nM6$qL9%wE2^rY5&uI1*oP4(aS7)dF0!gH'
const MFA_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
const MFA_OLD_KEY = 'q83vEjRWeJz9k2LmP4xYcB7nTuH1sA6dF0gVoXiQwKY='
const PEPPER = 'pQ3$rT6&uW9*xZ2!aC5%dF8^gJ1(kM4)nP7+sV0-yB'

const WORKSPACE_ROLES = { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }

type Written = Partial<Record<keyof BymaxAuthModuleOptions, unknown>>

/** Valid options, with the groups under test given by the case. */
function optionsWith(extra: Written): BymaxAuthModuleOptions {
  const given: Written = {
    jwt: { secret: JWT_SECRET },
    roles: { hierarchy: { MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...extra
  }
  return given as BymaxAuthModuleOptions
}

/** The options with the workspaces enabled and the given permissions. */
function withPermissions(permissions: unknown): BymaxAuthModuleOptions {
  return optionsWith({ workspaces: { enabled: true, roles: WORKSPACE_ROLES, permissions } })
}

describe('the permissions of the workspaces', () => {
  // Scenario: the permissions written as a class whose four lists are getters on its prototype, one of them naming a role
  // that does not exist. Expected: the options are refused naming the permission. Why: a permission is an authorization
  // table; a list the validation never read would grant a role nobody checked.
  it('validates lists that a class serves on its prototype', () => {
    class Permissions {
      get manageMembers(): string[] {
        return ['ghost']
      }
    }

    expect(() => resolveOptions(withPermissions(new Permissions()))).toThrow(
      'workspaces.permissions.manageMembers names a role at position 0 that is not a workspace role'
    )
  })

  // Scenario: each of the four lists served as a getter on the prototype of a class and naming a role that does not
  // exist. Expected: the options are refused naming that permission. Why: each of the four is read by name from the
  // class, and a list the validation never read would grant a role nobody checked.
  it.each(['manageWorkspace', 'deleteWorkspace', 'manageMembers', 'viewMembers'] as const)(
    'validates %s when a class serves it on its prototype',
    (action) => {
      class Permissions {}
      Object.defineProperty(Permissions.prototype, action, { get: (): string[] => ['ghost'] })

      expect(() => resolveOptions(withPermissions(new Permissions()))).toThrow(
        `workspaces.permissions.${action} names a role at position 0 that is not a workspace role`
      )
    }
  )

  // Scenario: valid permissions, then the host pushing a role that does not exist into one of its lists and replacing
  // another after the options resolved. Expected: the resolved permissions are what was validated. Why: the lists are the
  // host's own arrays, and a change after validation must never become a grant.
  it('holds a copy of the lists, and a later change by the host does not reach it', () => {
    const manageMembers = ['editor']
    const permissions: Record<string, string[]> = { manageMembers }

    const resolved = resolveOptions(withPermissions(permissions))
    manageMembers.push('ghost')
    permissions['manageMembers'] = ['ghost']

    expect(resolved.workspaces?.permissions.manageMembers).toEqual(['editor'])
  })

  // Scenario: each of the four lists of the permissions, changed by the host after the options resolved. Expected: the
  // resolved list is what was validated. Why: each of the four decides a different action, and each is kept the same way.
  it.each(['manageWorkspace', 'deleteWorkspace', 'manageMembers', 'viewMembers'] as const)(
    'holds a copy of %s',
    (action) => {
      const list = ['editor']

      const resolved = resolveOptions(withPermissions({ [action]: list }))
      list.push('ghost')

      expect(resolved.workspaces?.permissions[action]).toEqual(['editor'])
    }
  )

  // Scenario: every list a getter that counts its reads and answers a role that does not exist from the second read on.
  // Expected: each getter is read once and the options resolve from the first answer. Why: what is validated and what is
  // kept must be the same read.
  it('reads each list once', () => {
    const reads: Record<string, number> = {}
    const permissions: Record<string, string[]> = {}
    for (const action of ['manageWorkspace', 'deleteWorkspace', 'manageMembers', 'viewMembers'])
      Object.defineProperty(permissions, action, {
        enumerable: true,
        get(): string[] {
          reads[action] = (reads[action] ?? 0) + 1
          return reads[action] === 1 ? ['owner'] : ['ghost']
        }
      })

    const resolved = resolveOptions(withPermissions(permissions))
    void resolved.workspaces?.permissions.manageMembers

    expect(reads).toEqual({
      manageWorkspace: 1,
      deleteWorkspace: 1,
      manageMembers: 1,
      viewMembers: 1
    })
    expect(resolved.workspaces?.permissions.manageMembers).toEqual(['owner'])
  })

  // Scenario: the permissions written as a function, an array, a string and a number. Expected: each is refused by shape,
  // naming the option and what it was. Why: a function or an array is no group of settings.
  it.each([
    ['a function', Object.assign(() => undefined, { manageMembers: ['owner'] }), 'a function'],
    ['an array', [['owner']], 'an array'],
    ['a string', 'owner', 'a string'],
    ['a number', 7, '7']
  ] as const)('refuses the permissions written as %s', (_name, value, received) => {
    expect(() => resolveOptions(withPermissions(value))).toThrow(
      `workspaces.permissions must be an object (received ${received})`
    )
  })
})

describe('the lists of retired secrets and keys and the scopes of the API keys', () => {
  // Scenario: each list written in the options, then the host pushing an entry into it after the options resolved.
  // Expected: the resolved list is what was validated. Why: the retired secrets verify tokens, the retired keys open the
  // second factor and the scopes decide what a key may do, and the strength and format checks ran once, at the start.
  it.each([
    [
      'jwt.previousSecrets',
      (list: string[]): BymaxAuthModuleOptions =>
        optionsWith({ jwt: { secret: JWT_SECRET, previousSecrets: list } }),
      (resolved: ReturnType<typeof resolveOptions>): unknown => resolved.jwt.previousSecrets,
      [RETIRED_SECRET]
    ],
    [
      'apiKeys.scopes',
      (list: string[]): BymaxAuthModuleOptions =>
        optionsWith({ apiKeys: { enabled: true, pepper: PEPPER, scopes: list } }),
      (resolved: ReturnType<typeof resolveOptions>): unknown => resolved.apiKeys.scopes,
      ['read']
    ],
    [
      'mfa.previousEncryptionKeys',
      (list: string[]): BymaxAuthModuleOptions =>
        optionsWith({
          mfa: { encryptionKey: MFA_KEY, previousEncryptionKeys: list, issuer: 'App' }
        }),
      (resolved: ReturnType<typeof resolveOptions>): unknown =>
        resolved.mfa?.previousEncryptionKeys,
      [MFA_OLD_KEY]
    ]
  ] as const)(
    'copies %s, and a later change by the host does not reach it',
    (_name, write, read, entries) => {
      const list: string[] = [...entries]

      const resolved = resolveOptions(write(list))
      list.push('not-validated')
      list[0] = 'replaced'

      expect(read(resolved)).toEqual(entries)
    }
  )

  // Scenario: the groups that hold those lists (jwt, mfa, apiKeys) written as a function, an array, a string and a number.
  // Expected: each is refused by shape, naming the group and what it was. Why: a function or an array is no group of
  // settings, and the lists in it are copied out of the plain object the options are read into.
  it.each(
    (['jwt', 'mfa', 'apiKeys'] as const).flatMap((group) =>
      (
        [
          ['a function', Object.assign(() => undefined, { secret: JWT_SECRET }), 'a function'],
          ['an array', [JWT_SECRET], 'an array'],
          ['a string', 'secret', 'a string'],
          ['a number', 7, '7']
        ] as const
      ).map(([what, value, received]) => [group, what, value, received] as const)
    )
  )('refuses %s written as %s', (group, _what, value, received) => {
    expect(() => resolveOptions(optionsWith({ [group]: value }))).toThrow(
      `${group} must be an object (received ${received})`
    )
  })
})
