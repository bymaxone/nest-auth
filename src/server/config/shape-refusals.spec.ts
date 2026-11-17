/**
 * @fileoverview An option that is `null`, a symbol or a bigint is refused by name, with the type and
 * never the content.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const MFA_KEY = Buffer.alloc(32, 7).toString('base64')
const WORKSPACE_ROLES = { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }

/** Options built from what the case sets, read back as the type a typed call would refuse. */
function options(extra: Record<string, unknown>): BymaxAuthModuleOptions {
  const built = {
    jwt: { secret: SECRET },
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...extra
  }
  return built as BymaxAuthModuleOptions
}

/** The message `resolveOptions` throws for the options, or a failure when it does not throw. */
function refusal(given: BymaxAuthModuleOptions): { type: string; message: string } {
  try {
    resolveOptions(given)
  } catch (error) {
    if (error instanceof Error) return { type: error.constructor.name, message: error.message }
  }
  return { type: 'none', message: '' }
}

describe('a value that cannot be read is refused by name', () => {
  // Scenario: each option holding a value its reader cannot use. Expected: a plain Error that names the
  // option and the type received.
  it.each([
    ['oauth.google', { oauth: { google: null } }, 'oauth.google must be an object (received null)'],
    [
      'roles.hierarchy.ADMIN',
      { roles: { hierarchy: { ADMIN: null } } },
      "roles.hierarchy['ADMIN'] must be an array (received null)"
    ],
    [
      'workspaces.permissions.manageWorkspace',
      {
        workspaces: {
          enabled: true,
          roles: WORKSPACE_ROLES,
          permissions: { manageWorkspace: null }
        }
      },
      'workspaces.permissions.manageWorkspace must be an array (received null)'
    ],
    [
      'workspaces.permissions.viewMembers',
      {
        workspaces: { enabled: true, roles: WORKSPACE_ROLES, permissions: { viewMembers: 'owner' } }
      },
      'workspaces.permissions.viewMembers must be an array (received a string)'
    ],
    [
      'jwt.refreshExpiresInDays symbol',
      { jwt: { secret: SECRET, refreshExpiresInDays: Symbol('x') } },
      'jwt.refreshExpiresInDays must be a positive finite number. It received a symbol'
    ],
    [
      'jwt.refreshExpiresInDays bigint',
      { jwt: { secret: SECRET, refreshExpiresInDays: 7n } },
      'jwt.refreshExpiresInDays must be a positive finite number. It received a bigint'
    ],
    [
      'mfa.totpWindow symbol',
      { mfa: { encryptionKey: MFA_KEY, issuer: 'x', totpWindow: Symbol('x') } },
      '2N + 1 codes would be valid at once'
    ],
    [
      'mfa.totpWindow bigint',
      { mfa: { encryptionKey: MFA_KEY, issuer: 'x', totpWindow: 1n } },
      'mfa.totpWindow must be between 0 and'
    ],
    [
      'jwt.refreshGraceWindowSeconds symbol',
      { jwt: { secret: SECRET, refreshGraceWindowSeconds: Symbol('x') } },
      'jwt.refreshGraceWindowSeconds must be between 0 and 300 inclusive (received a symbol)'
    ],
    [
      'jwt.refreshGraceWindowSeconds huge bigint',
      { jwt: { secret: SECRET, refreshGraceWindowSeconds: 10n ** 30n } },
      'jwt.refreshGraceWindowSeconds must be between 0 and 300 inclusive (received a bigint)'
    ],
    [
      'jwt.refreshGraceWindowSeconds date',
      { jwt: { secret: SECRET, refreshGraceWindowSeconds: new Date(1e15) } },
      'jwt.refreshGraceWindowSeconds must be between 0 and 300 inclusive (received an object)'
    ]
  ])('%s', (_name, extra, message) => {
    const result = refusal(options(extra))

    expect(result.type).toBe('Error')
    expect(result.message).toContain(message)
  })

  // Scenario: a credential pasted into an option that holds a string. Expected: the refusal never contains it.
  it.each([
    ['rateLimit.clientIpSource', { rateLimit: { clientIpSource: 'hunter2-secret' } }],
    [
      'oauth.successRedirectUrl',
      { oauth: { successRedirectUrl: 'http://u:hunter2-secret@x.test/p' } }
    ],
    ['oauth.mfaRedirectUrl', { oauth: { mfaRedirectUrl: 'http://u:hunter2-secret@x.test/p' } }],
    ['oauth.errorRedirectUrl', { oauth: { errorRedirectUrl: 'http://u:hunter2-secret@x.test/p' } }],
    [
      'oauth.google.callbackUrl',
      {
        oauth: {
          google: {
            clientId: 'a',
            clientSecret: 'b',
            callbackUrl: 'http://u:hunter2-secret@x.test/p'
          }
        }
      }
    ]
  ])('%s is refused without quoting the value', (_name, extra) => {
    const result = refusal(options({ ...extra, environment: 'production' }))

    expect(result.type).toBe('Error')
    expect(result.message).not.toContain('hunter2-secret')
  })

  // Scenario: the platform role map set to null with the platform on. Expected: refused by name.
  it('roles.platformHierarchy null is refused by name', () => {
    const result = refusal(
      options({
        roles: { hierarchy: { A: [] }, platformHierarchy: null },
        platform: { enabled: true }
      })
    )

    expect(result.message).toContain('roles.platformHierarchy is required when platform.enabled')
  })
})
