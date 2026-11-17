/**
 * @fileoverview An option that holds `undefined` or `null` is unset, and an unset option means its
 * default, never "no bound". A spread of the defaults and the user's group lets an own key holding
 * `undefined` override the default, so `{ sessions: { defaultMaxSessions: undefined } }` (what
 * `Number(process.env.X) || undefined` produces) switched the session cap off.
 *
 * @layer Test
 */

import { DEFAULT_OPTIONS } from './default-options'
import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const KEY = Buffer.alloc(32, 7).toString('base64')

/** Options with `value` at `group.key`, and whatever the group needs in order to resolve. */
function build(group: string, key: string, value: unknown): BymaxAuthModuleOptions {
  const needs: Record<string, unknown> = group === 'mfa' ? { encryptionKey: KEY, issuer: 'x' } : {}
  const jwt = group === 'jwt' ? { secret: SECRET, [key]: value } : { secret: SECRET }
  const rest = group === 'jwt' ? {} : { [group]: { ...needs, [key]: value } }
  const options: Record<string, unknown> = {
    jwt,
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...rest
  }
  if (!isOptions(options)) throw new Error('the base options lost a required group')
  return options
}

/** Whether the built object still carries the three groups every module configuration needs. */
function isOptions(
  value: Record<string, unknown>
): value is Record<string, unknown> & BymaxAuthModuleOptions {
  return 'jwt' in value && 'roles' in value && 'rateLimit' in value
}

/** The resolved value of `group.key`. */
function resolvedValue(options: BymaxAuthModuleOptions, group: string, key: string): unknown {
  const resolved: unknown = resolveOptions(options)
  const section: unknown = Reflect.get(Object(resolved), group)
  return Reflect.get(Object(section), key)
}

const GROUPS = [
  'jwt',
  'password',
  'sessions',
  'bruteForce',
  'passwordReset',
  'emailVerification',
  'platform',
  'emailChange',
  'invitations',
  'controllers',
  'mfa'
] as const

/** Every (group, key, default) the module ships, except the keys a group cannot take unset. */
const CASES = GROUPS.flatMap((group) =>
  Object.entries(DEFAULT_OPTIONS[group] as Record<string, unknown>).map(
    ([key, fallback]) => [group, key, fallback] as const
  )
)

describe('an unset option means its default', () => {
  // Scenario: every defaulted option of every group held as an own key with `undefined`. Expected:
  // the default, as if the key were absent.
  it.each(CASES)('%s.%s: an explicit undefined resolves to the default', (group, key, fallback) => {
    expect(resolvedValue(build(group, key, undefined), group, key)).toEqual(fallback)
  })

  // Scenario: the same with `null`. Expected: the same, because null reads as unset everywhere.
  it.each(CASES)('%s.%s: null resolves to the default', (group, key, fallback) => {
    expect(resolvedValue(build(group, key, null), group, key)).toEqual(fallback)
  })

  // Scenario: the two caps that the bug switched off. Expected: the cap is the default, not absent.
  it('keeps the session cap and the absolute lifetime when they are set to undefined', () => {
    const sessions = resolveOptions(build('sessions', 'defaultMaxSessions', undefined))
    const lifetime = resolveOptions(build('jwt', 'absoluteSessionLifetimeDays', undefined))

    expect(sessions.sessions.defaultMaxSessions).toBe(5)
    expect(lifetime.jwt.absoluteSessionLifetimeDays).toBe(30)
  })

  // Scenario: a value read from an environment variable the way hosts do. Expected: an unset variable
  // gives the default and a set one is used.
  it('treats Number(env) || undefined as unset when the variable is absent', () => {
    const fromEnv = (raw: string | undefined): number | undefined => Number(raw) || undefined

    const absent = resolveOptions(build('sessions', 'defaultMaxSessions', fromEnv(undefined)))
    const present = resolveOptions(build('sessions', 'defaultMaxSessions', fromEnv('7')))

    expect(absent.sessions.defaultMaxSessions).toBe(5)
    expect(present.sessions.defaultMaxSessions).toBe(7)
  })

  // Scenario: the workspace settings and the top-level status cache TTL held as null or undefined.
  // Expected: each reads as unset and resolves to its default.
  it.each([undefined, null])(
    'resolves the workspace settings and the status cache from %s',
    (unset) => {
      const options = {
        ...build('sessions', 'enabled', undefined),
        userStatusCacheTtlSeconds: unset,
        workspaces: {
          enabled: true,
          roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' },
          maxWorkspacesPerUser: unset,
          invitationTtlSeconds: unset,
          maxPendingInvitationsPerWorkspace: unset,
          membershipCacheTtlSeconds: unset,
          deletionGraceDays: unset,
          accessDeniedEvents: { max: unset, windowSeconds: unset }
        }
      }
      if (!isOptions(options)) throw new Error('the base options lost a required group')

      const resolved = resolveOptions(options)

      expect(resolved.userStatusCacheTtlSeconds).toBe(60)
      expect(resolved.workspaces).toMatchObject({
        maxWorkspacesPerUser: 0,
        invitationTtlSeconds: 604_800,
        maxPendingInvitationsPerWorkspace: 100,
        membershipCacheTtlSeconds: 60,
        deletionGraceDays: 14,
        accessDeniedEvents: { max: 10, windowSeconds: 60 }
      })
    }
  )
})
