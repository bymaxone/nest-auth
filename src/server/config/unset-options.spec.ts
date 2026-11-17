/**
 * @fileoverview An option that holds `undefined` or `null` is unset, and an unset option means its
 * default, never "no bound": `{ sessions: { defaultMaxSessions: undefined } }`, which is what
 * `Number(process.env.X) || undefined` produces, keeps the default session cap.
 *
 * @layer Test
 */

import { runInNewContext } from 'node:vm'

import { DEFAULT_OPTIONS } from './default-options'
import { resolveOptions } from './resolved-options'
import { dropUnset } from './unset-options'
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

/** A value read back as the type a test needs it to be, for options a typed call would refuse. */
function untyped<T>(value: unknown): T {
  return value as T
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

  // Scenario: the two caps an unset value must not remove. Expected: the cap is the default, not absent.
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

  // Scenario: an option group that is a plain data bag of another shape: no prototype (what several
  // configuration parsers return) or made in another realm. Expected: its unset keys are dropped too,
  // so the cap is the default.
  it.each([
    [
      'no prototype',
      () => Object.assign(Object.create(null), { enabled: true, defaultMaxSessions: undefined })
    ],
    ['another realm', () => runInNewContext('({ enabled: true, defaultMaxSessions: undefined })')]
  ])('drops the unset keys of a group with %s', (_label, make) => {
    const options = { ...build('sessions', 'enabled', true), sessions: make() }
    if (!isOptions(options)) throw new Error('the base options lost a required group')

    expect(resolveOptions(options).sessions.defaultMaxSessions).toBe(5)
  })

  // Scenario: a host-defined map holding null: an OAuth provider block. Expected: refused, never
  // silently dropped, because a provider that vanishes before its fields are checked leaves OAuth
  // requests failing at runtime.
  it.each([null, undefined])('refuses an OAuth provider block that is %s', (block) => {
    const options = { ...build('sessions', 'enabled', undefined), oauth: { google: block } }
    if (!isOptions(options)) throw new Error('the base options lost a required group')

    expect(() => resolveOptions(options)).toThrow()
  })

  describe('dropUnset', () => {
    /** The options a call needs beyond the group under test. */
    const withGroup = (name: string, value: unknown): BymaxAuthModuleOptions => ({
      jwt: { secret: SECRET },
      roles: { hierarchy: {} },
      rateLimit: { enabled: false },
      ...{ [name]: value }
    })

    // Scenario: every fixed-key group, holding an unset key beside a set one. Expected: the unset key is
    // gone from each, the set key is kept: the allowlist names every group.
    it.each([
      'jwt',
      'password',
      'cookies',
      'sessions',
      'bruteForce',
      'passwordReset',
      'emailVerification',
      'platform',
      'invitations',
      'emailChange',
      'controllers',
      'rateLimit',
      'mfa',
      'apiKeys',
      'workspaces'
    ])('cleans the %s group', (name) => {
      const cleaned = dropUnset(withGroup(name, { unset: undefined, nothing: null, kept: 1 }))

      expect(Reflect.get(cleaned, name)).toEqual({ kept: 1 })
    })

    // Scenario: a host-defined map holding null, and a group named like none of the fixed ones.
    // Expected: left exactly as given.
    it.each(['oauth', 'roles', 'somethingElse'])('leaves the %s map as given', (name) => {
      const cleaned = dropUnset(withGroup(name, { entry: null }))

      expect(Reflect.get(cleaned, name)).toEqual({ entry: null })
    })

    // Scenario: a fixed-key group given something that cannot be a group. Expected: kept as it is, the same
    // value for a scalar, an array or a function.
    it('leaves a value that cannot be a group untouched', () => {
      const fn = (): number => 1
      const values = ['text', 7, true, ['x'], fn]

      for (const value of values) {
        expect(Reflect.get(dropUnset(withGroup('controllers', value)), 'controllers')).toBe(value)
      }
    })

    // Scenario: a group that is a class instance, with a getter on its prototype, a field that holds
    // `undefined` and one that holds `null`. Expected: read into a plain object with the getter's value
    // and the set field, and without the unset ones, so a typed configuration class is read like a literal.
    it('reads a class instance by property access', () => {
      class Settings {
        enabled = true
        defaultMaxSessions: number | undefined = undefined
        maxSessionsResolver = null
        get ignored(): string {
          return 'unknown key, not an own property'
        }
      }
      const cleaned = dropUnset(withGroup('sessions', new Settings()))
      const group = Reflect.get(cleaned, 'sessions')

      expect(group).toEqual({ enabled: true })
      expect(Object.getPrototypeOf(group)).toBe(Object.prototype)
    })

    // Scenario: a class whose getter supplies a known key. Expected: the getter's value is read.
    it('reads a known key that is a getter on the prototype', () => {
      class Settings {
        get defaultMaxSessions(): number {
          return 3
        }
      }

      expect(Reflect.get(dropUnset(withGroup('sessions', new Settings())), 'sessions')).toEqual({
        defaultMaxSessions: 3
      })
    })

    // Scenario: an own enumerable getter for a known key, whose value changes on each read. Expected: read
    // exactly once, so the value the host's getter first returns is the one that is configured.
    it('reads a known own getter once', () => {
      let reads = 0
      const sessions = {}
      Object.defineProperty(sessions, 'defaultMaxSessions', {
        enumerable: true,
        get: () => (++reads === 1 ? 2 : undefined)
      })

      const cleaned = dropUnset(withGroup('sessions', sessions))

      expect(reads).toBe(1)
      expect(Reflect.get(cleaned, 'sessions')).toEqual({ defaultMaxSessions: 2 })
    })

    // Scenario: the options themselves are a class instance, as a typed configuration class produces.
    // Expected: the same cleaning, getters included.
    it('reads options that are a class instance', () => {
      class AppOptions {
        jwt = { secret: SECRET }
        roles = { hierarchy: {} }
        rateLimit = { enabled: false }
        sessions = { enabled: true, defaultMaxSessions: undefined }
        get environment(): string {
          return 'test'
        }
      }
      const cleaned = dropUnset(untyped<BymaxAuthModuleOptions>(new AppOptions()))

      expect(Reflect.get(cleaned, 'sessions')).toEqual({ enabled: true })
      expect(Reflect.get(cleaned, 'environment')).toBe('test')
    })

    // Scenario: `workspaces` without either sub-group, with a non-object sub-group, and with both.
    // Expected: no error, and only the two named sub-groups are cleaned.
    it('cleans the workspaces sub-groups only when they are plain groups', () => {
      const absent = dropUnset(withGroup('workspaces', { enabled: true }))
      const scalar = dropUnset(withGroup('workspaces', { accessDeniedEvents: 3 }))
      const both = dropUnset(
        withGroup('workspaces', {
          accessDeniedEvents: { max: undefined, windowSeconds: 5 },
          invitations: { accountStatus: null, other: 1 }
        })
      )

      expect(Reflect.get(absent, 'workspaces')).toEqual({ enabled: true })
      expect(Reflect.get(scalar, 'workspaces')).toEqual({ accessDeniedEvents: 3 })
      expect(Reflect.get(both, 'workspaces')).toEqual({
        accessDeniedEvents: { windowSeconds: 5 },
        invitations: { other: 1 }
      })
    })

    // Scenario: a group that is not `workspaces` and holds keys named like its sub-groups. Expected: only
    // the group's own unset keys are dropped; what it holds under those names is left as given.
    it('does not look for sub-groups outside workspaces', () => {
      const cleaned = dropUnset(
        withGroup('sessions', {
          invitations: { keep: undefined },
          accessDeniedEvents: { keep: null }
        })
      )

      expect(Reflect.get(cleaned, 'sessions')).toEqual({
        invitations: { keep: undefined },
        accessDeniedEvents: { keep: null }
      })
    })
  })

  // Scenario: a typed configuration class as a group, the common Nest pattern, with a field that is
  // undefined. Expected: the default cap applies, as it does for an object literal.
  it('keeps the session cap and the absolute lifetime when their groups are class instances', () => {
    class SessionSettings {
      enabled = true
      defaultMaxSessions: number | undefined = undefined
    }
    class JwtSettings {
      secret = SECRET
      absoluteSessionLifetimeDays: number | undefined = undefined
    }
    const options = {
      ...build('sessions', 'enabled', true),
      sessions: new SessionSettings(),
      jwt: new JwtSettings()
    }
    if (!isOptions(options)) throw new Error('the base options lost a required group')

    const resolved = resolveOptions(options)

    expect(resolved.sessions.defaultMaxSessions).toBe(5)
    expect(resolved.jwt.absoluteSessionLifetimeDays).toBe(30)
  })
})
