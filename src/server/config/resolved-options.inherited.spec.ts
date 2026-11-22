/**
 * @fileoverview An option the host did not write is the default, however the runtime's own object is dressed: a key
 * planted on `Object.prototype` (by a library with a prototype-pollution flaw, say) is not an option. Only what the host
 * wrote, on the object or on the class it is an instance of, is read.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const MFA_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
const PEPPER = 'pQ3$rT6&uW9*xZ2!aC5%dF8^gJ1(kM4)nP7+sV0-yB'

type Written = Partial<Record<keyof BymaxAuthModuleOptions, unknown>>

/** Valid options in which the keys under test are not written. */
function options(extra: Written = {}): BymaxAuthModuleOptions {
  const given: Written = {
    jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
    roles: { hierarchy: { MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...extra
  }
  return given as BymaxAuthModuleOptions
}

/** Runs `body` with `key` planted on the shared prototype of every plain object, and always takes it away again. */
function withPlanted<T>(key: string, value: unknown, body: () => T): T {
  Object.defineProperty(Object.prototype, key, {
    value,
    configurable: true,
    enumerable: false,
    writable: true
  })
  try {
    return body()
  } finally {
    Reflect.deleteProperty(Object.prototype, key)
  }
}

/** Every key of the options, with a value that would change a default or enable a feature if it were read. */
const TOP_LEVEL: readonly (readonly [string, unknown])[] = [
  ['jwt', { secret: 'attacker-chosen-secret-0123456789abcdefghij' }],
  ['mfa', { encryptionKey: MFA_KEY, issuer: 'x' }],
  ['sessions', { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }],
  ['bruteForce', { maxAttempts: 1000000, windowSeconds: 1 }],
  ['passwordReset', { method: 'otp', otpTtlSeconds: 3600 }],
  ['emailVerification', { required: false }],
  ['platform', { enabled: true }],
  ['emailChange', { enabled: true }],
  ['invitations', { enabled: true }],
  ['apiKeys', { enabled: true, pepper: PEPPER }],
  ['oauth', { google: { clientId: 'a', clientSecret: 'b', callbackUrl: 'https://x.example/cb' } }],
  ['workspaces', { enabled: true }],
  ['password', { minLength: 1 }],
  ['cookies', { names: {} }],
  ['controllers', { auth: false }],
  ['tokenDelivery', 'bearer'],
  ['enforceTenantBinding', false],
  ['secureCookies', false],
  ['environment', 'development'],
  ['registration', 'closed'],
  ['routePrefix', 'x'],
  ['blockedStatuses', []],
  ['redisNamespace', 'zz'],
  ['userStatusCacheTtlSeconds', 1],
  ['identifierKey', 'x'],
  ['tenantIdResolver', () => 'planted'],
  ['isTrustedProxy', () => true]
]

describe('a key planted on Object.prototype', () => {
  // Scenario: each top-level option planted on Object.prototype with a value that would enable a feature, weaken a check
  // or change a default, and options that do not write it. Expected: the options resolve exactly as they do with nothing
  // planted. Why: a planted key reached every option the host left unwritten, so a flaw elsewhere that pollutes the
  // prototype could switch on invitations or sessions, turn off the verification of the email, or empty the blocked statuses.
  it.each(TOP_LEVEL)('does not become the option %s', (key, value) => {
    const baseline = resolveOptions(options())

    const planted = withPlanted(key, value, () => {
      const resolved = resolveOptions(options())
      return { json: JSON.stringify(resolved), read: Reflect.get(resolved, key) }
    })

    expect(planted.json).toBe(JSON.stringify(baseline))
    expect(planted.read).toEqual(Reflect.get(baseline, key))
  })

  // Scenario: a key of a group planted on Object.prototype and a group the host wrote without it. Expected: the group
  // resolves with its default. Why: the keys of a group are read like the groups themselves.
  it.each([
    ['sessions', 'enabled', true],
    ['invitations', 'enabled', true],
    ['emailChange', 'enabled', true],
    ['emailVerification', 'required', false],
    ['passwordReset', 'method', 'otp'],
    ['bruteForce', 'maxAttempts', 1000],
    ['cookies', 'sameSite', 'none']
  ] as const)('does not become the key %s.%s of a group', (group, key, value) => {
    const written: Written = {
      [group]: { ...(group === 'sessions' ? { defaultMaxSessions: 5 } : {}) }
    }
    const baseline = resolveOptions(options(written))

    const planted = withPlanted(key, value, () => {
      const resolved = resolveOptions(options(written))
      return {
        json: JSON.stringify(resolved),
        read: Reflect.get(Reflect.get(resolved, group), key)
      }
    })

    expect(planted.json).toBe(JSON.stringify(baseline))
    expect(planted.read).toEqual(Reflect.get(Reflect.get(baseline, group), key))
  })

  // Scenario: the same options written as an instance of a class that serves its settings on its prototype. Expected: they
  // are still read. Why: the planted key is ignored because it is not the host's; a class the host wrote is the host's.
  it('still reads a key a class serves on its prototype', () => {
    class Sessions {
      get enabled(): boolean {
        return true
      }
      get defaultMaxSessions(): number {
        return 7
      }
    }

    const resolved = resolveOptions(options({ sessions: new Sessions() }))

    expect(resolved.sessions).toMatchObject({ enabled: true, defaultMaxSessions: 7 })
  })
})
