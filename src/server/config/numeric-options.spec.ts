/**
 * @fileoverview Every numeric option, handed NaN, Infinity, a negative, zero, a fraction and a
 * numeric string at boot. A value that cannot name a count, a lifetime or a window is refused where
 * the module starts, because a comparison with `NaN` is false in both directions, so a bound written
 * as `x < min || x > max` accepts it and the bound it was meant to enforce is gone.
 *
 * @layer Test
 */

import { MAX_VERIFY_WINDOW } from '../crypto/totp'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import { resolveOptions } from './resolved-options'

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const KEY = Buffer.alloc(32, 7).toString('base64')

const BASE: Record<string, unknown> = {
  jwt: { secret: SECRET },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  rateLimit: { clientIpSource: 'peer' }
}

/** The group a feature option needs switched on before its value is read. */
const GROUPS: Record<string, Record<string, unknown>> = {
  mfa: { mfa: { encryptionKey: KEY, issuer: 'x' } },
  sessions: { sessions: { enabled: true } },
  passwordReset: { passwordReset: { method: 'token' } },
  emailVerification: { emailVerification: { required: true } },
  emailChange: { emailChange: {} },
  invitations: { invitations: { enabled: true } }
}

/** Options with `value` set at `path`, a dotted path whose first segment names the group. */
function optionsWith(path: string, value: unknown): BymaxAuthModuleOptions {
  const parts = path.split('.')
  const options: Record<string, unknown> = structuredClone({
    ...BASE,
    ...GROUPS[parts[0] as string]
  })
  let node = options
  for (const part of parts.slice(0, -1)) {
    node[part] = { ...((node[part] as Record<string, unknown> | undefined) ?? {}) }
    node = node[part] as Record<string, unknown>
  }
  node[parts[parts.length - 1] as string] = value
  return options as unknown as BymaxAuthModuleOptions
}

/** The six values an option can arrive as from JSON, an environment variable or untyped JavaScript. */
const HOSTILE: [string, unknown][] = [
  ['NaN', NaN],
  ['Infinity', Infinity],
  ['-1', -1],
  ['0', 0],
  ['1.5', 1.5],
  ["'3'", '3']
]

interface Rule {
  path: string
  /** Values the option takes. */
  accepts: unknown[]
  /** The hostile values from the table it takes anyway (a zero that means "off", a fraction of days). */
  tolerates?: string[]
  /** Further values outside its range, beside the table. */
  refusesAlso?: unknown[]
}

const RULES: Rule[] = [
  { path: 'jwt.accessCookieMaxAgeMs', accepts: [1, 900_000] },
  { path: 'jwt.absoluteSessionLifetimeDays', accepts: [0, 1, 30], tolerates: ['0', '1.5'] },
  {
    path: 'jwt.refreshGraceWindowSeconds',
    accepts: [0, 30, 300],
    tolerates: ['0'],
    refusesAlso: [301]
  },
  {
    path: 'mfa.totpWindow',
    accepts: [0, 1, MAX_VERIFY_WINDOW],
    tolerates: ['0'],
    refusesAlso: [MAX_VERIFY_WINDOW + 1]
  },
  { path: 'mfa.recoveryCodeCount', accepts: [1, 8, 50], refusesAlso: [51] },
  { path: 'passwordReset.otpLength', accepts: [4, 6, 8], refusesAlso: [3, 9] },
  { path: 'sessions.defaultMaxSessions', accepts: [1, 5, 1000] },
  { path: 'passwordReset.tokenTtlSeconds', accepts: [1, 600] },
  { path: 'passwordReset.otpTtlSeconds', accepts: [1, 600] },
  { path: 'emailVerification.otpTtlSeconds', accepts: [1, 600] },
  { path: 'emailChange.tokenTtlSeconds', accepts: [1, 3600] },
  { path: 'invitations.tokenTtlSeconds', accepts: [1, 172_800] },
  { path: 'userStatusCacheTtlSeconds', accepts: [1, 60, 3600], refusesAlso: [3601] }
]

describe('numeric options at boot', () => {
  describe.each(RULES)('$path', ({ path, accepts, tolerates = [], refusesAlso = [] }) => {
    // Scenario: values inside the option's range. Expected: the module resolves.
    it.each(accepts.map((value) => [String(value), value]))('takes %s', (_label, value) => {
      expect(() => resolveOptions(optionsWith(path, value))).not.toThrow()
    })

    // Scenario: each hostile value. Expected: refused at boot, naming the option, unless the option
    // gives that value a meaning (zero switching a cap off, a fraction of a day).
    it.each(HOSTILE.filter(([label]) => !tolerates.includes(label)))(
      'refuses %s',
      (_label, value) => {
        expect(() => resolveOptions(optionsWith(path, value))).toThrow(path)
      }
    )

    // Scenario: a whole number outside the range. Expected: refused at boot.
    if (refusesAlso.length > 0) {
      it.each(refusesAlso.map((value) => [String(value), value]))(
        'refuses %s beyond the table',
        (_label, value) => {
          expect(() => resolveOptions(optionsWith(path, value))).toThrow(path)
        }
      )
    }
  })

  // Scenario: the session cap given NaN. Expected: refused. Why: `length <= NaN` is false and
  // `slice(0, NaN)` is empty, so with NaN as the limit no session is ever evicted and the cap does not exist.
  it('refuses a NaN session cap, which would evict no session', () => {
    expect(() => resolveOptions(optionsWith('sessions.defaultMaxSessions', NaN))).toThrow(
      /sessions\.defaultMaxSessions must be a whole number of at least 1/
    )
  })

  // Scenario: the absolute lifetime given NaN or a negative. Expected: refused, and 0 switches
  // the cap off. Why: `NaN <= 0` is false and `age > NaN` is false, so NaN would skip the cap without
  // being asked to.
  it('refuses a NaN or negative absolute lifetime and keeps 0 as the way to switch it off', () => {
    expect(() => resolveOptions(optionsWith('jwt.absoluteSessionLifetimeDays', NaN))).toThrow(
      /jwt\.absoluteSessionLifetimeDays must be 0 or a positive finite number/
    )
    expect(() => resolveOptions(optionsWith('jwt.absoluteSessionLifetimeDays', -1))).toThrow(
      /jwt\.absoluteSessionLifetimeDays/
    )
    expect(
      resolveOptions(optionsWith('jwt.absoluteSessionLifetimeDays', 0)).jwt
        .absoluteSessionLifetimeDays
    ).toBe(0)
  })

  // Scenario: the status cache ceiling. Expected: 3600 seconds is the most a suspended account can keep passing.
  it('names the ceiling of the status cache in its refusal', () => {
    expect(() => resolveOptions(optionsWith('userStatusCacheTtlSeconds', 3601))).toThrow(
      /userStatusCacheTtlSeconds must be a whole number between 1 and 3600/
    )
  })
})
