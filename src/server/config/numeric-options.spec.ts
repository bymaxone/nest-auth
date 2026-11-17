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
  bruteForce: { bruteForce: {} },
  password: { password: {} },
  workspaces: {
    workspaces: {
      enabled: true,
      roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }
    }
  },
  apiKeys: {
    apiKeys: {
      enabled: true,
      pepper: 'Zt8#vB3@nM6$qL9%wE2^rY5&uI1*oP4(aS7)dF0!gH',
      scopes: ['read']
    }
  },
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
  ["'3'", '3'],
  ['1e300', 1e300],
  ['MAX_VALUE', Number.MAX_VALUE]
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
  {
    path: 'jwt.accessCookieMaxAgeMs',
    accepts: [1, 900_000, 315_360_000_000],
    refusesAlso: [315_360_000_001, 2 ** 53]
  },
  {
    path: 'jwt.absoluteSessionLifetimeDays',
    accepts: [0, 1 / 24, 1, 30, 3650],
    tolerates: ['0', '1.5'],
    refusesAlso: [3651, 0.01]
  },
  {
    path: 'jwt.refreshExpiresInDays',
    accepts: [1, 1.5, 7, 3650],
    tolerates: ['1.5'],
    refusesAlso: [3651, 1.1, 0.0001]
  },
  { path: 'bruteForce.windowSeconds', accepts: [1, 900, 604_800], refusesAlso: [604_801, 2 ** 53] },
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
  { path: 'sessions.defaultMaxSessions', accepts: [1, 5, 1000], refusesAlso: [1001, 2 ** 53] },
  {
    path: 'passwordReset.tokenTtlSeconds',
    accepts: [1, 600, 315_360_000],
    refusesAlso: [315_360_001, 2 ** 53]
  },
  {
    path: 'passwordReset.otpTtlSeconds',
    accepts: [1, 600, 315_360_000],
    refusesAlso: [315_360_001, 2 ** 53]
  },
  {
    path: 'emailVerification.otpTtlSeconds',
    accepts: [1, 600, 315_360_000],
    refusesAlso: [315_360_001, 2 ** 53]
  },
  {
    path: 'emailChange.tokenTtlSeconds',
    accepts: [1, 3600, 315_360_000],
    refusesAlso: [315_360_001, 2 ** 53]
  },
  {
    path: 'invitations.tokenTtlSeconds',
    accepts: [1, 172_800, 315_360_000],
    refusesAlso: [315_360_001, 2 ** 53]
  },
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
      /sessions\.defaultMaxSessions must be a whole number between 1 and 1000 inclusive/
    )
  })

  // Scenario: the absolute lifetime given NaN or a negative. Expected: refused, and 0 switches
  // the cap off. Why: `NaN <= 0` is false and `age > NaN` is false, so NaN would skip the cap without
  // being asked to.
  it('refuses a NaN or negative absolute lifetime and keeps 0 as the way to switch it off', () => {
    expect(() => resolveOptions(optionsWith('jwt.absoluteSessionLifetimeDays', NaN))).toThrow(
      /jwt\.absoluteSessionLifetimeDays must be 0 or between/
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

  // Scenario: each refusal, with the explanation it ends on. Expected: the message carries the whole
  // explanation, because it is what tells an operator why a value that looks harmless is refused.
  it.each([
    [
      'jwt.accessCookieMaxAgeMs',
      0,
      'It is the cookie Max-Age; zero deletes the cookie and NaN is ignored by the browser, so the session would end with the tab.'
    ],
    [
      'sessions.defaultMaxSessions',
      NaN,
      'It caps concurrent sessions: with NaN the comparison is false in both directions, no session is ever evicted, and the cap does not exist.'
    ],
    [
      'passwordReset.tokenTtlSeconds',
      0,
      'It is a Redis expiry in seconds: zero or a negative deletes the record as it is written, and NaN, a fraction, Infinity or a value past what Redis can hold is refused by Redis on every request.'
    ],
    [
      'userStatusCacheTtlSeconds',
      3601,
      'It is how long a suspended account keeps passing the dashboard guards, so it has a ceiling.'
    ],
    [
      'jwt.absoluteSessionLifetimeDays',
      NaN,
      '(current: NaN). Only 0 switches the cap off; NaN, a negative or a value so large that its length in milliseconds overflows would skip it without being asked to, and a value under an hour ends every session at its first rotation after that age, minutes after login. Set 0 to accept unbounded sessions deliberately.'
    ],
    [
      'passwordReset.otpLength',
      NaN,
      'degrade user experience. The value must also be a whole number: a comparison with NaN is false both ways, so a bound written as a range alone lets it through.'
    ],
    ['mfa.totpWindow', NaN, 'is never silently clamped. It must be a whole number.'],
    ['mfa.recoveryCodeCount', NaN, 'authenticator is lost. The count must be a whole number.'],
    [
      'jwt.refreshExpiresInDays',
      1.1,
      'It is also at most 3650 days, and its length in seconds must be a whole number, because Redis takes an integer expiry: 1.1 days is 95040.00000000001 s.'
    ],
    [
      'jwt.refreshGraceWindowSeconds',
      NaN,
      'The window is how long an already-consumed refresh token recovers a session, so it is exactly the replay window for a stolen one. It covers a client that rotated but never received the response — a retry, not a policy. 0 disables grace recovery entirely. The value must be a whole number: Redis takes an integer expiry, so a fraction or NaN would fail every rotation.'
    ]
  ])('explains the refusal of %s', (path, value, explanation) => {
    expect(() => resolveOptions(optionsWith(path, value))).toThrow(explanation)
  })

  // Scenario: a lifetime so long that days * 86_400_000 overflows to Infinity. Expected: refused. Why: with
  // an Infinity lifetime `age > lifetime` is never true, so the absolute cap would be off again.
  it.each([1e306, Number.MAX_VALUE, 3651])('refuses an absolute lifetime of %s days', (days) => {
    expect(() => resolveOptions(optionsWith('jwt.absoluteSessionLifetimeDays', days))).toThrow(
      /jwt\.absoluteSessionLifetimeDays must be 0 or between/
    )
  })

  // Scenario: a Redis TTL of 1e300 seconds, which Number.isInteger accepts. Expected: refused at boot.
  // Why: Redis answers "invalid expire time" to an expiry past its 64-bit millisecond range, on every request.
  it('refuses a TTL beyond what Redis can hold, which is also an integer', () => {
    expect(() => resolveOptions(optionsWith('passwordReset.tokenTtlSeconds', 1e300))).toThrow(
      /passwordReset\.tokenTtlSeconds must be a whole number between 1 and 315360000 inclusive/
    )
  })

  // Scenario: every other numeric option, handed values past any range. Expected: refused at boot.
  // Why: `Number.isInteger(1e300)` is true, so an option whose check has no ceiling takes it, and the
  // expiry, the memory or the comparison it feeds then fails or is skipped.
  it.each([
    'password.costFactor',
    'password.minLength',
    'password.blockSize',
    'password.parallelization',
    'bruteForce.maxAttempts',
    'workspaces.maxWorkspacesPerUser',
    'workspaces.invitationTtlSeconds',
    'workspaces.maxPendingInvitationsPerWorkspace',
    'workspaces.membershipCacheTtlSeconds',
    'workspaces.deletionGraceDays',
    'workspaces.accessDeniedEvents.max',
    'workspaces.accessDeniedEvents.windowSeconds',
    'apiKeys.lastUsedFlushSeconds'
  ])('refuses 1e300, MAX_VALUE and 2 ** 53 for %s', (path) => {
    for (const value of [1e300, Number.MAX_VALUE, 2 ** 53]) {
      expect(() => resolveOptions(optionsWith(path, value))).toThrow(
        path.split('.').pop() as string
      )
    }
  })

  // Scenario: the scrypt parallelism at and just over its ceiling. Expected: 16 resolves, 17 is refused.
  it('bounds password.parallelization at 16', () => {
    expect(() => resolveOptions(optionsWith('password.parallelization', 16))).not.toThrow()
    expect(() => resolveOptions(optionsWith('password.parallelization', 17))).toThrow(
      "password.parallelization must be at most 16 (current: 17). scrypt's CPU cost grows linearly with it and an unauthenticated login derives a hash even for an address that does not exist."
    )
  })
})
