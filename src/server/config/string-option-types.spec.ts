/**
 * @fileoverview A text option, a list of text or a group of settings given a value of another type is
 * refused by name, with the type and never the content, and never as a raw `TypeError`.
 *
 * @layer Test
 */

import { resolveOptions } from './resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'

/** Options built from what the case sets, read back as the type a typed call would refuse. */
function options(extra: Record<string, unknown>): BymaxAuthModuleOptions {
  const built = {
    roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
    rateLimit: { clientIpSource: 'peer' },
    ...extra,
    jwt: { secret: SECRET, ...(extra['jwt'] as object | undefined) }
  }
  return built as BymaxAuthModuleOptions
}

/** The error `resolveOptions` throws for the options, or a failure when it does not throw. */
function refusal(given: BymaxAuthModuleOptions): { type: string; message: string } {
  try {
    resolveOptions(given)
  } catch (error) {
    if (error instanceof Error) return { type: error.constructor.name, message: error.message }
  }
  return { type: 'none', message: '' }
}

describe('jwt.accessExpiresIn that is not text', () => {
  // Scenario: a number, boolean, object or array where a time span string belongs. Expected: the same
  // named refusal an unreadable string gets, a plain Error, never a `TypeError` from reading `.trim`.
  it.each([
    ['a number', 900, '900'],
    ['NaN', Number.NaN, 'NaN'],
    ['a boolean', true, 'a boolean'],
    ['an object', { minutes: 15 }, 'an object'],
    ['an array', ['15m'], 'an array'],
    ['a symbol', Symbol('15m'), 'a symbol'],
    ['a bigint', 900n, 'a bigint']
  ])('refuses %s by name and type', (_case, accessExpiresIn, type) => {
    const result = refusal(options({ jwt: { accessExpiresIn } }))

    expect(result.type).toBe('Error')
    expect(result.message).toContain('jwt.accessExpiresIn must be a time span')
    expect(result.message).toContain(`Received ${type}.`)
  })
})

/** Values of every type a text option can wrongly receive, with how the refusal names them. */
const WRONG_TYPES: ReadonlyArray<[string, unknown, string]> = [
  ['a number', 5, '5'],
  ['a boolean', true, 'a boolean'],
  ['an object', {}, 'an object'],
  ['an array', ['x'], 'an array'],
  ['a function', () => 'x', 'a function'],
  ['a symbol', Symbol('x'), 'a symbol'],
  ['a bigint', 5n, 'a bigint']
]

/** The group each text option lives in, and the key, so a case can build the options for it. */
const TEXT_PATHS: ReadonlyArray<[string, Record<string, unknown>]> = [
  ['jwt.issuer', { jwt: { issuer: undefined } }],
  ['jwt.audience', { jwt: { audience: undefined } }],
  ['cookies.accessTokenName', { cookies: {} }],
  ['cookies.refreshTokenName', { cookies: {} }],
  ['cookies.sessionSignalName', { cookies: {} }],
  ['cookies.refreshCookiePath', { cookies: {} }],
  ['cookies.mfaTempCookiePath', { cookies: {} }],
  ['mfa.issuer', { mfa: { encryptionKey: Buffer.alloc(32, 7).toString('base64') } }],
  ['apiKeys.pepper', { apiKeys: {} }],
  ['redisNamespace', {}],
  ['routePrefix', {}]
]

/** Options with the value set at the dotted path inside the base the path needs. */
function withValue(
  path: string,
  base: Record<string, unknown>,
  value: unknown
): BymaxAuthModuleOptions {
  const [head, key] = path.split('.')
  if (key === undefined) return options({ ...base, [head as string]: value })
  const group = { ...(base[head as string] as object), [key]: value }
  return options({ ...base, [head as string]: group })
}

describe('a text option that is not text', () => {
  // Scenario: every text option given each wrong type. Expected: a plain Error naming the option and
  // the type received, never a `TypeError` and never the content.
  describe.each(TEXT_PATHS)('%s', (path, base) => {
    it.each(WRONG_TYPES)('refuses %s by name and type', (_case, value, received) => {
      const result = refusal(withValue(path, base, value))

      expect(result.type).toBe('Error')
      expect(result.message).toBe(
        `[BymaxAuthModule] ${path} must be a string (received ${received}).`
      )
    })
  })
})

describe('a list of text that is not a list of text', () => {
  const LISTS: ReadonlyArray<[string, Record<string, unknown>]> = [
    ['blockedStatuses', {}],
    ['cookies.trustedOrigins', { cookies: {} }],
    ['password.blocklist', { password: {} }]
  ]

  // Scenario: a string where the list belongs (`'evil'` reads as no list at all and would be accepted),
  // and a list holding something that is not text. Expected: refused by option name, naming the type
  // and for an entry its position, never the content.
  describe.each(LISTS)('%s', (path, base) => {
    it('refuses a string', () => {
      const result = refusal(withValue(path, base, 'evil'))

      expect(result.type).toBe('Error')
      expect(result.message).toBe(
        `[BymaxAuthModule] ${path} must be an array of strings (received a string).`
      )
    })

    it('refuses an entry that is not text and names its position', () => {
      const result = refusal(withValue(path, base, ['ok', 7]))

      expect(result.message).toBe(
        `[BymaxAuthModule] ${path} must contain only strings (entry 1 is 7).`
      )
    })
  })
})

describe('a group of settings that is not an object', () => {
  // Scenario: each group given a string, which every reader sees as empty and silently ignores.
  // Expected: refused by name, with the type and never the content.
  it.each([
    'password',
    'cookies',
    'sessions',
    'bruteForce',
    'passwordReset',
    'emailVerification',
    'platform',
    'invitations',
    'emailChange',
    'oauth'
  ])('refuses a string, an array and a function for %s', (group) => {
    const received: ReadonlyArray<[unknown, string]> = [
      ['secret-not-an-object', 'a string'],
      [[], 'an array'],
      [() => ({}), 'a function']
    ]
    for (const [value, type] of received) {
      const result = refusal(options({ [group]: value }))

      expect(result.type).toBe('Error')
      expect(result.message).toBe(
        `[BymaxAuthModule] ${group} must be an object (received ${type}).`
      )
    }
  })
})
