/**
 * @fileoverview Tests for the `identifierKey` option of resolveOptions(): the secret the Redis
 * identifiers derive from, which defaults to `jwt.secret` and is never used to sign or verify.
 * Covers the unchanged default derivation, a pinned key surviving a `jwt.secret` rotation, every
 * name family built on the key, and the validation of the option.
 */

import { createHash } from 'node:crypto'

import { recentAuthKey } from '../constants/recent-auth'
import { sessionIndexKey, tokenEpochKey } from '../constants/user-keys'
import { userSubject } from '../constants/user-subject'
import { hmacSha256 } from '../crypto/secure-token'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import { resolveOptions } from './resolved-options'

/** A high-entropy secret, deterministic so a failure reproduces. */
const VALID_SECRET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv'

/** A second, unrelated high-entropy secret, used as the key the identifiers derive from. */
const IDENTIFIER_KEY = 'Zt8#vB3@nM6$qL9%wE2^rY5&uI1*oP4(aS7)dF0!gH'

const MINIMAL_OPTIONS: BymaxAuthModuleOptions = {
  jwt: { secret: VALID_SECRET },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  rateLimit: { clientIpSource: 'peer' }
}

describe('resolveOptions — identifierKey', () => {
  const NEW_SECRET = 'Qw3$eR6%tY9&uI2*oP5(aS8)dF1!gH4@jK7zXcVbNm'

  /** The key the identifiers derive from, computed the way the library documents it. */
  const derive = (secret: string): string =>
    createHash('sha256').update(`bymax-auth:hmac-key:v1:${secret}`, 'utf8').digest('hex')

  // Scenario: no identifierKey. Expected: the key is the derivation from jwt.secret that every
  // deployment has run so far, byte for byte, pinned by the known-answer vector the Rust port
  // carries as well. Why: a default that moved would rename every identifier on upgrade.
  it('derives the identifier key from jwt.secret exactly as before when identifierKey is absent', () => {
    const secret = '0123456789abcdef0123456789abcdef'

    const resolved = resolveOptions({ ...MINIMAL_OPTIONS, jwt: { secret } })

    expect(resolved.hmacKey).toBe(
      '0dd66555bd2d89e0eb4ce050f1fef427bea6799bec27fb8e313f69ab965048c1'
    )
  })

  // Scenario: identifierKey set to the current jwt.secret. Expected: the same key as leaving it
  // out. Why: that is the step that makes a later rotation safe, so it must move nothing.
  it('derives the same key from an identifierKey equal to the current jwt.secret', () => {
    const pinned = resolveOptions({ ...MINIMAL_OPTIONS, identifierKey: VALID_SECRET })
    const unpinned = resolveOptions(MINIMAL_OPTIONS)

    expect(pinned.hmacKey).toBe(unpinned.hmacKey)
  })

  // Scenario: the signing secret changes while identifierKey stays. Expected: hmacKey does not
  // move. Why: this is the property the option exists for.
  it('keeps hmacKey fixed when jwt.secret changes and identifierKey is pinned', () => {
    const before = resolveOptions({ ...MINIMAL_OPTIONS, identifierKey: VALID_SECRET })
    const after = resolveOptions({
      ...MINIMAL_OPTIONS,
      jwt: { secret: NEW_SECRET, previousSecrets: [VALID_SECRET] },
      identifierKey: VALID_SECRET
    })

    expect(after.hmacKey).toBe(before.hmacKey)
  })

  // Scenario: a different identifierKey. Expected: a different key, derived with the same label.
  // Why: choosing a new value is how a rotation cuts the link to the old secret.
  it('derives a different key from a different identifierKey, with the same derivation', () => {
    const resolved = resolveOptions({ ...MINIMAL_OPTIONS, identifierKey: IDENTIFIER_KEY })

    expect(resolved.hmacKey).toBe(derive(IDENTIFIER_KEY))
    expect(resolved.hmacKey).not.toBe(resolveOptions(MINIMAL_OPTIONS).hmacKey)
  })

  // Scenario: previous secrets listed. Expected: previousHmacKeys still derive from them and
  // not from identifierKey. Why: they exist to read recovery-code digests written under a
  // retired signing secret, which identifierKey does not change.
  it('keeps previousHmacKeys derived from jwt.previousSecrets', () => {
    const resolved = resolveOptions({
      ...MINIMAL_OPTIONS,
      jwt: { secret: VALID_SECRET, previousSecrets: [NEW_SECRET] },
      identifierKey: IDENTIFIER_KEY
    })

    expect(resolved.previousHmacKeys).toEqual([derive(NEW_SECRET)])
  })

  // Scenario: an identifierKey that is too weak. Expected: the same refusal jwt.secret gets,
  // naming the option. Why: it is key material for every identifier, so it clears the same bar.
  it.each([
    ['empty', '', /identifierKey is required and must not be empty/],
    ['short', 'short', /identifierKey must be at least 32 characters long/],
    ['repetitive', 'a'.repeat(40), /identifierKey has insufficient entropy/]
  ])('should refuse an identifierKey that is %s', (_why, identifierKey, message) => {
    expect(() => resolveOptions({ ...MINIMAL_OPTIONS, identifierKey })).toThrow(message)
  })

  // Scenario: a non-string value from a loosely typed config source. Expected: the descriptive
  // error rather than a raw TypeError.
  it('should refuse an identifierKey that is not a string', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      identifierKey: 12345
    } as unknown as BymaxAuthModuleOptions

    expect(() => resolveOptions(options)).toThrow(/identifierKey must be a string/)
  })

  // Scenario: identifierKey is explicitly undefined (an unset environment variable passed
  // through). Expected: treated as absent, like every other optional option.
  it('should treat an undefined identifierKey as absent', () => {
    const options = {
      ...MINIMAL_OPTIONS,
      identifierKey: undefined
    } as unknown as BymaxAuthModuleOptions
    const resolved = resolveOptions(options)

    expect(resolved.hmacKey).toBe(resolveOptions(MINIMAL_OPTIONS).hmacKey)
  })
  // Scenario: one name from every family that derives from the key, built the way the services
  // build it, before and after a rotation. Expected: each is identical with identifierKey
  // pinned and each is different without it. Why: a family that reads the signing secret
  // directly instead of `hmacKey` would move on rotation while this option claims it does not.
  describe('identifier families across a rotation', () => {
    const families: Array<[string, (hmacKey: string) => string]> = [
      ['session index', (k) => sessionIndexKey('dashboard', 'user-1', k, 'tenant-1')],
      ['platform session index', (k) => sessionIndexKey('platform', 'admin-1', k, undefined)],
      ['token epoch', (k) => tokenEpochKey('dashboard', 'user-1', k, 'tenant-1')],
      ['platform token epoch', (k) => tokenEpochKey('platform', 'admin-1', k, undefined)],
      ['recent-authentication marker', (k) => recentAuthKey('dashboard', 'user-1', k, 'tenant-1')],
      [
        'MFA setup and lock keys',
        (k) =>
          `mfa_setup:${hmacSha256(userSubject('dashboard', 'user-1', 'tenant-1'), k)}` +
          `|mfalock:${hmacSha256(userSubject('dashboard', 'user-1', 'tenant-1'), k)}`
      ],
      ['OTP identifier', (k) => hmacSha256('tenant-1:person@example.com', k)],
      ['rate-limit bucket', (k) => `rl:login:${hmacSha256('203.0.113.7', k)}`]
    ]

    const keysOf = (options: BymaxAuthModuleOptions): string[] => {
      const { hmacKey } = resolveOptions(options)
      return families.map(([, build]) => build(hmacKey))
    }
    const before = { ...MINIMAL_OPTIONS, identifierKey: VALID_SECRET }
    const rotated = {
      ...MINIMAL_OPTIONS,
      jwt: { secret: NEW_SECRET, previousSecrets: [VALID_SECRET] }
    }

    it.each(families.map(([name], index) => [name, index] as const))(
      'keeps the %s name fixed when identifierKey is pinned',
      (_name, index) => {
        expect(keysOf({ ...rotated, identifierKey: VALID_SECRET })[index]).toBe(
          keysOf(before)[index]
        )
      }
    )

    it.each(families.map(([name], index) => [name, index] as const))(
      'moves the %s name on rotation when identifierKey is not set',
      (_name, index) => {
        expect(keysOf(rotated)[index]).not.toBe(keysOf(MINIMAL_OPTIONS)[index])
      }
    )
  })
})
