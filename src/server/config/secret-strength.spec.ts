/**
 * @fileoverview Tests for the secret strength check and the length floor it shares with every secret
 * option.
 *
 * @layer Test
 */

import { AUTH_SECRET_MIN_LENGTH, validateSecretStrength } from './secret-strength'
import { resolveOptions } from './resolved-options'

/**
 * A secret of an exact length made of distinct characters, so its entropy clears the floor for any
 * length up to 62.
 *
 * @param length - The length.
 * @returns The secret.
 */
function secretOf(length: number): string {
  return 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.slice(0, length)
}

describe('the secret length floor', () => {
  // Scenario: the floor itself. Expected: 32, the number the template's environment schema holds.
  it('is 32', () => {
    expect(AUTH_SECRET_MIN_LENGTH).toBe(32)
  })

  // Scenario: a secret one character under the floor, then exactly at it. Expected: refused naming
  // the option and the floor, then accepted, so the boundary is the constant and no copy of it.
  it('refuses a secret one under the floor and accepts one at it', () => {
    expect(() =>
      validateSecretStrength(secretOf(AUTH_SECRET_MIN_LENGTH - 1), 'jwt.secret')
    ).toThrow(`jwt.secret must be at least ${AUTH_SECRET_MIN_LENGTH} characters long`)
    expect(() =>
      validateSecretStrength(secretOf(AUTH_SECRET_MIN_LENGTH), 'jwt.secret')
    ).not.toThrow()
  })

  // Scenario: a signing secret of 31 characters at boot, the case an environment schema with a floor
  // of 32 refuses first. Expected: the module refuses it too, with the same floor in its message.
  it('refuses a 31-character jwt.secret at boot', () => {
    expect(() =>
      resolveOptions({
        jwt: { secret: secretOf(31) },
        roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
        rateLimit: { clientIpSource: 'peer' }
      })
    ).toThrow('jwt.secret must be at least 32 characters long')
  })
})

describe('a retired signing secret that fails the strength rules', () => {
  // Scenario: a weak entry at a position past the first. Expected: the error names
  // `jwt.previousSecrets[index]` and not `jwt.secret`. Why: the operator fixes the variable the
  // message names, and one naming the current secret leaves the retired entry broken.
  it.each([
    ['too short', secretOf(AUTH_SECRET_MIN_LENGTH - 1), /previousSecrets\[1\] must be at least 32/],
    ['empty', '', /previousSecrets\[1\] is required and must not be empty/],
    ['low entropy', 'a'.repeat(40), /previousSecrets\[1\] has insufficient entropy/]
  ])('names the retired entry when it is %s', (_why, weak, message) => {
    const attempt = (): unknown =>
      resolveOptions({
        jwt: {
          secret: secretOf(48),
          previousSecrets: [secretOf(40).split('').reverse().join(''), weak]
        },
        roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
        rateLimit: { clientIpSource: 'peer' }
      })

    expect(attempt).toThrow(message)
    expect(attempt).not.toThrow(/\bjwt\.secret\b/)
  })
})
