/**
 * @fileoverview A key planted on `Object.prototype` is not read by the dependencies the library hands options to:
 * `@nestjs/jwt` and `jsonwebtoken` copy the options they get into a new object and read names the library never set, so
 * every name they read carries an own value. The rows run the real libraries.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { jwtModuleOptions, jwtSignOptions } from './dependency-options'
import { signerOf, verifyWithRotation } from './verify-with-rotation'

const SECRET = 'real-secret-real-secret-real-secret-1234'
const ATTACKER = 'attacker-secret-attacker-secret-1234'

const OPTIONS = {
  jwt: {
    secret: SECRET,
    algorithm: 'HS256',
    previousSecrets: [],
    issuer: undefined,
    audience: undefined
  }
} as unknown as ResolvedOptions

/** Runs `body` with `key` planted on the root object of the process and always takes it away again. */
function withPlanted<T>(key: string, value: unknown, body: () => T): T {
  const held = Object.getOwnPropertyDescriptor(Object.prototype, key)
  Object.defineProperty(Object.prototype, key, {
    value,
    configurable: true,
    enumerable: false,
    writable: true
  })
  try {
    return body()
  } finally {
    if (held === undefined) Reflect.deleteProperty(Object.prototype, key)
    else Object.defineProperty(Object.prototype, key, held)
  }
}

const NOW = Math.floor(Date.now() / 1000)
const real = new JwtService({ secret: SECRET })
const expired = real.sign({ sub: 'user', exp: NOW - 3600 }, { noTimestamp: true })
const forged = new JwtService({ secret: ATTACKER }).sign({ sub: 'attacker' })
const valid = real.sign({ sub: 'user' }, { expiresIn: 600 })

/** The result of verifying `token` with the real service, as `accepted` or the refusal. */
function outcome(service: JwtService, token: string, ignoreExpiration = false): string {
  try {
    const claims = verifyWithRotation<{ sub?: string }>(service, OPTIONS, token, {
      ignoreExpiration
    })
    return `accepted ${JSON.stringify(claims)}`
  } catch (error) {
    return `refused ${(error as Error).message}`
  }
}

describe('verifying with a key planted on Object.prototype', () => {
  const service = new JwtService(jwtModuleOptions(SECRET))

  // Scenario: each option name `@nestjs/jwt` or `jsonwebtoken` reads and the library does not set, planted on
  // Object.prototype with a value that would accept a forged or an expired token, and the token that value is aimed at.
  // Expected: the token is refused as it is with nothing planted. Why: the key of verification, the tolerance of the clock
  // and the age bound decide whether a token is believed, and none may come from outside the configuration.
  it.each([
    ['secretOrPrivateKey', ATTACKER, forged],
    ['verifyOptions', { clockTolerance: 100000, ignoreExpiration: true }, expired],
    ['clockTolerance', 100000, expired],
    ['clockTimestamp', 1, expired],
    ['publicKey', ATTACKER, forged],
    ['privateKey', ATTACKER, forged]
  ] as const)('does not read %s', (name, value, token) => {
    const baseline = outcome(service, token)

    const planted = withPlanted(name, value, () => outcome(service, token))

    expect(baseline).toMatch(/^refused /u)
    expect(planted).toBe(baseline)
  })

  // Scenario: names that change what a verified token returns or which tokens are accepted, planted, against a token the
  // library accepts. Expected: the answer is what it is with nothing planted. Why: `complete` changes the shape of the
  // answer, and a bound on age, a nonce or a claim to match would refuse every session.
  it.each([
    ['complete', true],
    ['maxAge', 1],
    ['ignoreNotBefore', true],
    ['nonce', 'planted'],
    ['subject', 'someone-else'],
    ['jwtid', 'planted']
  ] as const)('does not read %s', (name, value) => {
    const baseline = outcome(service, valid)

    const planted = withPlanted(name, value, () => outcome(service, valid))

    expect(baseline).toBe(
      'accepted {"sub":"user"' + baseline.slice('accepted {"sub":"user"'.length)
    )
    expect(planted).toBe(baseline)
  })

  // Scenario: logout's verification, which ignores the expiry, with a clock tolerance planted. Expected: the same answer as
  // with nothing planted. Why: the call that ignores the expiry is the one a planted tolerance would also be read by.
  it('keeps the answer of a verification that ignores the expiry', () => {
    const baseline = outcome(service, expired, true)

    const planted = withPlanted('clockTolerance', 100000, () => outcome(service, expired, true))

    expect(planted).toBe(baseline)
  })
})

describe('signing with a key planted on Object.prototype', () => {
  const service = new JwtService(jwtModuleOptions(SECRET))
  const chosen = { expiresIn: '10m', ...signerOf(OPTIONS) }
  const sign = (): string => service.sign({ sub: 'user' }, jwtSignOptions(chosen))
  const claimsOf = (token: string): unknown => service.decode(token, { complete: true })

  // Scenario: the option names of `jsonwebtoken.sign` that have a neutral value, planted. Expected: the token has the
  // header and the claims it has with nothing planted. Why: a token without `iat`, or with a header the host never wrote,
  // is a token this backend would mint on the word of a flaw elsewhere.
  it.each([
    ['noTimestamp', true],
    ['header', { kid: 'planted', evil: 1 }],
    ['encoding', 'latin1'],
    ['mutatePayload', true]
  ] as const)('does not read %s', (name, value) => {
    const baseline = claimsOf(sign())

    const planted = withPlanted(name, value, () => claimsOf(sign()))

    expect(planted).toEqual(baseline)
  })

  // Scenario: the names that add a claim or a header field and have no neutral value, planted. Expected: no token is
  // signed, and the refusal is the library's `auth.internal`. Why: signing with one of them would put a planted claim into
  // a token the backend signed, and the schema of `jsonwebtoken` refuses an own `undefined` that would shadow it.
  it.each(['keyid', 'notBefore', 'jwtid', 'subject', 'issuer', 'audience'] as const)(
    'refuses to sign while %s is planted',
    (name) => {
      let refused: unknown
      try {
        withPlanted(name, 'planted', sign)
      } catch (error) {
        refused = error
      }

      expect(refused).toBeInstanceOf(AuthException)
      expect((refused as AuthException).getResponse()).toMatchObject({
        error: { code: AUTH_ERROR_CODES.INTERNAL }
      })
    }
  )

  // Scenario: nothing planted. Expected: a token with `iat`, `exp` and the algorithm the library pinned. Why: the shadows
  // are neutral, so the token is the one the library always signed.
  it('signs the token it always signed', () => {
    const decoded = claimsOf(sign()) as {
      header: { alg: string }
      payload: Record<string, unknown>
    }

    expect(decoded.header).toEqual({ alg: 'HS256', typ: 'JWT' })
    expect(Object.keys(decoded.payload).sort()).toEqual(['exp', 'iat', 'sub'])
  })
})
