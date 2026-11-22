/**
 * @fileoverview A key planted on `Object.prototype` is not read by the dependencies the library hands options to:
 * `@nestjs/jwt` and `jsonwebtoken` copy the options they get into a new object and read names the library never set, so
 * every name they read carries an own value. The rows run the real libraries.
 *
 * @layer Test
 */

import { generateKeyPairSync } from 'node:crypto'

import { JwtService } from '@nestjs/jwt'
import type { JwtSignOptions, JwtVerifyOptions } from '@nestjs/jwt'
import { JWT_SIGN_SHADOWS, JWT_VERIFY_SHADOWS, jwtModuleOptions } from './dependency-options'

const SECRET = 'real-secret-real-secret-real-secret-1234'
const ATTACKER = 'attacker-secret-attacker-secret-1234'

const OPTIONS = { jwt: { algorithm: 'HS256' } }

/** Runs `body` with `key` planted on the root object of the process and always takes it away again. */
function withPlanted<T>(key: string, value: unknown, body: () => T): T {
  const held = Object.getOwnPropertyDescriptor(Object.prototype, key)
  Object.defineProperty(Object.prototype, key, {
    value,
    configurable: true,
    enumerable: true,
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

/** The result of verifying `token` with the real service, with the options the library hands to it, as `accepted` or the refusal. */
function outcome(service: JwtService, token: string, ignoreExpiration = false): string {
  try {
    const claims = service.verify<{ sub?: string }>(token, {
      ...JWT_VERIFY_SHADOWS,
      algorithms: [OPTIONS.jwt.algorithm],
      ignoreExpiration,
      issuer: undefined,
      audience: undefined,
      secret: SECRET
    } as JwtVerifyOptions)
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

const pem = (key: import('node:crypto').KeyObject, type: 'pkcs8' | 'spki'): string =>
  key.export({ type, format: 'pem' }) as string
const RSA = generateKeyPairSync('rsa', { modulusLength: 2048 })
const RSA_SMALL = generateKeyPairSync('rsa', { modulusLength: 1024 })
const EC = generateKeyPairSync('ec', { namedCurve: 'P-256' })

/** The message of the failure of `call`, or the word `signed` when it did not fail. */
function refusalOf(call: () => unknown): string {
  try {
    call()
    return 'signed'
  } catch (error) {
    return (error as Error).message
  }
}

describe('the options that decide how a key and a clock are judged, planted on Object.prototype', () => {
  const service = new JwtService(jwtModuleOptions(SECRET))
  const early = real.sign({ sub: 'user' }, { expiresIn: 600, notBefore: 300 })
  const asymmetric = real.sign(
    { sub: 'user' },
    { algorithm: 'RS256', secret: pem(RSA.privateKey, 'pkcs8'), expiresIn: 600 }
  )
  const verifyAs = (token: string, secret: string, algorithm: 'HS256' | 'RS256'): string =>
    refusalOf(() =>
      service.verify(token, {
        ...JWT_VERIFY_SHADOWS,
        algorithms: [algorithm],
        ignoreExpiration: false,
        issuer: undefined,
        audience: undefined,
        secret
      } as JwtVerifyOptions)
    )
  const signAs = (secret: string): string =>
    refusalOf(() =>
      service.sign(
        { sub: 'user' },
        Object.assign({} as JwtSignOptions, JWT_SIGN_SHADOWS, {
          algorithm: 'RS256',
          expiresIn: '10m',
          secret
        })
      )
    )

  // Scenario: a token that is not yet valid, and a key of another type than the algorithm asks for, verified with
  // `ignoreNotBefore` and `allowInvalidAsymmetricKeyTypes` planted as true. Expected: each is refused with the message it has
  // with nothing planted. Why: those two options turn off the check of the clock and the check of the type of the key, and
  // the answer has to be the library's, not a refusal for another reason.
  it.each([
    ['ignoreNotBefore', () => verifyAs(early, SECRET, 'HS256'), /jwt not active/u],
    [
      'allowInvalidAsymmetricKeyTypes',
      () => verifyAs(asymmetric, pem(EC.publicKey, 'spki'), 'RS256'),
      /"alg" parameter for "ec" key type/u
    ]
  ] as const)('does not read %s on verify', (name, run, message) => {
    const baseline = run()

    const planted = withPlanted(name, true, run)

    expect(baseline).toMatch(message)
    expect(planted).toBe(baseline)
  })

  // Scenario: a key that is too small and a key of another type than the algorithm asks for, used to sign, with
  // `allowInsecureKeySizes` and `allowInvalidAsymmetricKeyTypes` planted as true. Expected: each is refused with the message
  // it has with nothing planted. Why: those two options turn off the minimum size of a key and the check of its type.
  it.each([
    [
      'allowInsecureKeySizes',
      () => signAs(pem(RSA_SMALL.privateKey, 'pkcs8')),
      /minimum key size of 2048/u
    ],
    [
      'allowInvalidAsymmetricKeyTypes',
      () => signAs(pem(EC.privateKey, 'pkcs8')),
      /"alg" parameter for "ec" key type/u
    ]
  ] as const)('does not read %s on sign', (name, run, message) => {
    const baseline = run()

    const planted = withPlanted(name, true, run)

    expect(baseline).toMatch(message)
    expect(planted).toBe(baseline)
  })
})

describe('signing with a key planted on Object.prototype', () => {
  const service = new JwtService(jwtModuleOptions(SECRET))
  const chosen = { expiresIn: '10m', secret: SECRET, algorithm: 'HS256' }
  const sign = (): string =>
    service.sign({ sub: 'usér €' }, { ...JWT_SIGN_SHADOWS, ...chosen } as JwtSignOptions)
  const claimsOf = (token: string): unknown => service.decode(token, { complete: true })

  // Scenario: a payload object handed to the signature while `mutatePayload` is planted as true. Expected: the object the caller
  // handed in is left as it was, with no `iat` or `exp` written into it. Why: the option makes `jsonwebtoken` write the
  // claims into the caller's own object, so a planted one would change an object the backend still holds.
  it('does not read mutatePayload, and leaves the payload object as it was', () => {
    const payload: Record<string, unknown> = { sub: 'user' }

    withPlanted('mutatePayload', true, () =>
      service.sign(payload, { ...JWT_SIGN_SHADOWS, ...chosen } as JwtSignOptions)
    )

    expect(Object.keys(payload)).toEqual(['sub'])
  })

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
