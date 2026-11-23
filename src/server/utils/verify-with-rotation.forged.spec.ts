/**
 * @fileoverview A forged token is never verified while a function the verification is made with is replaced: `jwa` reads
 * `crypto.timingSafeEqual` and `crypto.createHmac` at each call, so a replaced one accepts a token signed with the attacker's
 * secret. The guard that runs at the entry of the verification compares those functions, so it refuses before the token is read.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'

import type { ResolvedOptions } from '../config/resolved-options'
import { jwtModuleOptions } from './dependency-options'
import { verifyWithRotation } from './verify-with-rotation'

const SECRET = 'real-secret-real-secret-real-secret-1234'
const ATTACKER = 'attacker-secret-attacker-secret-1234'
const options = Object.assign({} as ResolvedOptions, {
  jwt: { secret: SECRET, algorithm: 'HS256', previousSecrets: [] }
})
const service = new JwtService(jwtModuleOptions(SECRET))
const forged = new JwtService(jwtModuleOptions(ATTACKER)).sign({ sub: 'u', role: 'ADMIN' })

// The test's own copies: the windows below replace functions of `node:crypto`.
const nodeCrypto = jest.requireActual<Record<string, unknown>>('node:crypto')
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

/** What each replacement does to make a forged token pass: answer true, or sign with the attacker's key. */
const REPLACEMENTS: Record<string, (original: (...args: unknown[]) => unknown) => unknown> = {
  timingSafeEqual: () => () => true,
  createHmac: (original) => (algorithm: unknown) => original(algorithm, ATTACKER),
  createSecretKey: (original) => () => original(Buffer.from(ATTACKER)),
  createVerify: () => () => ({ update: () => undefined, verify: () => true }),
  createSign: (original) => original,
  createPublicKey: (original) => original,
  createPrivateKey: (original) => original,
  KeyObject: (original) => original
}

/** Runs `run` with `name` of `node:crypto` replaced, and puts it back. */
function withReplaced<T>(name: string, run: () => T): T {
  const held = getOwn(nodeCrypto, name) as PropertyDescriptor
  const make = REPLACEMENTS[name] as (original: (...args: unknown[]) => unknown) => unknown
  const stub = (...args: unknown[]): unknown =>
    (make(held.value as (...a: unknown[]) => unknown) as (...a: unknown[]) => unknown)(...args)
  define(nodeCrypto, name, { ...held, value: stub })
  try {
    return run()
  } finally {
    define(nodeCrypto, name, held)
  }
}

/** The status the refusal carries, or `undefined` when the verification answered with a payload or threw another error. */
function refusalStatus(run: () => unknown): number | undefined {
  try {
    run()
  } catch (error) {
    return (error as { getStatus?: () => number }).getStatus?.()
  }
  return undefined
}

describe('a forged token while a function of node:crypto is replaced', () => {
  // Scenario: a token signed with the attacker's secret, verified with nothing replaced. Expected: refused as an invalid
  // signature. Why: the control for the rows below.
  it('is refused as an invalid signature with nothing replaced', () => {
    expect(() => verifyWithRotation(service, options, forged)).toThrow('invalid signature')
  })

  // Scenario: each function of `node:crypto` the JWT libraries read, replaced by one that makes a forged token pass, then the
  // forged token verified. Expected: the library's refusal (500), never the payload of the token. Why: with the control above
  // as the clean answer, a payload here is a forged administrator token accepted.
  it.each(Object.keys(REPLACEMENTS))(
    'is refused with the library refusal while %s is replaced',
    (name) => {
      let payload: unknown
      const status = withReplaced(name, () =>
        refusalStatus(() => {
          payload = verifyWithRotation(service, options, forged)
        })
      )

      expect(payload).toBeUndefined()
      expect(status).toBe(500)
    }
  )

  // Scenario: the methods `jwa` calls on the `Hmac` it gets back, replaced by ones that make the forged token's own signature the
  // computed one (`digest` answers it, `update` ignores the data), each in turn, then the forged token verified. Expected: the
  // library's refusal. Why: `timingSafeEqual` forges only when the lengths match, so these are the replacements that forge a
  // token with the real comparison untouched.
  it.each(['digest', 'update'] as const)(
    'is refused with the library refusal while Hmac.prototype.%s is replaced',
    (name) => {
      const prototype = nodeCrypto['Hmac'] as { prototype: object }
      const held = getOwn(prototype.prototype, name) as PropertyDescriptor
      const signature = Buffer.from(forged.split('.')[2] as string, 'base64url').toString('base64')
      define(prototype.prototype, name, {
        ...held,
        value: function (this: unknown): unknown {
          return name === 'digest' ? signature : this
        }
      })
      let payload: unknown
      let status: number | undefined
      try {
        status = refusalStatus(() => {
          payload = verifyWithRotation(service, options, forged)
        })
      } finally {
        define(prototype.prototype, name, held)
      }

      expect(payload).toBeUndefined()
      expect(status).toBe(500)
    }
  )

  // Scenario: `RegExp.prototype[Symbol.replace]`, which `jwa` reaches through the regular expressions it converts a digest with,
  // replaced by a function that answers the same text for every digest, then a token validly signed for an ordinary user
  // verified. Expected: the library's refusal. Why: with it replaced every signature computes to the same text, so a token signed
  // with that text verifies, and no source names the function.
  it('is refused while RegExp.prototype[Symbol.replace] is replaced', () => {
    const token = service.sign({ sub: 'user', role: 'MEMBER' })
    const held = getOwn(RegExp.prototype, Symbol.replace) as PropertyDescriptor
    define(RegExp.prototype, Symbol.replace, { ...held, value: () => 'AAAA' })
    let payload: unknown
    let status: number | undefined
    try {
      status = refusalStatus(() => {
        payload = verifyWithRotation(service, options, token)
      })
    } finally {
      define(RegExp.prototype, Symbol.replace, held)
    }

    expect(payload).toBeUndefined()
    expect(status).toBe(500)
  })

  // Scenario: a token validly signed with the real secret for an ordinary user, verified while `JSON.parse` is replaced by a function
  // that answers an administrator. Expected: the library's refusal, never the administrator's claims. Why: `jws` decodes the payload
  // with `JSON.parse` after the signature was checked, so a replaced one turns any validly signed token into any claims.
  it('is refused while JSON.parse is replaced', () => {
    const token = service.sign({ sub: 'user', role: 'MEMBER' })
    const held = getOwn(JSON, 'parse') as PropertyDescriptor
    define(JSON, 'parse', { ...held, value: () => ({ sub: 'user', role: 'ADMIN' }) })
    let payload: unknown
    let status: number | undefined
    try {
      status = refusalStatus(() => {
        payload = verifyWithRotation(service, options, token)
      })
    } finally {
      define(JSON, 'parse', held)
    }

    expect(payload).toBeUndefined()
    expect(status).toBe(500)
  })

  // Scenario: `JwtService.prototype.verify` replaced by a function that answers an administrator. Expected: the library's
  // refusal. Why: the sources call `jwtService.verify` at each decision, and a replaced one is the same forgery.
  it('is refused while JwtService.prototype.verify is replaced', () => {
    const held = getOwn(JwtService.prototype, 'verify') as PropertyDescriptor
    define(JwtService.prototype, 'verify', { ...held, value: () => ({ role: 'ADMIN' }) })
    let payload: unknown
    let status: number | undefined
    try {
      status = refusalStatus(() => {
        payload = verifyWithRotation(service, options, forged)
      })
    } finally {
      define(JwtService.prototype, 'verify', held)
    }

    expect(payload).toBeUndefined()
    expect(status).toBe(500)
  })
})
