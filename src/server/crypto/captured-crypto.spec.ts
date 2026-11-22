/**
 * @fileoverview The secret comparisons, the HMACs and the random bytes of the library are not changed by a `node:crypto`
 * method replaced after the library loaded, and no source file reads those three from `node:crypto` directly.
 *
 * @layer Test
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

import { digestsMatch, apiKeyDigest, generateApiKeySecret } from './api-key'
import * as captured from './captured-crypto'
import { generateSecureToken, hmacSha256, sha256, timingSafeCompare } from './secure-token'
import { generateTotp, generateTotpSecret, verifyTotp } from './totp'

// The test's own copies: the windows below replace methods of the module, so nothing inside one may call a live one.
const nodeCrypto = jest.requireActual<Record<string, unknown>>('node:crypto')
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

const TOTP_SECRET = generateTotpSecret().base32

/** Runs `run` with `name` of `node:crypto` replaced by `stub`, and puts it back. */
function withReplaced<T>(name: string, stub: unknown, run: () => T): T {
  const held = getOwn(nodeCrypto, name) as PropertyDescriptor
  define(nodeCrypto, name, { ...held, value: stub })
  try {
    return run()
  } finally {
    define(nodeCrypto, name, held)
  }
}

/** The files of `src/server` that are not specs, as `[path, text]`. */
function sources(dir = join(__dirname, '..')): [string, string][] {
  return readdirSync(dir).flatMap((name): [string, string][] => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sources(path)
    return /\.ts$/.test(name) && !/\.(spec|test)\.ts$/.test(name)
      ? [[path, readFileSync(path, 'utf8')]]
      : []
  })
}

describe('the crypto primitives of the library after a method of node:crypto is replaced', () => {
  // Scenario: every source file of the server, read as text. Expected: none but the module that captures them imports a value
  // from `node:crypto` (a type import is fine). Why: one direct import is a call the replacement reaches.
  it('imports no value from node:crypto in any source file but the captured module', () => {
    const direct = sources()
      .filter(([path]) => !path.endsWith('captured-crypto.ts'))
      .filter(([, text]) => /import\s+(?!type\b)[^;]*?from\s*'node:crypto'/.test(text))
      .map(([path]) => path)

    expect(direct).toEqual([])
  })

  // Scenario: `timingSafeEqual` replaced by a function that answers true, then a different digest compared. Expected: still false.
  // Why: a replaced compare must not accept a secret that is not the stored one.
  it('still rejects a different secret with timingSafeEqual replaced', () => {
    const right = generateTotp(TOTP_SECRET)
    const wrongCode = right === '000000' ? '000001' : '000000'
    const answer = withReplaced(
      'timingSafeEqual',
      () => true,
      () => ({
        digest: digestsMatch(apiKeyDigest('a', 'p'), apiKeyDigest('b', 'p')),
        hex: timingSafeCompare('a'.repeat(64), 'b'.repeat(64)),
        totp: verifyTotp(TOTP_SECRET, wrongCode)
      })
    )

    expect(answer).toEqual({ digest: false, hex: false, totp: false })
  })

  // Scenario: `createHmac` replaced by a function that answers a fixed object, then an HMAC and a TOTP computed. Expected: the
  // same values as before the replacement. Why: a replaced HMAC would make every digest and code the attacker's.
  it('computes the same HMAC and TOTP with createHmac replaced', () => {
    const before = { hmac: hmacSha256('message', 'secret'), totp: generateTotp(TOTP_SECRET) }
    const during = withReplaced(
      'createHmac',
      () => ({ update: () => ({ digest: (): string => 'attacker' }) }),
      () => ({ hmac: hmacSha256('message', 'secret'), totp: generateTotp(TOTP_SECRET) })
    )

    expect(during).toEqual(before)
  })

  // Scenario: `randomBytes` replaced by a function that answers zeroes, then a token, an API-key secret generated. Expected:
  // neither is all zeroes. Why: a replaced generator would make every token and secret predictable.
  it('draws random bytes with the copy taken at load', () => {
    const drawn = withReplaced(
      'randomBytes',
      (size: number) => Buffer.alloc(size),
      () => ({
        token: generateSecureToken(16),
        secret: generateApiKeySecret()
      })
    )

    expect(drawn.token).not.toBe('0'.repeat(32))
    expect(drawn.secret).not.toBe(Buffer.alloc(32).toString('base64url'))
  })

  // Scenario: `createHash` replaced by a function that answers a fixed digest, then a SHA-256 computed. Expected: the real
  // digest. Why: a replaced hash would make different tokens and keys hash alike.
  it('hashes with the createHash taken at load', () => {
    const during = withReplaced(
      'createHash',
      () => ({ update: () => ({ digest: (): string => 'same' }) }),
      () => sha256('abc')
    )

    expect(during).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })

  // Scenario: each of the six values of the module compared, after every one was replaced on `node:crypto`, with the function
  // `node:crypto` held before. Expected: the module still exports the original of each. Why: the identifier and integer
  // generators, the ciphers and the key derivation are called by the services through these exports.
  it.each([
    'createCipheriv',
    'createDecipheriv',
    'createHash',
    'randomInt',
    'randomUUID',
    'scrypt'
  ] as const)('keeps the original %s after node:crypto replaces it', (name) => {
    const original = nodeCrypto[name]
    const kept = withReplaced(
      name,
      () => 'attacker',
      () => captured[name]
    )

    expect(kept).toBe(original)
  })
})
