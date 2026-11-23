/**
 * @fileoverview A `catch` that turns a failure into another answer lets the library's refusal through: a polluted process answers
 * `auth.internal` and is not told that a secret did not decrypt, that a reset was quietly refused or that nothing needed to be done.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { encrypt } from '../crypto/aes-gcm'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { answerResetRequest } from './answer-reset-request'
import { decryptWithRotation, holdsSecret } from './mfa-secret-cipher'
import { assertRootIsStandard } from './object-prototype-guard'

const KEY = Buffer.alloc(32, 3).toString('base64')
const OTHER_KEY = Buffer.alloc(32, 4).toString('base64')
const STORED = encrypt('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', KEY)

/** The refusal of the guard, made while a key is planted on the root. */
function refusal(): unknown {
  Object.defineProperty(Object.prototype, 'sessions', {
    value: 1,
    configurable: true,
    enumerable: true,
    writable: true
  })
  try {
    assertRootIsStandard()
  } catch (error) {
    return error
  } finally {
    Reflect.deleteProperty(Object.prototype, 'sessions')
  }
  return undefined
}

/** What a call throws, or `undefined`. */
function thrown(run: () => unknown): unknown {
  try {
    run()
  } catch (error) {
    return error
  }
  return undefined
}

/** The status of what a call throws, or `undefined`. */
function statusOf(error: unknown): number | undefined {
  return (error as { getStatus?: () => number } | undefined)?.getStatus?.()
}

describe('the cipher of the TOTP secret while the runtime is not standard', () => {
  // Scenario: the key is right and a key is planted on the root while the secret is decrypted. Expected: the library's refusal
  // (500), not `TOKEN_INVALID` and not `false`. Why: the decryption would have succeeded, so reporting it as invalid data hides
  // the failure of the runtime.
  it.each([
    ['decryptWithRotation', () => decryptWithRotation(STORED, { encryptionKey: KEY })],
    [
      'holdsSecret',
      () => holdsSecret(STORED, 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', { encryptionKey: KEY })
    ],
    [
      'decryptWithRotation under a retired key',
      () => decryptWithRotation(STORED, { encryptionKey: OTHER_KEY, previousEncryptionKeys: [KEY] })
    ]
  ] as const)('%s answers with the refusal while a key is planted', (_name, call) => {
    Object.defineProperty(Object.prototype, 'sessions', {
      value: 1,
      configurable: true,
      enumerable: true,
      writable: true
    })
    let error: unknown
    try {
      error = thrown(call)
    } finally {
      Reflect.deleteProperty(Object.prototype, 'sessions')
    }

    expect(statusOf(error)).toBe(500)
  })

  // Scenario: the same calls with the runtime standard, and a ciphertext no key opens. Expected: `TOKEN_INVALID` and `false`.
  // Why: the control: only the refusal is let through, the tolerance for a record nobody can read stays.
  it('still answers an opaque failure for a ciphertext no key opens', () => {
    expect(statusOf(thrown(() => decryptWithRotation(STORED, { encryptionKey: OTHER_KEY })))).toBe(
      401
    )
    expect(
      holdsSecret(STORED, 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', { encryptionKey: OTHER_KEY })
    ).toBe(false)
  })
})

describe('the answer to a reset request while the runtime is not standard', () => {
  const redis = (): Pick<AuthRedisService, 'setnx' | 'del'> => ({
    setnx: jest.fn().mockResolvedValue(true),
    del: jest.fn().mockResolvedValue(undefined)
  })
  const request = (issue: () => Promise<void>): Parameters<typeof answerResetRequest>[1] => ({
    cooldownKey: 'k',
    cooldownSeconds: 60,
    floorMs: 0,
    start: Date.now(),
    findAccount: async () => ({ id: 'u', status: 'ACTIVE' }),
    isBlocked: () => false,
    issue
  })

  // Scenario: issuing the reset raises the library's refusal. Expected: the request rejects with it. Why: answering as if it
  // had been sent would tell a caller a reset is on its way from a process that cannot send one.
  it('rejects with the refusal that issuing raises', async () => {
    const raised = refusal()
    const deps = { redis: redis(), logger: new Logger('t') }

    await expect(
      answerResetRequest(
        deps,
        request(async () => {
          throw raised
        })
      )
    ).rejects.toBe(raised)
  })

  // Scenario: issuing fails the ordinary way. Expected: the request completes and the cooldown is released. Why: the control.
  it('still completes when issuing fails the ordinary way', async () => {
    const deps = { redis: redis(), logger: new Logger('t') }
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

    await expect(
      answerResetRequest(
        deps,
        request(async () => {
          throw new Error('store down')
        })
      )
    ).resolves.toBeUndefined()
    expect(deps.redis.del).toHaveBeenCalled()
  })
})
