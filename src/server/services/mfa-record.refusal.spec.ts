/**
 * @fileoverview The detached re-encryption of an MFA secret swallows a store failure, but never the library's own refusal while
 * a built-in is replaced: that one reaches the caller.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { MfaRecordService } from './mfa-record.service'
import { assertRootIsStandard, isRefusal } from '../utils/object-prototype-guard'

// The test's own copies: the window below replaces a built-in, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

/** Makes the refusal of the library by calling its check while a built-in is replaced. */
function makeRefusal(): unknown {
  const held = getOwn(Array.prototype, 'every') as PropertyDescriptor
  define(Array.prototype, 'every', { ...held, value: () => true })
  try {
    assertRootIsStandard()
  } catch (error) {
    return error
  } finally {
    define(Array.prototype, 'every', held)
  }
  return undefined
}

const OPTIONS = { hmacKey: 'k'.repeat(48), blockedStatuses: [] } as never
const KEYS = { current: { id: 'k1', key: Buffer.alloc(32) }, retired: [] } as never

describe('MfaRecordService.reencryptSecret and a refusal of the library', () => {
  // Scenario: the lookup of the account fails with a store error. Expected: the call resolves. Why: the migration is best effort.
  it('swallows a store failure', async () => {
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const repo = { findById: jest.fn().mockRejectedValue(new Error('down')), updateMfa: jest.fn() }
    const redis = {
      setIfAbsent: jest.fn().mockResolvedValue(true),
      eval: jest.fn().mockResolvedValue(1)
    }
    const service = new MfaRecordService(OPTIONS, repo as never, null, redis as never)

    await expect(
      service.reencryptSecret('u1', 'dashboard', 'S', 't1', KEYS)
    ).resolves.toBeUndefined()
  })

  // Scenario: the lookup fails with the refusal of the library. Expected: the call rejects with that refusal. Why: swallowing it
  // would hide that the runtime differs from its own.
  it('rejects with the refusal of the library', async () => {
    const refusal = makeRefusal()
    expect(isRefusal(refusal)).toBe(true)
    const repo = { findById: jest.fn().mockRejectedValue(refusal), updateMfa: jest.fn() }
    const redis = {
      setIfAbsent: jest.fn().mockResolvedValue(true),
      eval: jest.fn().mockResolvedValue(1)
    }
    const service = new MfaRecordService(OPTIONS, repo as never, null, redis as never)

    await expect(service.reencryptSecret('u1', 'dashboard', 'S', 't1', KEYS)).rejects.toBe(refusal)
  })
})
