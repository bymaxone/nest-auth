/**
 * @fileoverview The decoy derivation of `compareDummy` runs under the configured cost, not under the defaults of scrypt.
 *
 * @layer Test
 */

import type { ScryptOptions } from 'node:crypto'

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_BREACH_CHECKER, BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { PasswordService } from './password.service'

/** The options each derivation was asked for, in order. */
const asked: ScryptOptions[] = []

jest.mock('node:crypto', () => {
  const actual = jest.requireActual<typeof import('node:crypto')>('node:crypto')
  const recording = (
    password: string,
    salt: string,
    keylen: number,
    options: ScryptOptions,
    callback: (error: Error | null, key: Buffer) => void
  ): void => {
    asked.push(options)
    actual.scrypt(password, salt, keylen, options, callback)
  }
  return { ...actual, scrypt: recording }
})

describe('PasswordService.compareDummy', () => {
  // Scenario: a service configured at a cost other than the defaults of scrypt runs the decoy. Expected: the derivation is asked for that
  // cost, block size, parallelization and memory ceiling. Why: the decoy exists to take as long as a real verify, so a derivation under
  // other parameters reopens the timing oracle while its result, always false, stays the same.
  it('derives under the configured parameters', async () => {
    const module = await Test.createTestingModule({
      providers: [
        PasswordService,
        {
          provide: BYMAX_AUTH_OPTIONS,
          useValue: { password: { costFactor: 4096, blockSize: 4, parallelization: 2 } }
        },
        { provide: BYMAX_AUTH_BREACH_CHECKER, useValue: { isBreached: jest.fn() } }
      ]
    }).compile()
    const service = module.get(PasswordService)
    asked.length = 0

    await expect(service.compareDummy('anything')).resolves.toBe(false)

    expect(asked).toHaveLength(1)
    expect(asked[0]).toMatchObject({
      N: 4096,
      r: 4,
      p: 2,
      maxmem: service['maxmem' as keyof PasswordService]
    })
    expect(typeof asked[0]?.maxmem).toBe('number')
  })
})
