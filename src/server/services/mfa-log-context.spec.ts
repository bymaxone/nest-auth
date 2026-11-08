/**
 * @fileoverview Pins the logger context of every MFA service to `MfaService`.
 *
 * An operator filters and alerts on the context tag of a log line. The MFA flows are split across
 * several classes, and a line must keep reading `[MfaService]` whichever class writes it, or a
 * filter keyed on it stops matching without any error.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { MfaChallengeService } from './mfa-challenge.service'
import { MfaManagementService } from './mfa-management.service'
import { MfaRecordService } from './mfa-record.service'
import { ReauthenticationService } from './reauthentication.service'

const KEY = 'k'.repeat(48)
const OPTIONS = { hmacKey: KEY } as never
const LOCKED = { isLockedOut: async (): Promise<boolean> => true } as never

/** The context of the logger instance the spied method was last called on. */
function contextOf(spy: jest.SpyInstance): unknown {
  const instance = spy.mock.contexts.at(-1) as object
  return Reflect.get(instance, 'context')
}

describe('MFA log context', () => {
  afterEach(() => jest.restoreAllMocks())

  it('logs ReauthenticationService lines as MfaService', async () => {
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation()
    const service = new ReauthenticationService(OPTIONS, {} as never, {} as never, LOCKED)

    await expect(
      service.assertReauthenticated('dashboard', 'u1', 'hash', 'secret', 't1')
    ).rejects.toBeDefined()

    expect(contextOf(warn)).toBe('MfaService')
  })

  it('logs MfaRecordService lines as MfaService', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation()
    const down = {
      setIfAbsent: async (): Promise<boolean> => {
        throw new Error('redis down')
      }
    } as never
    const service = new MfaRecordService(OPTIONS, {} as never, null, down)

    await service.reencryptSecret('u1', 'dashboard', 'SECRET', 't1', { encryptionKey: KEY })

    expect(contextOf(error)).toBe('MfaService')
  })

  it('logs MfaChallengeService lines as MfaService', async () => {
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation()
    const tokenManager = {
      verifyMfaTempToken: async () => ({ userId: 'u1', context: 'dashboard', tenantId: 't1' })
    } as never
    const service = new MfaChallengeService(
      OPTIONS,
      {} as never,
      null,
      tokenManager,
      LOCKED,
      {} as never,
      {} as never,
      {} as never
    )

    await expect(
      service.challenge('token', '123456', '1.2.3.4', 'ua', {} as never)
    ).rejects.toBeDefined()

    expect(contextOf(warn)).toBe('MfaService')
  })

  it('logs MfaManagementService lines as MfaService', async () => {
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation()
    const records = {
      loadAccount: async () => ({ mfaEnabled: true, mfaSecret: 'enc' })
    } as never
    const service = new MfaManagementService(
      OPTIONS,
      null,
      {} as never,
      LOCKED,
      records,
      {} as never,
      {} as never
    )

    await expect(
      service.disable('u1', '123456', '1.2.3.4', 'ua', 'dashboard', 't1', {} as never)
    ).rejects.toBeDefined()

    expect(contextOf(warn)).toBe('MfaService')
  })
})
