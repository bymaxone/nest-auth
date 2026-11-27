/**
 * @fileoverview The verify script's reading of the attempt counter, against a REAL Redis.
 *
 * The script decides what counts as an integer with Lua's patterns over a stored string, and the
 * in-memory Redis answers an empty string differently from a server.
 *
 * @layer Test
 */

import Redis from 'ioredis'

import { OtpService } from '../../../src/server/services/otp.service'
import { BYMAX_AUTH_REDIS_CLIENT } from '../../../src/server/bymax-auth.constants'
import type { BootstrappedTestApp } from '../setup'
import { bootstrapTestApp } from '../setup'

const CODE = '123456'

describe('the OTP attempt counter (E2E, real Redis)', () => {
  let boot: BootstrappedTestApp
  let client: Redis
  let otp: OtpService

  beforeAll(async () => {
    client = new Redis(process.env['BYMAX_E2E_REDIS_URL'] as string)
    boot = await bootstrapTestApp(
      {},
      {
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(client)
      }
    )
    otp = boot.app.get(OtpService, { strict: false })
  })

  afterAll(async () => {
    await boot.app.close()
    client.disconnect()
  })

  /** Stores a code under `who`, then sets the counter, or removes it for `null`. */
  async function recordWith(who: string, attempts: string | null): Promise<string> {
    await otp.store('reset', who, CODE, 60)
    const [key] = await client.keys(`*otp:reset:${who}`)
    if (attempts === null) await client.hdel(key as string, 'attempts')
    else await client.hset(key as string, 'attempts', attempts)
    return key as string
  }

  // An absent counter is the first attempt.
  it.each([
    ['absent', null],
    ['zero', '0'],
    ['four', '4']
  ])('verifies the right code over a counter that is %s', async (who, stored) => {
    await recordWith(who, stored)

    await expect(otp.verify('reset', who, CODE)).resolves.toBeUndefined()
  })

  // Present and not a non-negative integer is the ceiling.
  it.each([
    ['empty', ''],
    ['nan', 'nan'],
    ['negative', '-1000000'],
    ['text', 'abc']
  ])('refuses and consumes a record whose counter is %s', async (who, stored) => {
    const key = await recordWith(who, stored)

    await expect(otp.verify('reset', who, CODE)).rejects.toThrow()
    await expect(client.exists(key)).resolves.toBe(0)
  })
})
