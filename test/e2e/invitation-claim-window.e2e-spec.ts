/**
 * @fileoverview The window between claiming the invitee index and writing the invitation record.
 *
 * `invite` claims the index first and writes the record second, so the index is the handle a
 * revoke reaches the record through. Two things can happen in between that a single-threaded
 * walk through the route never shows:
 *
 *  - a revoke reads the index, finds the claimed hash, deletes an index and a record that is not
 *    there yet, and the write then lands: a redeemable invitation that nothing names;
 *  - the index TTL starts at the claim and the record TTL at the write, so the record outlives
 *    the entry that names it.
 *
 * Each case forces the interleave deterministically by wrapping the Redis client's `set` for the
 * invitation record, rather than racing two requests and hoping.
 */

import type { INestApplication } from '@nestjs/common'
import type { Redis } from 'ioredis'
import request from 'supertest'

import type { BootstrappedTestApp, CapturedEmail } from './setup'
import { bootstrapTestApp } from './setup'

const TTL_SECONDS = 3_600
const INVITEE = 'window@example.com'

/** The keys the invitation flow owns, as the mock Redis holds them. */
async function invitationKeys(redis: Redis): Promise<{ records: string[]; indexes: string[] }> {
  const keys = await redis.keys('*')
  return {
    records: keys.filter((key) => key.includes(':inv:')),
    indexes: keys.filter((key) => key.includes(':invidx:'))
  }
}

describe('invitation claim-then-write window (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let adminToken: string
  let sent: CapturedEmail[]
  let realSet: Redis['set']

  /** Runs `beforeWrite` once, immediately before the invitation record is written. */
  function beforeRecordWrite(beforeWrite: () => Promise<void>): void {
    const original = realSet.bind(boot.redis)
    let done = false
    jest.spyOn(boot.redis, 'set').mockImplementation(((...args: unknown[]) => {
      const key = String(args[0])
      if (!done && key.includes(':inv:')) {
        done = true
        return beforeWrite().then(() => (original as (...a: unknown[]) => unknown)(...args))
      }
      return (original as (...a: unknown[]) => unknown)(...args)
    }) as never)
  }

  beforeEach(async () => {
    boot = await bootstrapTestApp(
      { invitations: { enabled: true, tokenTtlSeconds: TTL_SECONDS } },
      {
        controllers: {
          auth: true,
          mfa: true,
          passwordReset: true,
          sessions: true,
          invitations: true
        }
      }
    )
    app = boot.app
    realSet = boot.redis.set
    sent = boot.email.sentEmails

    await request(app.getHttpServer()).post('/register').send({
      email: 'admin@example.com',
      password: 'AdminSecret123!',
      name: 'Admin User',
      tenantId: 'tenant-1'
    })
    for (const user of boot.repo.users.values()) {
      if (user.email === 'admin@example.com') {
        boot.repo.users.set(user.id, { ...user, role: 'ADMIN' })
      }
    }
    const login = await request(app.getHttpServer())
      .post('/login')
      .send({ email: 'admin@example.com', password: 'AdminSecret123!', tenantId: 'tenant-1' })
    adminToken = login.body.accessToken as string
  })

  afterEach(async () => {
    jest.restoreAllMocks()
    await app.close()
  })

  const invite = () =>
    request(app.getHttpServer())
      .post('/invitations')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: INVITEE, role: 'MEMBER' })

  const revoke = () =>
    request(app.getHttpServer())
      .post('/invitations/revoke')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: INVITEE })

  // Scenario: a revoke lands after the index is claimed and before the record is written.
  // Expected: the invitation is refused and nothing redeemable is left behind. Why: the revoke
  // found an index naming a record that did not exist yet, deleted the index, and reported
  // success; the write then published a token no index names, which a later revoke can never reach.
  it('leaves no redeemable record when a revoke lands between the claim and the write', async () => {
    beforeRecordWrite(async () => {
      await revoke()
    })

    const res = await invite()

    const { records, indexes } = await invitationKeys(boot.redis)
    expect({ status: res.status, records: records.length, indexes: indexes.length }).toEqual({
      status: 403,
      records: 0,
      indexes: 0
    })
    expect(sent.filter((mail) => mail.to === INVITEE)).toHaveLength(0)
  })

  // Scenario: the record is written some time after the claim. Expected: the index outlives, or
  // matches, the record it names. Why: both are given the full TTL but at different instants, so
  // the record would otherwise expire after the index and sit redeemable with no handle on it.
  it('keeps the index alive at least as long as the record it names', async () => {
    beforeRecordWrite(async () => {
      await new Promise((resolve) => setTimeout(resolve, 1_100))
    })

    const res = await invite()

    const { records, indexes } = await invitationKeys(boot.redis)
    expect(res.status).toBe(204)
    const recordTtl = await boot.redis.pttl(records[0] as string)
    const indexTtl = await boot.redis.pttl(indexes[0] as string)
    expect(indexTtl).toBeGreaterThanOrEqual(recordTtl)
  })
})
