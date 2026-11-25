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
 * The other window is on the removing side: a revoke and an acceptance read the index, or consume
 * the record it names, and drop the index afterwards. A later invite of the address can claim the
 * index in between.
 *
 * Each case forces the interleave deterministically by wrapping one command of the Redis client,
 * rather than racing two requests and hoping.
 */

import type { INestApplication } from '@nestjs/common'
import type { Redis } from 'ioredis'
import request from 'supertest'

import type { BootstrappedTestApp, CapturedEmail } from './setup'
import { bootstrapTestApp } from './setup'

const TTL_SECONDS = 3_600
const INVITEE = 'window@example.com'

/**
 * The keys the invitation flow owns under `namespace`, as the Redis the suite runs on holds them.
 * A real server is shared by every suite in the run, so the scan is bounded to the namespace.
 */
async function invitationKeys(
  redis: Redis,
  namespace: string
): Promise<{ records: string[]; indexes: string[] }> {
  const keys = await redis.keys(`${namespace}:*`)
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

  /**
   * Runs `write` once, right after the first call of `command` that names an invitation record:
   * after a revoke has read it, or an acceptance has consumed it.
   */
  function afterRecordAccess(command: 'get' | 'eval', write: () => Promise<void>): void {
    const original = (boot.redis[command] as (...a: unknown[]) => Promise<unknown>).bind(boot.redis)
    let done = false
    jest.spyOn(boot.redis, command).mockImplementation((async (...args: unknown[]) => {
      const reply = await original(...args)
      if (!done && args.some((arg) => String(arg).includes(':inv:'))) {
        done = true
        await write()
      }
      return reply
    }) as never)
  }

  /** Moves the index to a new record granting `role`, as a later invite by someone else does. */
  async function replaceWithRole(role: string): Promise<void> {
    const namespace = boot.options.redisNamespace ?? 'auth'
    const { records, indexes } = await invitationKeys(boot.redis, namespace)
    const stored = JSON.parse((await boot.redis.get(records[0] as string)) as string) as object
    const hash = 'f'.repeat(64)
    await boot.redis.del(records[0] as string)
    await boot.redis.set(`${namespace}:inv:${hash}`, JSON.stringify({ ...stored, role }))
    await boot.redis.set(indexes[0] as string, hash)
  }

  /** Collects the raw tokens of the invitations emailed from here on. */
  function emailedTokens(): string[] {
    const tokens: string[] = []
    boot.email.sendInvitation = async (_tenantId, _email, data) => {
      tokens.push(data.inviteToken)
    }
    return tokens
  }

  /** The invitation keys of this suite's namespace, counted. */
  async function countKeys(): Promise<{ records: number; indexes: number }> {
    const namespace = boot.options.redisNamespace ?? 'auth'
    const { records, indexes } = await invitationKeys(boot.redis, namespace)
    return { records: records.length, indexes: indexes.length }
  }

  const accept = (token: string) =>
    request(app.getHttpServer())
      .post('/invitations/accept')
      .send({ token, name: 'Invitee', password: 'InviteeSecret123!' })

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
      {
        invitations: { enabled: true, tokenTtlSeconds: TTL_SECONDS },
        roles: {
          hierarchy: { OWNER: ['ADMIN'], ADMIN: ['MEMBER'], MEMBER: [] },
          platformHierarchy: { SUPER_ADMIN: [] }
        }
      },
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

    const { records, indexes } = await invitationKeys(
      boot.redis,
      boot.options.redisNamespace ?? 'auth'
    )
    expect({ status: res.status, records: records.length, indexes: indexes.length }).toEqual({
      status: 403,
      records: 0,
      indexes: 0
    })
    expect(sent.filter((mail) => mail.to === INVITEE)).toHaveLength(0)
  })

  // Scenario: a re-invite lands after a revoke has read the invitation and before it drops the
  // index. Expected: the replacement stays indexed, and the next revoke removes it. Why: dropping
  // the index unconditionally left the new token redeemable, out of reach of every later revoke,
  // and let a further invite add a second live token beside it.
  it('keeps a replacement revocable when it lands during a revoke', async () => {
    const tokens = emailedTokens()
    await invite()
    afterRecordAccess('get', async () => {
      await invite()
    })

    expect((await revoke()).status).toBe(204)

    expect(await countKeys()).toEqual({ records: 0, indexes: 0 })
    expect((await accept(tokens[1] as string)).status).toBe(400)
  })

  // Scenario: the replacement grants a role above the revoker. Expected: it stays, indexed, and the
  // revoke answers as it does for an address with nothing pending. Why: the ceiling applies to
  // what is there, and the answer must not say that something is.
  it('leaves a replacement above the revoker, answering as for no invitation', async () => {
    await invite()
    afterRecordAccess('get', async () => {
      await replaceWithRole('OWNER')
    })

    const res = await revoke()

    const nothingPending = await request(app.getHttpServer())
      .post('/invitations/revoke')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ email: 'nobody@example.com' })
    expect([res.status, res.text]).toEqual([nothingPending.status, nothingPending.text])
    expect(await countKeys()).toEqual({ records: 1, indexes: 1 })
  })

  // Scenario: a re-invite lands after an acceptance has consumed the record and before it drops
  // the index. Expected: the replacement stays indexed, so a revoke removes it. Why: the
  // acceptance dropped whatever the index named, which was no longer the invitation it consumed.
  it('keeps a replacement revocable when it lands during an acceptance', async () => {
    const tokens = emailedTokens()
    await invite()
    afterRecordAccess('eval', async () => {
      await invite()
    })

    expect((await accept(tokens[0] as string)).status).toBe(201)

    expect(await countKeys()).toEqual({ records: 1, indexes: 1 })
    await revoke()
    expect(await countKeys()).toEqual({ records: 0, indexes: 0 })
  })

  // Scenario: the address is invited again after an acceptance that was raced by a re-invite.
  // Expected: that invite supersedes the replacement, leaving one record. Why: an invite deletes
  // only the record the index names, so a lost entry left two live tokens.
  it('leaves one live record after an invite that follows the race', async () => {
    const tokens = emailedTokens()
    await invite()
    afterRecordAccess('eval', async () => {
      await invite()
    })
    await accept(tokens[0] as string)

    expect((await invite()).status).toBe(204)

    expect(await countKeys()).toEqual({ records: 1, indexes: 1 })
  })

  // Scenario: the record is written some time after the claim. Expected: the index outlives, or
  // matches, the record it names. Why: both are given the full TTL but at different instants, so
  // the record would otherwise expire after the index and sit redeemable with no handle on it.
  it('keeps the index alive at least as long as the record it names', async () => {
    beforeRecordWrite(async () => {
      await new Promise((resolve) => setTimeout(resolve, 1_100))
    })

    const res = await invite()

    const { records, indexes } = await invitationKeys(
      boot.redis,
      boot.options.redisNamespace ?? 'auth'
    )
    expect(res.status).toBe(204)
    // The index is read FIRST. Its expiry is the record's or later, and a remaining time shrinks as
    // the clock advances, so reading it earlier keeps `indexTtl >= recordTtl` true however coarse
    // the clock: reading the record first lets a real server's clock tick between the two reads and
    // report the index a millisecond lower with an equal expiry.
    const indexTtl = await boot.redis.pttl(indexes[0] as string)
    const recordTtl = await boot.redis.pttl(records[0] as string)
    expect(indexTtl).toBeGreaterThanOrEqual(recordTtl)
  })
})
