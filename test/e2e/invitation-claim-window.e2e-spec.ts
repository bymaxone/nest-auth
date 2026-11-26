/**
 * @fileoverview Writers that overlap on one invitee address.
 *
 * `invite` stores the record and the index that names it in one step, and a revoke removes both in
 * one step. These cases put a second request, a failing command or another writer of the keyspace
 * at a chosen point of that flow, which a single-threaded walk through the routes never shows.
 *
 * A revoke and an acceptance also read the index, or consume the record it names, before they drop
 * it, and a later invite of the address can claim the index in between.
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

describe('invitation writers that overlap (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let adminToken: string
  let sent: CapturedEmail[]

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

  /** Runs `beforeWrite` once, immediately before the first command that stores a record. */
  function beforeRecordWrite(beforeWrite: () => Promise<void>): void {
    let done = false
    for (const command of ['set', 'eval'] as const) {
      const original = (boot.redis[command] as (...a: unknown[]) => Promise<unknown>).bind(
        boot.redis
      )
      jest.spyOn(boot.redis, command).mockImplementation((async (...args: unknown[]) => {
        if (!done && args.some((arg) => String(arg).includes(':inv:'))) {
          done = true
          await beforeWrite()
        }
        return original(...args)
      }) as never)
    }
  }

  /** The invitation keys counted after each command that changes one. */
  function statesAfterEachWrite(): { records: number; indexes: number }[] {
    const states: { records: number; indexes: number }[] = []
    for (const command of ['set', 'del', 'eval'] as const) {
      const original = (boot.redis[command] as (...a: unknown[]) => Promise<unknown>).bind(
        boot.redis
      )
      jest.spyOn(boot.redis, command).mockImplementation((async (...args: unknown[]) => {
        const reply = await original(...args)
        if (args.some((arg) => String(arg).includes(':inv'))) states.push(await countKeys())
        return reply
      }) as never)
    }
    return states
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

  // Scenario: the keyspace is read after each command of an invite and of a re-invite. Expected:
  // an index and a record, or neither. Why: an index with no record gives a revoke nothing to
  // judge, and a record with no index is redeemable and out of reach of every revoke.
  it('never holds an address without its record, or a record without its address', async () => {
    const states = statesAfterEachWrite()

    await invite()
    await invite()

    expect(states.length).toBeGreaterThan(0)
    expect(states).toEqual(states.map(() => ({ records: 1, indexes: 1 })))
  })

  // Scenario: a revoke runs to completion just before the invite stores its invitation. Expected:
  // both answer 204 and the invitation is stored and indexed. Why: that revoke found nothing
  // pending, so it removes nothing and the invite owes it nothing.
  it('stores an indexed invitation when a revoke ran just before it', async () => {
    const tokens = emailedTokens()
    let revoked = 0
    beforeRecordWrite(async () => {
      revoked = (await revoke()).status
    })

    const res = await invite()

    expect([revoked, res.status]).toEqual([204, 204])
    expect(await countKeys()).toEqual({ records: 1, indexes: 1 })
    expect((await accept(tokens[0] as string)).status).toBe(201)
  })

  // Scenario: a re-invite lands after a revoke has read the invitation and before it releases the
  // index. Expected: the release leaves the replacement indexed, and the same revoke reads the
  // address again and removes it. Why: an index dropped without comparing it leaves the new token
  // redeemable, out of reach of every later revoke, and lets a further invite add a second live
  // token beside it.
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
  // the index. Expected: the replacement stays indexed, so a revoke removes it. Why: the index can
  // name an invitation other than the one consumed, so it is released only while it names that one.
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
  // only the record the index names, so a lost entry leaves two live tokens.
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

  /** Fails, once, the next `del` or script that names an invitation record. */
  function failNextRecordRemoval(): void {
    let failed = false
    for (const command of ['del', 'eval'] as const) {
      const original = (boot.redis[command] as (...a: unknown[]) => Promise<unknown>).bind(
        boot.redis
      )
      jest.spyOn(boot.redis, command).mockImplementation((async (...args: unknown[]) => {
        if (!failed && args.some((arg) => String(arg).includes(':inv:'))) {
          failed = true
          throw new Error('store down')
        }
        return original(...args)
      }) as never)
    }
  }

  /** Takes the stored record away, leaving the index, and returns how to put it back. */
  async function holdRecordBack(change: object = {}): Promise<() => Promise<void>> {
    const namespace = boot.options.redisNamespace ?? 'auth'
    const [key] = (await invitationKeys(boot.redis, namespace)).records
    const stored = JSON.parse((await boot.redis.get(key as string)) as string) as object
    await boot.redis.del(key as string)
    return async () => {
      const record = JSON.stringify({ ...stored, ...change })
      await boot.redis.set(key as string, record, 'EX', TTL_SECONDS)
    }
  }

  // Scenario: a revoke reads an address whose record is not there, another writer of the keyspace
  // then stores it, and the one command that removes the record fails. Expected: the revoke errors,
  // the record stays indexed and trying again removes it. Why: an index released on its own leaves
  // the emailed token acceptable with nothing that reaches it.
  it('keeps the record revocable when its removal fails after it appeared', async () => {
    const tokens = emailedTokens()
    await invite()
    const putBack = await holdRecordBack()
    afterRecordAccess('get', async () => {
      await putBack()
      failNextRecordRemoval()
    })

    expect((await revoke()).status).toBe(500)

    expect(await countKeys()).toEqual({ records: 1, indexes: 1 })
    expect((await revoke()).status).toBe(204)
    expect(await countKeys()).toEqual({ records: 0, indexes: 0 })
    expect((await accept(tokens[0] as string)).status).toBe(400)
  })

  // Scenario: a re-invite fails at the first command that would remove or replace the pending
  // record. Expected: the pending invitation is still stored, indexed and revocable. Why: a failed
  // re-invite must not leave the earlier token redeemable under an address that names another.
  it('keeps the pending invitation when its replacement cannot be stored', async () => {
    const tokens = emailedTokens()
    await invite()
    failNextRecordRemoval()

    expect((await invite()).status).toBe(500)

    expect((await revoke()).status).toBe(204)
    expect(await countKeys()).toEqual({ records: 0, indexes: 0 })
    expect((await accept(tokens[0] as string)).status).toBe(400)
  })

  // Scenario: the record a revoke found missing is written before the revoke removes anything, and
  // grants a role above the revoker. Expected: it stays, indexed. Why: the ceiling applies to the
  // record that would be removed, so one that appeared is read before it is judged.
  it('leaves a record above the revoker that is written while the revoke is under way', async () => {
    await invite()
    const putBack = await holdRecordBack({ role: 'OWNER' })
    afterRecordAccess('get', putBack)

    expect((await revoke()).status).toBe(204)

    expect(await countKeys()).toEqual({ records: 1, indexes: 1 })
  })

  // Scenario: an invitation is stored. Expected: the index outlives, or matches, the record it
  // names. Why: a record that expires after its index sits redeemable with no handle on it.
  it('keeps the index alive at least as long as the record it names', async () => {
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
