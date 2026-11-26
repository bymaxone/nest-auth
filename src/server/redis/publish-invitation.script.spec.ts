/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />
/**
 * @fileoverview The keys and arguments `publishInvitation` sends, and how it reads the reply.
 *
 * The script also runs here, for real, against the in-memory Redis.
 *
 * @layer Test
 */

import RedisMock from 'ioredis-mock'

import type { AuthRedisService } from './auth-redis.service'
import { PUBLISH_INVITATION_SCRIPT, publishInvitation } from './publish-invitation.script'

const PUBLICATION = {
  indexKey: 'invidx:t:who',
  tokenHash: 'new',
  record: '{"role":"member"}',
  ttl: 60,
  superseded: null
}

/** A store whose script answers `reply`. */
function storeAnswering(reply: unknown): { redis: AuthRedisService; evaluate: jest.Mock } {
  const evaluate = jest.fn().mockResolvedValue(reply)
  return { redis: { eval: evaluate } as Partial<AuthRedisService> as AuthRedisService, evaluate }
}

/** A store that runs each script it is given on the in-memory Redis. */
function storeOver(redis: InstanceType<typeof RedisMock>): AuthRedisService {
  const run = (script: string, keys: string[], args: string[]): Promise<unknown> =>
    redis.eval(script, keys.length, ...keys, ...args)
  return { eval: run } as Partial<AuthRedisService> as AuthRedisService
}

describe('publishInvitation', () => {
  // With nothing pending the index must be absent, spelled as the empty string.
  it('asks for an absent index when nothing is superseded', async () => {
    const { redis, evaluate } = storeAnswering(1)

    await publishInvitation(redis, PUBLICATION)

    expect(evaluate.mock.calls).toEqual([
      [
        PUBLISH_INVITATION_SCRIPT,
        ['invidx:t:who', 'inv:new', 'inv:new'],
        ['', 'new', '{"role":"member"}', '60']
      ]
    ])
  })

  // The superseded record is declared as a key, so a client prefix reaches it.
  it('names the superseded record and expects the index to hold its hash', async () => {
    const { redis, evaluate } = storeAnswering(1)

    await publishInvitation(redis, { ...PUBLICATION, superseded: 'old' })

    expect(evaluate.mock.calls[0]?.slice(1)).toEqual([
      ['invidx:t:who', 'inv:new', 'inv:old'],
      ['old', 'new', '{"role":"member"}', '60']
    ])
  })

  // `stringNumbers` clients answer integers as strings.
  it.each([
    [1, true],
    ['1', true],
    [0, false],
    ['0', false]
  ])('reads the reply %p as stored %p', async (reply, stored) => {
    const { redis } = storeAnswering(reply)

    await expect(publishInvitation(redis, PUBLICATION)).resolves.toBe(stored)
  })
})

describe('PUBLISH_INVITATION_SCRIPT', () => {
  let redis: InstanceType<typeof RedisMock>
  let port = 7400

  beforeEach(() => {
    redis = new RedisMock({ port: port++ })
  })

  afterEach(() => redis.disconnect())

  // With nothing pending the record and the index are written, both for the lifetime asked.
  it('stores the record and its index', async () => {
    await expect(publishInvitation(storeOver(redis), PUBLICATION)).resolves.toBe(true)

    expect(await redis.get('inv:new')).toBe(PUBLICATION.record)
    expect(await redis.get(PUBLICATION.indexKey)).toBe('new')
    expect(await redis.ttl('inv:new')).toBe(60)
    expect(await redis.ttl(PUBLICATION.indexKey)).toBe(60)
  })

  // The superseded invitation must stop being redeemable in the same step.
  it('removes the superseded record', async () => {
    await redis.set(PUBLICATION.indexKey, 'old')
    await redis.set('inv:old', 'pending')

    await publishInvitation(storeOver(redis), { ...PUBLICATION, superseded: 'old' })

    expect((await redis.keys('*')).sort()).toEqual(['inv:new', PUBLICATION.indexKey])
    expect(await redis.get(PUBLICATION.indexKey)).toBe('new')
  })

  // Another invite got there first: its invitation is not the one the caller judged.
  it('writes nothing when the index holds another hash', async () => {
    await redis.set(PUBLICATION.indexKey, 'other')

    await expect(publishInvitation(storeOver(redis), PUBLICATION)).resolves.toBe(false)

    expect(await redis.keys('*')).toEqual([PUBLICATION.indexKey])
    expect(await redis.get(PUBLICATION.indexKey)).toBe('other')
  })
})
