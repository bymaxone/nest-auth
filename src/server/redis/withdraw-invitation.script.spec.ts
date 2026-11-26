/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />
/**
 * @fileoverview Tests for the withdrawal script, run against the in-memory Redis, and for how its
 * reply is read.
 *
 * @layer Test
 */

import { Test } from '@nestjs/testing'
import RedisMock from 'ioredis-mock'

import { AuthRedisService } from './auth-redis.service'
import { withdrawInvitation } from './withdraw-invitation.script'

/** A store that runs each script it is given on the in-memory Redis. */
function storeOver(redis: InstanceType<typeof RedisMock>): AuthRedisService {
  const run = (script: string, keys: string[], args: string[]): Promise<unknown> =>
    redis.eval(script, keys.length, ...keys, ...args)
  return { eval: run } as Partial<AuthRedisService> as AuthRedisService
}

describe('withdrawInvitation', () => {
  const redis = { eval: jest.fn() }
  let store: AuthRedisService

  beforeEach(async () => {
    jest.resetAllMocks()
    const module = await Test.createTestingModule({
      providers: [{ provide: AuthRedisService, useValue: redis }]
    }).compile()
    store = module.get(AuthRedisService)
  })

  // Scenario: each reply the script gives, as a number and as the string a `stringNumbers` client builds. Expected: `-1` is a
  // changed address, `0` an index with no record, `1` a removal. Why: a changed address is read again, the others are answers.
  it.each([
    [-1, 'changed'],
    ['-1', 'changed'],
    [0, 'absent'],
    ['0', 'absent'],
    [1, 'removed'],
    ['1', 'removed']
  ])('reads %p as %s', async (reply, outcome) => {
    redis.eval.mockResolvedValueOnce(reply)

    await expect(withdrawInvitation(store, 'invidx:t:a', 'h', 'record')).resolves.toBe(outcome)
  })
})

describe('WITHDRAW_INVITATION_SCRIPT', () => {
  const INDEX = 'invidx:t:a'
  let redis: InstanceType<typeof RedisMock>
  let port = 7500

  beforeEach(async () => {
    redis = new RedisMock({ port: port++ })
    await redis.set(INDEX, 'h')
  })

  afterEach(() => redis.disconnect())

  /** Withdraws the invitation `h`, having read `judged` under it. */
  const withdraw = (judged: string | null): Promise<string> =>
    withdrawInvitation(storeOver(redis), INDEX, 'h', judged)

  // The record and its index go together.
  it('removes the record it was shown and the index', async () => {
    await redis.set('inv:h', 'record')

    await expect(withdraw('record')).resolves.toBe('removed')

    expect(await redis.keys('*')).toEqual([])
  })

  // An index with no record is dropped, and nothing is reported as removed.
  it('drops an index that has no record', async () => {
    await expect(withdraw(null)).resolves.toBe('absent')

    expect(await redis.keys('*')).toEqual([])
  })

  // Nobody has judged a record written or replaced after the read, so it stays.
  it.each([
    ['replaced after the read', 'record'],
    ['written after a read that found none', null]
  ])('leaves a record %s', async (_label, judged) => {
    await redis.set('inv:h', 'newer')

    await expect(withdraw(judged)).resolves.toBe('changed')

    expect(await redis.get('inv:h')).toBe('newer')
    expect(await redis.get(INDEX)).toBe('h')
  })

  // The address moved to another invitation since the read.
  it('deletes nothing when the index names another hash', async () => {
    await redis.set(INDEX, 'other')
    await redis.set('inv:h', 'record')

    await expect(withdraw('record')).resolves.toBe('changed')

    expect(await redis.get('inv:h')).toBe('record')
    expect(await redis.get(INDEX)).toBe('other')
  })
})
