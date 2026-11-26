/**
 * @fileoverview Tests for how the reply of the withdrawal script is read.
 *
 * @layer Test
 */

import { Test } from '@nestjs/testing'

import { AuthRedisService } from './auth-redis.service'
import { withdrawInvitation } from './withdraw-invitation.script'

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
