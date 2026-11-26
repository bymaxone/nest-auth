/**
 * @fileoverview Every integer Redis answers, as the string a client built with `stringNumbers` hands back.
 *
 * @layer Test
 */

import { Redis } from 'ioredis'

import { AuthRedisService } from './auth-redis.service'
import type { ResolvedOptions } from '../config/resolved-options'

/** The service over a client whose commands answer what `replies` names for them. */
function answering(replies: Record<string, unknown>): AuthRedisService {
  const client: Redis = Object.create(null)
  for (const [command, reply] of Object.entries(replies)) {
    Object.assign(client, { [command]: (): Promise<unknown> => Promise.resolve(reply) })
  }
  const options: ResolvedOptions = Object.assign(Object.create(null), {
    redisNamespace: 'spec',
    hmacKey: 'string-replies-spec-key'
  })
  return new AuthRedisService(client, options)
}

describe('AuthRedisService over a client that answers integers as strings', () => {
  // Scenario: each counting command answers a string. Expected: the number it spells. Why: a string
  // is never `===` a number, so a cap compared that way never fires, and a string reaches a response body.
  it.each([
    ['incr', { incr: '5' }, (s: AuthRedisService) => s.incr('k'), 5],
    ['ttl', { ttl: '-2' }, (s: AuthRedisService) => s.ttl('k'), -2],
    ['sadd', { sadd: '1' }, (s: AuthRedisService) => s.sadd('k', 'm'), 1],
    ['srem', { srem: '0' }, (s: AuthRedisService) => s.srem('k', 'm'), 0],
    ['sismember', { sismember: '1' }, (s: AuthRedisService) => s.sismember('k', 'm'), true],
    ['incrWithFixedTtl', { eval: '4' }, (s: AuthRedisService) => s.incrWithFixedTtl('k', 60), 4],
    [
      'bumpUserTokenEpoch',
      { eval: '2' },
      (s: AuthRedisService) => s.bumpUserTokenEpoch('u1', 't1', 'dashboard'),
      2
    ]
  ])('reads %s', async (_command, replies, call, expected) => {
    await expect(call(answering(replies))).resolves.toBe(expected)
  })

  // Scenario: the family revocation counts what it removed. Expected: the count.
  it('reports the members a family revocation removed', async () => {
    const service = answering({ smembers: [], eval: '3' })

    await expect(service.revokeFamily('fam-1')).resolves.toEqual({ removed: 3, ownerId: '' })
  })

  // Scenario: a grace recovery asks whether its family still exists. Expected: `1` as a string says yes.
  // Why: read as no, a client's one retry is refused.
  it('recovers a grace pointer whose family exists', async () => {
    const sessionJson = JSON.stringify({ familyId: 'fam-1' })
    const service = answering({ eval: `GRACE:${sessionJson}`, exists: '1' })

    await expect(
      service.rotateRefreshSession({
        kind: 'dashboard',
        tenantId: 't1',
        userId: 'u1',
        familyId: 'fam-1',
        oldHash: 'old',
        newHash: 'new',
        newSessionJson: '{}',
        refreshTtl: 60,
        graceTtl: 10
      })
    ).resolves.toEqual({ kind: 'grace', sessionJson })
  })
})
