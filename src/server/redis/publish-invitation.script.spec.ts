/**
 * @fileoverview The keys and arguments `publishInvitation` sends, and how it reads the reply.
 *
 * The script itself runs in the e2e suites, over the invitation routes.
 */

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
