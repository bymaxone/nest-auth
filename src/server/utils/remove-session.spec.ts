/**
 * @fileoverview What removing one session through {@link endStoredSession} ends and announces.
 *
 * @layer Test
 */

import { endStoredSession } from './remove-session'
import type { AuthRedisService } from '../redis/auth-redis.service'

const familyId = '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b'
const session = { userId: 'u1', tenantId: 't1', sessionHash: 'a'.repeat(64) }
const options = { hmacKey: 'k', jwt: { accessExpiresIn: '5m' } }

/** A store that owns the session unless told otherwise. */
function store() {
  return {
    readSessionOwner: jest.fn().mockResolvedValue({ familyId }),
    eval: jest.fn().mockResolvedValue(1),
    set: jest.fn().mockResolvedValue(undefined)
  }
}

/** Runs the removal over `redis`. */
const end = (redis: ReturnType<typeof store>, announce: () => void, target = session) =>
  endStoredSession(redis as unknown as AuthRedisService, options, target, announce)

describe('endStoredSession', () => {
  // Scenario: an owned session. Expected: the family is read before the removal, then ended.
  it('ends the access tokens of the removed session and announces it', async () => {
    const redis = store()
    const announce = jest.fn()

    await end(redis, announce)

    expect(redis.readSessionOwner).toHaveBeenCalledWith(`rt:${session.sessionHash}`)
    expect(redis.readSessionOwner.mock.invocationCallOrder[0]).toBeLessThan(
      redis.eval.mock.invocationCallOrder[0] ?? 0
    )
    expect(redis.set).toHaveBeenCalledWith(`rvs:${familyId}`, '1', 360)
    expect(announce).toHaveBeenCalledTimes(1)
  })

  // Scenario: a session the account does not own. Expected: nobody's access tokens are ended.
  it('writes and announces nothing for a session the account does not own', async () => {
    const redis = store()
    redis.eval.mockResolvedValue(0)
    const announce = jest.fn()

    await expect(end(redis, announce)).rejects.toMatchObject({
      response: { error: { code: 'auth.session_not_found' } }
    })

    expect(redis.set).not.toHaveBeenCalled()
    expect(announce).not.toHaveBeenCalled()
  })

  // Scenario: the session is removed and the access write refused. Expected: announced, then raised.
  it('announces the removal before raising a refused access write', async () => {
    const redis = store()
    redis.set.mockRejectedValue(new Error('READONLY'))
    const announce = jest.fn()

    await expect(end(redis, announce)).rejects.toThrow('READONLY')

    expect(announce).toHaveBeenCalledTimes(1)
  })

  // Scenario: a malformed hash or a blank tenant. Expected: refused before any key is read.
  it.each([
    { ...session, sessionHash: 'x' },
    { ...session, tenantId: '' }
  ])('refuses %o before reading the store', async (target) => {
    const redis = store()

    await expect(end(redis, jest.fn(), target)).rejects.toMatchObject({
      response: { error: { code: 'auth.validation' } }
    })

    expect(redis.readSessionOwner).not.toHaveBeenCalled()
  })
})
