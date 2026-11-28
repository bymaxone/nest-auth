/**
 * @fileoverview What removing one session through {@link endStoredSession} ends and announces.
 *
 * @layer Test
 */

import { endStoredSession, removeStoredSession } from './remove-session'

const familyId = '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b'
const session = { userId: 'u1', tenantId: 't1', sessionHash: 'a'.repeat(64) }
const options = { hmacKey: 'k', jwt: { accessExpiresIn: '5m' } }

/** A store that owns the session unless told otherwise. */
function store() {
  return {
    readSessionOwner: jest.fn().mockResolvedValue({ familyId }),
    eval: jest.fn().mockResolvedValue(1),
    set: jest.fn().mockResolvedValue(undefined),
    revokeFamily: jest.fn().mockResolvedValue({ sessionHashes: [session.sessionHash] })
  }
}

/** Runs the removal over `redis`. */
const end = (
  redis: ReturnType<typeof store>,
  announce: (sessionIds: string[]) => void,
  target = session,
  withoutFamily?: () => Promise<unknown>
) => endStoredSession(redis, options, target, announce, withoutFamily)

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

  // Scenario: the sign-in holds a second session. Expected: both named, the named one once and
  // first.
  it('announces the other sessions of the sign-in with the named one', async () => {
    const redis = store()
    redis.revokeFamily.mockResolvedValue({ sessionHashes: ['sibling', session.sessionHash] })
    const announce = jest.fn()

    await end(redis, announce)

    expect(redis.revokeFamily).toHaveBeenCalledWith(familyId, 'dashboard')
    expect(announce.mock.calls).toEqual([[[session.sessionHash, 'sibling']]])
  })

  // Scenario: the sign-in is removed and the entry refused. Expected: every removed session named.
  it('names the siblings when the entry is refused', async () => {
    const redis = store()
    redis.revokeFamily.mockResolvedValue({ sessionHashes: ['sibling'] })
    redis.set.mockRejectedValue(new Error('READONLY'))
    const announce = jest.fn()

    await expect(end(redis, announce)).rejects.toThrow('READONLY')

    expect(announce.mock.calls).toEqual([[[session.sessionHash, 'sibling']]])
  })

  // Scenario: the family cannot be revoked. Expected: no entry, which would leave a live session
  // refreshing into refused tokens.
  it('writes no entry when the family is not revoked', async () => {
    const redis = store()
    redis.revokeFamily.mockRejectedValue(new Error('READONLY'))
    const announce = jest.fn()

    await expect(end(redis, announce)).rejects.toThrow('READONLY')

    expect(redis.set).not.toHaveBeenCalled()
    expect(announce.mock.calls).toEqual([[[session.sessionHash]]])
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

  // Scenario: a record that names its family, and one that does not. Expected: the fallback runs
  // only for the second, in place of the entry write.
  it.each([
    [familyId, 1, 0],
    [undefined, 0, 1]
  ])('with family %p writes %i entries and runs the fallback %i times', async (id, sets, falls) => {
    const redis = store()
    redis.readSessionOwner.mockResolvedValue({ familyId: id })
    const withoutFamily = jest.fn().mockResolvedValue(undefined)

    await end(redis, jest.fn(), session, withoutFamily)

    expect(redis.set).toHaveBeenCalledTimes(sets)
    expect(withoutFamily).toHaveBeenCalledTimes(falls)
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

describe('removeStoredSession', () => {
  // Scenario: called directly, as logout does, with a malformed hash or a blank tenant. Expected:
  // refused before the store is reached.
  it.each([
    { ...session, sessionHash: 'x' },
    { ...session, tenantId: '' }
  ])('refuses %o before reaching the store', async (target) => {
    const redis = store()

    await expect(removeStoredSession(redis, options.hmacKey, target)).rejects.toMatchObject({
      response: { error: { code: 'auth.validation' } }
    })

    expect(redis.eval).not.toHaveBeenCalled()
  })
})
