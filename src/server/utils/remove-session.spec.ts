/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />
/**
 * @fileoverview What removing one session through {@link endStoredSession} ends and announces, with
 * its script run for real against the in-memory Redis.
 *
 * @layer Test
 */

import RedisMock from 'ioredis-mock'

import { endStoredSession, removeStoredSession } from './remove-session'
import type { ResolvedOptions } from '../config/resolved-options'
import { sessionIndexKey } from '../constants/user-keys'
import { AuthRedisService } from '../redis/auth-redis.service'

const familyId = '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b'
const named = 'a'.repeat(64)
const sibling = 'b'.repeat(64)
const elsewhere = 'c'.repeat(64)
const session = { userId: 'u1', tenantId: 't1', sessionHash: named }
const options = { hmacKey: 'k', jwt: { accessExpiresIn: '5m' } }
const index = sessionIndexKey('dashboard', 'u1', options.hmacKey, 't1')
const notFound = { response: { error: { code: 'auth.session_not_found' } } }
let port = 7600

describe('endStoredSession', () => {
  let client: InstanceType<typeof RedisMock>
  let redis: AuthRedisService

  /** One live session of `u1`, indexed, with its detail. */
  async function seed(hash: string, record: Record<string, unknown>): Promise<void> {
    await redis.set(`rt:${hash}`, JSON.stringify({ userId: 'u1', tenantId: 't1', ...record }), 600)
    await redis.set(`sd:${hash}`, '{}', 600)
    await client.sadd(`spec:${index}`, `rt:${hash}`)
  }

  /** Two sessions of one sign-in and a third of another. */
  async function signIns(): Promise<void> {
    await seed(named, { familyId })
    await seed(sibling, { familyId })
    await seed(elsewhere, {})
    await client.sadd(`spec:fam:${familyId}`, named, sibling)
  }

  const stored = async (): Promise<string[]> => (await client.keys('*')).sort()

  const end = (
    announce: (sessionIds: string[]) => void,
    target = session,
    withoutFamily?: () => Promise<unknown>
  ): Promise<void> => endStoredSession(redis, options, target, announce, withoutFamily)

  /** A client, with whatever the host set on it, and the service over it. */
  function connect(host: { keyPrefix?: string } = {}): void {
    client = new RedisMock({ port, ...host })
    const resolved: ResolvedOptions = Object.assign(Object.create(null), {
      redisNamespace: 'spec',
      hmacKey: options.hmacKey
    })
    redis = new AuthRedisService(client as never, resolved)
  }

  beforeEach(() => {
    port += 1
    connect()
  })

  afterEach(() => client.disconnect())

  // Scenario: one of two sessions of a sign-in is ended. Expected: both and their details are gone,
  // the family with them, the entry stands for the access lifetime and a margin, and the other
  // sign-in is untouched.
  it('ends every session of the sign-in and writes the entry', async () => {
    await signIns()
    const announce = jest.fn()

    await end(announce)

    expect(await stored()).toEqual(
      [
        `spec:rt:${elsewhere}`,
        `spec:rvs:${familyId}`,
        `spec:sd:${elsewhere}`,
        `spec:${index}`
      ].sort()
    )
    expect(await client.smembers(`spec:${index}`)).toEqual([`rt:${elsewhere}`])
    expect(await redis.get(`rvs:${familyId}`)).toBe('1')
    expect(await client.ttl(`spec:rvs:${familyId}`)).toBe(360)
    expect(announce.mock.calls).toEqual([[[named, sibling]]])
  })

  // Scenario: a host client with its own key prefix. Expected: the siblings, whose keys the script
  // builds itself, are removed under that prefix too.
  it('removes the siblings under the key prefix of the host client', async () => {
    client.disconnect()
    connect({ keyPrefix: 'host:' })
    await signIns()

    await end(jest.fn())

    const raw = new RedisMock({ port })
    const kept = (await raw.keys('*')).filter((key: string) => key.includes(sibling))
    raw.disconnect()
    expect(kept).toEqual([])
  })

  // Scenario: the family set has expired. Expected: the named session is ended all the same.
  it('ends the named session of a sign-in whose family set is gone', async () => {
    await seed(named, { familyId })
    const announce = jest.fn()

    await end(announce)

    expect(await stored()).toEqual([`spec:rvs:${familyId}`])
    expect(announce.mock.calls).toEqual([[[named]]])
  })

  // Scenario: the record names a family and the account's index does not hold the session.
  // Expected: not found, nothing written and nothing announced.
  it('writes and announces nothing for a session the account does not own', async () => {
    await signIns()
    await client.srem(`spec:${index}`, `rt:${named}`)
    const before = await stored()
    const announce = jest.fn()

    await expect(end(announce)).rejects.toMatchObject(notFound)

    expect(await stored()).toEqual(before)
    expect(announce).not.toHaveBeenCalled()
  })

  // Scenario: the store refuses the script. Expected: its error, and nothing announced, so the call
  // is there to be repeated.
  it('announces nothing when the script is refused', async () => {
    await signIns()
    jest.spyOn(redis, 'eval').mockRejectedValue(new Error('READONLY'))
    const announce = jest.fn()

    await expect(end(announce)).rejects.toThrow('READONLY')

    expect(announce).not.toHaveBeenCalled()
  })

  // Scenario: a client that decodes integers as strings, and an answer that is neither a count nor
  // a list. Expected: the first reads as not owned, the second is refused.
  it.each([
    ['0', notFound],
    [1, { response: { error: { code: 'auth.internal' } } }]
  ])('reads the answer %p of the script', async (reply, refusal) => {
    await signIns()
    jest.spyOn(redis, 'eval').mockResolvedValue(reply)
    const announce = jest.fn()

    await expect(end(announce)).rejects.toMatchObject(refusal)

    expect(announce).not.toHaveBeenCalled()
  })

  // Scenario: a record that names no family, with a fallback. Expected: the fallback runs while the
  // session is still there, then the session is removed and announced.
  it('runs the fallback before removing a session that names no family', async () => {
    await seed(named, {})
    const seen: string[][] = []
    const announce = jest.fn()

    await end(announce, session, async () => {
      seen.push(await stored())
    })

    expect(seen).toEqual([[`spec:rt:${named}`, `spec:sd:${named}`, `spec:${index}`].sort()])
    expect(await stored()).toEqual([])
    expect(announce.mock.calls).toEqual([[[named]]])
  })

  // Scenario: the same record and the fallback refused. Expected: the session stays, for the call
  // to be repeated.
  it('keeps the session when the fallback is refused', async () => {
    await seed(named, {})
    const announce = jest.fn()
    const refused = (): Promise<never> => Promise.reject(new Error('READONLY'))

    await expect(end(announce, session, refused)).rejects.toThrow('READONLY')

    expect(await redis.get(`rt:${named}`)).not.toBeNull()
    expect(announce).not.toHaveBeenCalled()
  })

  // Scenario: a session of no family that the account does not own. Expected: no fallback, which
  // would end the access tokens of the caller for a session that is not theirs.
  it('runs no fallback for a session the account does not own', async () => {
    const withoutFamily = jest.fn()

    await expect(end(jest.fn(), session, withoutFamily)).rejects.toMatchObject(notFound)

    expect(withoutFamily).not.toHaveBeenCalled()
  })

  // Scenario: no family and no fallback. Expected: removed, and nothing else written.
  it('removes a session that names no family and writes nothing', async () => {
    await seed(named, {})
    const announce = jest.fn()

    await end(announce)

    expect(await stored()).toEqual([])
    expect(announce.mock.calls).toEqual([[[named]]])
  })

  // Scenario: a malformed hash or a blank tenant. Expected: refused before any key is read, by this
  // function and by the plain removal logout calls.
  it.each([
    { ...session, sessionHash: 'x' },
    { ...session, tenantId: '' }
  ])('refuses %o before reaching the store', async (target) => {
    const read = jest.spyOn(redis, 'readSessionOwner')
    const script = jest.spyOn(redis, 'eval')
    const refusal = { response: { error: { code: 'auth.validation' } } }

    await expect(end(jest.fn(), target)).rejects.toMatchObject(refusal)
    await expect(removeStoredSession(redis, options.hmacKey, target)).rejects.toMatchObject(refusal)

    expect(read).not.toHaveBeenCalled()
    expect(script).not.toHaveBeenCalled()
  })
})
