/**
 * @fileoverview Tests for the workspace invitation store over an in-memory Redis: the record, the
 * index compare-and-set, the pending set and what a foreign value under a key reads as.
 *
 * @layer Test
 */

/// <reference path="../../../test/e2e/ioredis-mock.d.ts" />

import type { Redis } from 'ioredis'
import RedisMock from 'ioredis-mock'

import { WORKSPACE_REF, workspaceOptions } from './__tests__/workspace-service-harness'
import { WorkspaceInvitationStore } from './workspace-invitation.store'
import { invitationIndexKey, invitationSetKey } from '../constants/workspace-invitation-keys'
import type { StoredWorkspaceInvitation } from '../interfaces/workspace-invitation.interface'
import { AuthRedisService } from '../redis/auth-redis.service'

let port = 44_000
const EMAIL = 'a@example.com'

function record(overrides: Partial<StoredWorkspaceInvitation> = {}): StoredWorkspaceInvitation {
  return {
    email: EMAIL,
    role: 'viewer',
    tenantId: 't1',
    workspaceId: 'w1',
    inviterUserId: 'u1',
    createdAt: '2026-01-10T12:00:00.000Z',
    resendCount: 0,
    ...overrides
  }
}

function build(): { store: WorkspaceInvitationStore; redis: AuthRedisService; hmacKey: string } {
  const options = workspaceOptions()
  const redis = new AuthRedisService(
    new RedisMock({ port: (port += 1) }) as Partial<Redis> as Redis,
    options
  )
  return { store: new WorkspaceInvitationStore(redis, options), redis, hmacKey: options.hmacKey }
}

describe('WorkspaceInvitationStore', () => {
  it('writes a record that reads back by its digest, with the lifetime it was given', async () => {
    const { store, redis } = build()

    await store.write(WORKSPACE_REF, 'winv:h1', record(), 300)

    expect(await store.readByHash('h1')).toEqual(record())
    expect(await redis.ttl('winv:h1')).toBe(300)
  })

  it('lists the record as pending and keeps the set alive as long as the record', async () => {
    const { store, redis, hmacKey } = build()

    await store.write(WORKSPACE_REF, 'winv:h1', record(), 300)

    expect(await redis.smembers(invitationSetKey('t1', 'w1', hmacKey))).toEqual(['winv:h1'])
    expect(await redis.ttl(invitationSetKey('t1', 'w1', hmacKey))).toBe(300)
  })

  describe('write with a limit', () => {
    it('lists a record while the workspace is under the limit and refuses it at the limit, leaving nothing', async () => {
      const { store, redis } = build()

      expect(await store.write(WORKSPACE_REF, 'winv:a', record(), 300, 2)).toBe(true)
      expect(await store.write(WORKSPACE_REF, 'winv:b', record(), 300, 2)).toBe(true)
      expect(await store.write(WORKSPACE_REF, 'winv:c', record(), 300, 2)).toBe(false)

      expect(await redis.get('winv:c')).toBeNull()
      expect((await store.pending(WORKSPACE_REF)).map((p) => p.key).sort()).toEqual([
        'winv:a',
        'winv:b'
      ])
    })

    it('has no limit when none is given', async () => {
      const { store } = build()

      for (const key of ['winv:a', 'winv:b', 'winv:c']) {
        expect(await store.write(WORKSPACE_REF, key, record(), 300)).toBe(true)
      }
    })
  })

  it.each([
    ['absent', null],
    ['not JSON', 'not json'],
    ['not an object', '"text"'],
    ['null', 'null'],
    ['missing a field', JSON.stringify({ ...record(), role: undefined })],
    ['a wrong field type', JSON.stringify({ ...record(), resendCount: '0' })]
  ])('reads a value that is %s as no record', async (_name, raw) => {
    const { store, redis } = build()
    if (raw !== null) await redis.set('winv:h1', raw)

    expect(await store.readByHash('h1')).toBeNull()
  })

  it.each(['email', 'role', 'tenantId', 'workspaceId', 'inviterUserId', 'createdAt'])(
    'refuses a record whose %s is not a string',
    async (field) => {
      const { store, redis } = build()
      await redis.set('winv:h1', JSON.stringify({ ...record(), [field]: 7 }))

      expect(await store.readByHash('h1')).toBeNull()
    }
  )

  it('names nothing for an address with no index', async () => {
    const { store } = build()

    expect(await store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
  })

  it('names the key and record an index points at, and the key alone when the record is gone', async () => {
    const { store } = build()
    await store.write(WORKSPACE_REF, 'winv:h1', record(), 300)
    await store.claimIndex(WORKSPACE_REF, EMAIL, null, 'winv:h1', 300)

    expect(await store.readByEmail(WORKSPACE_REF, EMAIL)).toEqual({
      key: 'winv:h1',
      record: record()
    })

    await store.remove(WORKSPACE_REF, 'other@example.com', 'winv:h1')

    expect(await store.readByEmail(WORKSPACE_REF, EMAIL)).toEqual({ key: 'winv:h1', record: null })
  })

  describe('claimIndex', () => {
    it('claims an absent index only when none was expected, and gives it the lifetime', async () => {
      const { store, redis, hmacKey } = build()

      expect(await store.claimIndex(WORKSPACE_REF, EMAIL, 'winv:old', 'winv:new', 300)).toBe(false)
      expect(await store.claimIndex(WORKSPACE_REF, EMAIL, null, 'winv:new', 300)).toBe(true)
      expect(await redis.ttl(invitationIndexKey('t1', 'w1', EMAIL, hmacKey))).toBe(300)
    })

    it('replaces the index only while it still names the key that was read', async () => {
      const { store } = build()
      await store.claimIndex(WORKSPACE_REF, EMAIL, null, 'winv:a', 300)

      expect(await store.claimIndex(WORKSPACE_REF, EMAIL, 'winv:stale', 'winv:b', 300)).toBe(false)
      expect(await store.claimIndex(WORKSPACE_REF, EMAIL, null, 'winv:b', 300)).toBe(false)
      expect(await store.claimIndex(WORKSPACE_REF, EMAIL, 'winv:a', 'winv:b', 300)).toBe(true)
      expect((await store.readByEmail(WORKSPACE_REF, EMAIL))?.key).toBe('winv:b')
    })

    it('keeps one address in one workspace apart from the same address elsewhere', async () => {
      const { store } = build()
      await store.claimIndex(WORKSPACE_REF, EMAIL, null, 'winv:a', 300)

      expect(await store.readByEmail({ tenantId: 't1', workspaceId: 'w2' }, EMAIL)).toBeNull()
      expect(await store.readByEmail({ tenantId: 't2', workspaceId: 'w1' }, EMAIL)).toBeNull()
    })
  })

  describe('remove', () => {
    it('deletes the record, its place in the set and the index that names it', async () => {
      const { store } = build()
      await store.write(WORKSPACE_REF, 'winv:h1', record(), 300)
      await store.claimIndex(WORKSPACE_REF, EMAIL, null, 'winv:h1', 300)

      await store.remove(WORKSPACE_REF, EMAIL, 'winv:h1')

      expect(await store.readByHash('h1')).toBeNull()
      expect(await store.pending(WORKSPACE_REF)).toEqual([])
      expect(await store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
    })

    it('leaves an index that already names a newer record', async () => {
      const { store } = build()
      await store.write(WORKSPACE_REF, 'winv:old', record(), 300)
      await store.write(WORKSPACE_REF, 'winv:new', record(), 300)
      await store.claimIndex(WORKSPACE_REF, EMAIL, null, 'winv:new', 300)

      await store.remove(WORKSPACE_REF, EMAIL, 'winv:old')

      expect((await store.readByEmail(WORKSPACE_REF, EMAIL))?.key).toBe('winv:new')
      expect((await store.pending(WORKSPACE_REF)).map((p) => p.key)).toEqual(['winv:new'])
    })
  })

  describe('pending', () => {
    it('lists live records with their remaining lifetime and drops members whose record is gone', async () => {
      const { store, redis, hmacKey } = build()
      await store.write(WORKSPACE_REF, 'winv:live', record(), 300)
      await store.write(WORKSPACE_REF, 'winv:dead', record({ email: 'b@example.com' }), 300)
      await redis.del('winv:dead')

      const prune = jest.spyOn(redis, 'pruneDeadMembers')
      const pending = await store.pending(WORKSPACE_REF)

      expect(prune).toHaveBeenCalledWith(invitationSetKey('t1', 'w1', hmacKey), ['winv:dead'])
      expect(pending).toEqual([{ key: 'winv:live', record: record(), ttlSeconds: 300 }])
      expect(await redis.smembers(invitationSetKey('t1', 'w1', hmacKey))).toEqual(['winv:live'])
    })

    it('asks to prune nothing when every member is live', async () => {
      const { store, redis, hmacKey } = build()
      await store.write(WORKSPACE_REF, 'winv:live', record(), 300)
      const prune = jest.spyOn(redis, 'pruneDeadMembers')

      await store.pending(WORKSPACE_REF)

      expect(prune).toHaveBeenCalledWith(invitationSetKey('t1', 'w1', hmacKey), [])
    })

    it('lists nothing for a workspace with no invitations', async () => {
      const { store } = build()

      expect(await store.pending(WORKSPACE_REF)).toEqual([])
    })
  })
})
