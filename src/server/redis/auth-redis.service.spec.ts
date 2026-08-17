/**
 * @fileoverview Tests for AuthRedisService, which wraps an ioredis client and
 * automatically namespaces all keys with the configured prefix. Covers all
 * string, set, counter, expiry, Lua eval, and atomic compound operations.
 */

import { createHash } from 'node:crypto'
import { inspect } from 'node:util'

import { Test } from '@nestjs/testing'

import type { Redis } from 'ioredis'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { hmacSha256 } from '../crypto/secure-token'
import { AuthRedisService } from './auth-redis.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const NAMESPACE = 'auth'

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  incr: jest.fn(),
  expire: jest.fn(),
  ttl: jest.fn(),
  sadd: jest.fn(),
  srem: jest.fn(),
  smembers: jest.fn(),
  sismember: jest.fn(),
  exists: jest.fn(),
  eval: jest.fn()
}

// Note: setnx in AuthRedisService calls redis.set(..., 'NX'), not a separate redis.setnx method.

/** Mirrors the `hmacKey` the mock options carry, so a key can be spelled out. */
const HMAC_KEY = 'test-hmac-key'

const mockOptions = { redisNamespace: NAMESPACE, hmacKey: 'test-hmac-key' }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function prefixed(key: string): string {
  return `${NAMESPACE}:${key}`
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('AuthRedisService', () => {
  let service: AuthRedisService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        AuthRedisService,
        { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    service = module.get(AuthRedisService)
  })

  // ---------------------------------------------------------------------------
  // get
  // ---------------------------------------------------------------------------

  describe('get', () => {
    // Verifies that get forwards a namespace-prefixed key to redis.get and returns the stored value.
    it('should call redis.get with prefixed key', async () => {
      mockRedis.get.mockResolvedValue('value')
      const result = await service.get('mykey')
      expect(mockRedis.get).toHaveBeenCalledWith(prefixed('mykey'))
      expect(result).toBe('value')
    })

    // Verifies that get returns null when the key does not exist in Redis.
    it('should return null when key does not exist', async () => {
      mockRedis.get.mockResolvedValue(null)
      expect(await service.get('missing')).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // set
  // ---------------------------------------------------------------------------

  describe('set', () => {
    // Verifies that set uses the EX flag when a TTL is provided.
    it('should call redis.set with EX when ttl is provided', async () => {
      mockRedis.set.mockResolvedValue('OK')
      await service.set('k', 'v', 60)
      expect(mockRedis.set).toHaveBeenCalledWith(prefixed('k'), 'v', 'EX', 60)
    })

    // Verifies that set omits the EX flag when no TTL is provided (persistent key).
    it('should call redis.set without EX when ttl is omitted', async () => {
      mockRedis.set.mockResolvedValue('OK')
      await service.set('k', 'v')
      expect(mockRedis.set).toHaveBeenCalledWith(prefixed('k'), 'v')
    })
  })

  // ---------------------------------------------------------------------------
  // setnx
  // ---------------------------------------------------------------------------

  describe('setnx', () => {
    // Verifies that setnx calls redis.set with EX, NX flags and returns true when redis returns 'OK' (key was newly set).
    it('should call redis.set with NX flag and return true when redis returns OK', async () => {
      mockRedis.set.mockResolvedValue('OK')
      const result = await service.setnx('cooldown:key', 60)
      expect(mockRedis.set).toHaveBeenCalledWith(prefixed('cooldown:key'), '1', 'EX', 60, 'NX')
      expect(result).toBe(true)
    })

    // Verifies that setnx returns false when redis returns null (key already existed — cooldown active).
    it('should return false when redis returns null (key already exists)', async () => {
      mockRedis.set.mockResolvedValue(null)
      const result = await service.setnx('cooldown:key', 60)
      expect(mockRedis.set).toHaveBeenCalledWith(prefixed('cooldown:key'), '1', 'EX', 60, 'NX')
      expect(result).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // del
  // ---------------------------------------------------------------------------

  describe('del', () => {
    // Verifies that del passes the namespace-prefixed key to redis.del.
    it('should call redis.del with prefixed key', async () => {
      mockRedis.del.mockResolvedValue(1)
      await service.del('mykey')
      expect(mockRedis.del).toHaveBeenCalledWith(prefixed('mykey'))
    })

    // Scenario: what `del` REPORTS, not just what it calls. Expected: `true` only when a key
    // was actually removed. Why: callers that need exactly-once semantics — consuming an MFA
    // temp token, claiming a recovery code — decide on this boolean, and "I removed it" has to
    // be distinguishable from "someone else already had". A reply this method cannot read as a
    // count must read as "no", not as "yes".
    it.each([
      ['one key removed', 1, true],
      ['several keys removed', 3, true],
      ['nothing to remove', 0, false],
      ['a negative count', -1, false],
      ['a string reply', '1', false],
      ['a nil reply', null, false],
      ['an unexpected shape', {}, false]
    ])('reports %s as %s', async (_label, reply, expected) => {
      mockRedis.del.mockResolvedValue(reply)

      await expect(service.del('mykey')).resolves.toBe(expected)
    })
  })

  // ---------------------------------------------------------------------------
  // incr
  // ---------------------------------------------------------------------------

  describe('incr', () => {
    // Verifies that incr atomically increments the counter and returns the new value.
    it('should call redis.incr with prefixed key and return new value', async () => {
      mockRedis.incr.mockResolvedValue(3)
      const result = await service.incr('counter')
      expect(mockRedis.incr).toHaveBeenCalledWith(prefixed('counter'))
      expect(result).toBe(3)
    })
  })

  // ---------------------------------------------------------------------------
  // expire
  // ---------------------------------------------------------------------------

  describe('expire', () => {
    // Verifies that expire sets the TTL on the prefixed key.
    it('should call redis.expire with prefixed key and TTL', async () => {
      mockRedis.expire.mockResolvedValue(1)
      await service.expire('mykey', 120)
      expect(mockRedis.expire).toHaveBeenCalledWith(prefixed('mykey'), 120)
    })
  })

  // ---------------------------------------------------------------------------
  // ttl
  // ---------------------------------------------------------------------------

  describe('ttl', () => {
    // Verifies that ttl returns the remaining seconds for an existing key.
    it('should call redis.ttl with prefixed key and return remaining seconds', async () => {
      mockRedis.ttl.mockResolvedValue(45)
      const result = await service.ttl('mykey')
      expect(mockRedis.ttl).toHaveBeenCalledWith(prefixed('mykey'))
      expect(result).toBe(45)
    })

    // Verifies that ttl returns -2 when the key does not exist in Redis.
    it('should return -2 when key does not exist', async () => {
      mockRedis.ttl.mockResolvedValue(-2)
      expect(await service.ttl('missing')).toBe(-2)
    })
  })

  // ---------------------------------------------------------------------------
  // sadd
  // ---------------------------------------------------------------------------

  describe('sadd', () => {
    // Verifies that sadd adds a member to the prefixed Redis Set and returns the add count.
    it('should call redis.sadd with prefixed set key', async () => {
      mockRedis.sadd.mockResolvedValue(1)
      const result = await service.sadd('sessions:user1', 'session-id')
      expect(mockRedis.sadd).toHaveBeenCalledWith(prefixed('sessions:user1'), 'session-id')
      expect(result).toBe(1)
    })
  })

  // ---------------------------------------------------------------------------
  // srem
  // ---------------------------------------------------------------------------

  describe('srem', () => {
    // Verifies that srem removes a member from the prefixed Redis Set and returns the remove count.
    it('should call redis.srem with prefixed set key', async () => {
      mockRedis.srem.mockResolvedValue(1)
      const result = await service.srem('sessions:user1', 'session-id')
      expect(mockRedis.srem).toHaveBeenCalledWith(prefixed('sessions:user1'), 'session-id')
      expect(result).toBe(1)
    })
  })

  // ---------------------------------------------------------------------------
  // smembers
  // ---------------------------------------------------------------------------

  describe('smembers', () => {
    // Verifies that smembers returns all members of the prefixed Redis Set.
    it('should call redis.smembers with prefixed key and return array', async () => {
      mockRedis.smembers.mockResolvedValue(['a', 'b', 'c'])
      const result = await service.smembers('sessions:user1')
      expect(mockRedis.smembers).toHaveBeenCalledWith(prefixed('sessions:user1'))
      expect(result).toEqual(['a', 'b', 'c'])
    })

    // Verifies that smembers returns an empty array when the set does not exist.
    it('should return an empty array when set does not exist', async () => {
      mockRedis.smembers.mockResolvedValue([])
      expect(await service.smembers('empty')).toEqual([])
    })
  })

  // ---------------------------------------------------------------------------
  // sismember
  // ---------------------------------------------------------------------------

  describe('sismember', () => {
    // Verifies that sismember returns true when Redis returns 1 (member exists in the set).
    it('should return true when member is in the set (redis returns 1)', async () => {
      mockRedis.sismember.mockResolvedValue(1)
      const result = await service.sismember('sessions:user1', 'session-id')
      expect(mockRedis.sismember).toHaveBeenCalledWith(prefixed('sessions:user1'), 'session-id')
      expect(result).toBe(true)
    })

    // Verifies that sismember returns false when Redis returns 0 (member not in the set).
    it('should return false when member is not in the set (redis returns 0)', async () => {
      mockRedis.sismember.mockResolvedValue(0)
      expect(await service.sismember('sessions:user1', 'unknown')).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // eval
  // ---------------------------------------------------------------------------

  describe('eval', () => {
    // Verifies that eval prefixes all key arguments and passes ARGV through unchanged.
    it('should prefix keys and pass args through to redis.eval', async () => {
      mockRedis.eval.mockResolvedValue('ok')
      await service.eval('return 1', ['key1', 'key2'], ['arg1'])
      expect(mockRedis.eval).toHaveBeenCalledWith(
        'return 1',
        2,
        prefixed('key1'),
        prefixed('key2'),
        'arg1'
      )
    })

    // Verifies that eval works correctly when called with empty keys and args arrays.
    it('should handle empty keys and args arrays', async () => {
      mockRedis.eval.mockResolvedValue(null)
      await service.eval('return redis.call("ping")', [], [])
      expect(mockRedis.eval).toHaveBeenCalledWith('return redis.call("ping")', 0)
    })
  })

  // ---------------------------------------------------------------------------
  // rotateRefreshSession
  // ---------------------------------------------------------------------------

  describe('readSessionOwner', () => {
    // Scenario: a live session record. Expected: its `userId`. Why: logout reads the owner
    // from here rather than from the access token's claims — the route accepts an absent or
    // expired token, so its `sub` is either missing or only as trustworthy as its signature,
    // and taking the owner from it would let a caller aim a revocation at someone else.
    it('should return the owner recorded on the session', async () => {
      mockRedis.get.mockResolvedValue(
        JSON.stringify({ userId: 'user-1', tenantId: 'tenant-1', role: 'member' })
      )

      await expect(service.readSessionOwner('rt:abc')).resolves.toEqual({
        userId: 'user-1',
        tenantId: 'tenant-1'
      })
    })

    // A record whose `tenantId` is present but not a string. It reads as absent rather than
    // being coerced: the value goes into a key derivation, and `String(42)` would name a real
    // key belonging to a tenant nobody asked about. The owner still resolves, because the two
    // fields fail independently — a usable owner with an unusable tenant is exactly the
    // pre-upgrade record the logout path is written to skip.
    it('reads a non-string tenant as absent, keeping the owner', async () => {
      mockRedis.get.mockResolvedValue(JSON.stringify({ userId: 'user-1', tenantId: 42 }))

      await expect(service.readSessionOwner('rt:abc')).resolves.toEqual({
        userId: 'user-1',
        tenantId: undefined
      })
      expect(mockRedis.get).toHaveBeenCalledWith(prefixed('rt:abc'))
    })

    // A BLANK tenant reads as absent for the same reason a non-string one does, and it is the
    // likelier shape: an unset environment variable arrives as `''`. Returned as a usable string
    // it passed `AuthService.logout`'s `tenantId !== undefined` check, which then derived
    // `dashboard::{userId}` — a key belonging to no tenant — missed the real index, and left the
    // member and its detail record behind while reporting a completed logout.
    it('reads a blank tenant as absent, keeping the owner', async () => {
      mockRedis.get.mockResolvedValue(JSON.stringify({ userId: 'user-1', tenantId: '' }))

      await expect(service.readSessionOwner('rt:abc')).resolves.toEqual({
        userId: 'user-1',
        tenantId: undefined
      })
    })

    // Scenario: every shape that names nobody. Expected: the empty string, never a throw.
    // Why: the caller treats it as "no live session" and completes the logout quietly — a
    // throw here would turn a missing session into a 500 on a route that must always answer
    // the same way, and an exception would also tell the caller a record existed.
    it.each([
      ['a missing key', null],
      ['unparseable JSON', '{not-json'],
      ['a non-object record', '42'],
      ['a null record', 'null'],
      ['a record with no userId', '{"role":"member"}'],
      ['a record whose userId is not a string', '{"userId":123}']
    ])('should answer the empty string for %s', async (_label, stored) => {
      mockRedis.get.mockResolvedValue(stored)

      await expect(service.readSessionOwner('rt:abc')).resolves.toEqual({
        userId: '',
        tenantId: undefined
      })
    })
  })

  describe('writeRecoveredSession', () => {
    const RECOVERED = {
      kind: 'dashboard' as const,
      tenantId: 'tenant-1',
      newHash: 'new-hash',
      newSessionJson: '{"userId":"u1","tenantId":"tenant-1"}',
      familyId: 'fam-1',
      userId: 'u1',
      refreshTtl: 604_800
    }

    // The gate the whole script exists for: the per-user session index is the witness that a
    // revoke-all has not already swept the account, and the write and the check are one step.
    it('passes the three keys the script gates and writes on', async () => {
      mockRedis.eval.mockResolvedValue(1)

      await expect(service.writeRecoveredSession(RECOVERED)).resolves.toBe(true)

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining("redis.call('EXISTS', KEYS[2])"),
        3,
        prefixed('rt:new-hash'),
        prefixed(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`),
        prefixed('fam:fam-1'),
        '{"userId":"u1","tenantId":"tenant-1"}',
        '604800',
        'fam-1',
        'rt',
        'new-hash'
      )
    })

    // `0` is the sweep: the account no longer has a session index, so a revoke-all ran between
    // the rotation script's return and this write.
    it('reports a sweep when the script refuses', async () => {
      mockRedis.eval.mockResolvedValue(0)

      await expect(service.writeRecoveredSession(RECOVERED)).resolves.toBe(false)
    })

    // `eval` answers `unknown`. A client that surfaced the Lua integer as a string would make a
    // bare `=== 1` false, reporting a successful write as a sweep and refusing a rotation whose
    // session was already stored — so the reply is narrowed rather than compared straight.
    it.each([
      ['the string "1"', '1', true],
      ['the string "0"', '0', false],
      ['a nil reply', null, false]
    ])('reads %s correctly', async (_label, reply, expected) => {
      mockRedis.eval.mockResolvedValue(reply)

      await expect(service.writeRecoveredSession(RECOVERED)).resolves.toBe(expected)
    })
  })

  describe('pruneExpiredGraceMembers', () => {
    // Scenario: the sweep that keeps the per-user index from growing without bound. Expected:
    // it inspects only grace members, and only removes the ones whose key is already gone.
    // Why: a rotation adds `rp:{old}` as a member and only a full revoke-all ever removed it,
    // while the `rp:` KEY dies with the 30-second grace window — so the index gained one
    // permanent entry per refresh, with its own TTL re-armed each time. Every reader of the
    // index is linear in its size, so this is a growth defect with an amplifier attached.
    it('removes only the grace members whose pointer has expired', async () => {
      mockRedis.eval.mockResolvedValue(2)

      await expect(
        service.pruneExpiredGraceMembers(
          `sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`,
          'rp:'
        )
      ).resolves.toBe(2)

      const [script, numKeys, key, namespace, prefix] = mockRedis.eval.mock.calls[0] as unknown as [
        string,
        number,
        string,
        string,
        string
      ]
      expect(numKeys).toBe(1)
      expect(key).toBe(prefixed(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`))
      expect(namespace).toBe('auth')
      expect(prefix).toBe('rp:')
      // Only members carrying the grace prefix are considered — a live `rt:` member must
      // survive a sweep whose whole job is tidying pointers.
      expect(script).toContain('string.sub(member, 1, string.len(grace)) == grace')
      // And among those, only the ones whose key is gone. A pointer still inside its window is
      // what lets a revoke-all also kill a token rotated away moments earlier.
      expect(script).toContain("redis.call('EXISTS', ns .. ':' .. member) == 0")
      expect(script).toContain("redis.call('SREM', KEYS[1], member)")
    })

    // The platform plane sweeps its own index under its own prefix: the two id spaces come
    // from different repositories and may collide.
    it('sweeps the platform index under the platform prefix', async () => {
      mockRedis.eval.mockResolvedValue(0)

      await service.pruneExpiredGraceMembers(`psess:${hmacSha256('platform:a1', HMAC_KEY)}`, 'prp:')

      const call = mockRedis.eval.mock.calls[0] as unknown[]
      expect(call).toContain(prefixed(`psess:${hmacSha256('platform:a1', HMAC_KEY)}`))
      expect(call).toContain('prp:')
    })

    // `eval` answers `unknown`, and a client that surfaced the Lua integer as a string would
    // make a numeric read `NaN` — which is not a count, and would misreport the sweep in any
    // log or metric built on it.
    it.each([
      ['an integer reply', 3, 3],
      ['the string "3"', '3', 3],
      ['a nil reply', null, 0],
      ['an unexpected shape', {}, 0]
    ])('reads %s as a count', async (_label, reply, expected) => {
      mockRedis.eval.mockResolvedValue(reply)

      await expect(
        service.pruneExpiredGraceMembers(
          `sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`,
          'rp:'
        )
      ).resolves.toBe(expected)
    })
  })

  describe('pruneDeadMembers', () => {
    // Scenario: a reader found members it believes are stale and asks for them to be dropped.
    // Expected: the drop is conditioned on the member's own key being gone, inside one script.
    // Why: every caller reaches its candidate list by way of the `sd:` detail record, and a
    // missing detail record does not mean a missing session. A live `rt:` with no `sd:` still
    // opens the account, so removing that member from `sess:{userId}` hides a working session
    // from `invalidateUserSessions` — it then survives "sign out everywhere" and keeps rotating.
    it('drops a candidate only when its own key is gone', async () => {
      mockRedis.eval.mockResolvedValue(1)

      await expect(
        service.pruneDeadMembers(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`, [
          'rt:aaa',
          'rt:bbb'
        ])
      ).resolves.toBe(1)

      const [script, numKeys, key, namespace, first, second] = mockRedis.eval.mock
        .calls[0] as unknown as [string, number, string, string, string, string]
      expect(numKeys).toBe(1)
      expect(key).toBe(prefixed(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`))
      expect(namespace).toBe('auth')
      expect([first, second]).toEqual(['rt:aaa', 'rt:bbb'])
      // The guard IS the fix. Without it the SREM is unconditional and a live session leaves
      // the index; the two calls share one script so a key written between them cannot lose.
      expect(script).toContain("redis.call('EXISTS', ns .. ':' .. ARGV[i]) == 0")
      expect(script).toContain("redis.call('SREM', KEYS[1], ARGV[i])")
      // From 2: ARGV[1] is the namespace, so a loop starting at 1 would test `auth:auth` —
      // absent, so every candidate would be dropped and the guard would be decorative.
      expect(script).toContain('for i = 2, #ARGV do')
    })

    // No candidates means no round trip: the script would loop zero times, and a reader that
    // found nothing stale is the common case on every session listing.
    it('makes no call when there are no candidates', async () => {
      await expect(
        service.pruneDeadMembers(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`, [])
      ).resolves.toBe(0)

      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // The platform plane prunes its own index: the two id spaces come from different
    // repositories and may legitimately collide.
    it('prunes the platform index', async () => {
      mockRedis.eval.mockResolvedValue(0)

      await service.pruneDeadMembers(`psess:${hmacSha256('platform:a1', HMAC_KEY)}`, ['prt:aaa'])

      const call = mockRedis.eval.mock.calls[0] as unknown[]
      expect(call).toContain(prefixed(`psess:${hmacSha256('platform:a1', HMAC_KEY)}`))
      expect(call).toContain('prt:aaa')
    })

    // Same reason as `pruneExpiredGraceMembers`: a client surfacing the Lua integer as a string
    // would make a numeric read `NaN`, which is not a count.
    it.each([
      ['an integer reply', 3, 3],
      ['the string "3"', '3', 3],
      ['a nil reply', null, 0],
      ['an unexpected shape', {}, 0]
    ])('reads %s as a count', async (_label, reply, expected) => {
      mockRedis.eval.mockResolvedValue(reply)

      await expect(
        service.pruneDeadMembers(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`, [
          'rt:aaa'
        ])
      ).resolves.toBe(expected)
    })
  })

  describe('rotateRefreshSession', () => {
    const BUNDLE = {
      kind: 'dashboard' as const,
      tenantId: 'tenant-1',
      oldHash: 'old-hash',
      newHash: 'new-hash',
      newSessionJson: '{"userId":"u1","tenantId":"tenant-1"}',
      familyId: 'fam-1',
      userId: 'u1',
      refreshTtl: 604_800,
      graceTtl: 30
    }

    // Verifies the script receives the six keys and nine arguments it documents, in order.
    it('passes the six rotation keys and nine arguments to the script', async () => {
      mockRedis.eval.mockResolvedValue('{"userId":"u1","tenantId":"tenant-1"}')

      await service.rotateRefreshSession(BUNDLE)

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining("redis.call('GET', KEYS[1])"),
        6,
        prefixed('rt:old-hash'),
        prefixed('rt:new-hash'),
        prefixed('rp:old-hash'),
        prefixed('cf:old-hash'),
        prefixed('fam:fam-1'),
        // The owner's session index, which the script maintains itself so a concurrent
        // "log out everywhere" cannot sweep past the session this rotation is minting.
        prefixed(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`),
        '{"userId":"u1","tenantId":"tenant-1"}',
        '604800',
        '30',
        'fam-1',
        'old-hash',
        'new-hash',
        // The namespaced live-session prefix, so the grace branch can probe whether the
        // session a rotation produced is still alive before honouring the pointer.
        prefixed('rt'),
        // …and the two member prefixes the index entries are built from.
        'rt',
        'rp'
      )
    })

    // Verifies the platform plane rotates over its own keyspace. The two planes are keyed by
    // ids from different consumer repositories that may legitimately collide, so a platform
    // rotation touching `rt:`/`fam:` would cross the planes.
    it('rotates the platform plane over the platform keyspace', async () => {
      mockRedis.eval.mockResolvedValue(null)

      await service.rotateRefreshSession({ ...BUNDLE, kind: 'platform' })

      const call = mockRedis.eval.mock.calls[0] as string[]
      expect(call.slice(2, 7)).toEqual([
        prefixed('prt:old-hash'),
        prefixed('prt:new-hash'),
        prefixed('prp:old-hash'),
        prefixed('pcf:old-hash'),
        prefixed('pfam:fam-1')
      ])
    })

    // Verifies each tagged reply is decoded into its own outcome. The tags are what separate a
    // recoverable replay from a theft signal, so a mis-parse would either reject a legitimate
    // retry or silently skip the family revocation.
    it('decodes every tagged reply into its outcome', async () => {
      mockRedis.eval.mockResolvedValue('{"userId":"u1","tenantId":"tenant-1"}')
      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toEqual({
        kind: 'rotated',
        sessionJson: '{"userId":"u1","tenantId":"tenant-1"}'
      })

      mockRedis.exists.mockResolvedValue(1)
      mockRedis.eval.mockResolvedValue('GRACE:{"userId":"u1","familyId":"fam-1"}')
      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toEqual({
        kind: 'grace',
        sessionJson: '{"userId":"u1","familyId":"fam-1"}'
      })
      expect(mockRedis.exists).toHaveBeenCalledWith(prefixed('fam:fam-1'))

      mockRedis.eval.mockResolvedValue('REUSED:fam-1')
      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toEqual({
        kind: 'reused',
        familyId: 'fam-1'
      })
    })

    // SECURITY REGRESSION GUARD. A grace pointer can outlive its own lineage: reuse detection
    // revokes the family's live sessions, but a pointer planted by an EARLIER rotation of that
    // same lineage can still be inside its window. Recovering from it would mint a session
    // carrying the revoked family id and hand back the lineage the revocation just killed.
    it('refuses a grace recovery whose family has been revoked', async () => {
      mockRedis.eval.mockResolvedValue('GRACE:{"userId":"u1","familyId":"fam-1"}')
      mockRedis.exists.mockResolvedValue(0)

      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toEqual({ kind: 'invalid' })
    })

    // Scenario: a static guard on the rotation script itself. Expected: the grace pointer is
    // written with the successor hash prefixed, and the grace branch probes that successor
    // before honouring the pointer. Why: a grace pointer exists to cover the one retry where
    // the old token was consumed but the client never received the new one. Without the probe,
    // a session revoked from the session list — or swept by "log out everywhere" — could be
    // rebuilt from its own predecessor's pointer inside the grace window, handing back a fresh
    // full-lifetime session built from the record the user had just revoked. The pointer is
    // keyed by the OLD hash, so a revoke acting on the new hash cannot find it; gating on the
    // successor is what closes that, and it closes the bulk path and the single-session path
    // with one rule.
    it('gates grace recovery on the successor session still being live', async () => {
      // The script text as the service actually sends it — read from the eval call rather
      // than restated here, so the guard cannot drift from what runs.
      mockRedis.eval.mockResolvedValue(null)
      await service.rotateRefreshSession(BUNDLE)
      const script = mockRedis.eval.mock.calls[0]?.[0] as string

      // The pointer carries `{successorHash}:{json}` — ARGV[6] is sha256(new).
      expect(script).toContain(
        "redis.call('SET', KEYS[3], ARGV[6] .. ':' .. ARGV[1], 'EX', ARGV[3])"
      )
      // …and the grace branch only returns when that successor key still exists.
      expect(script).toContain("redis.call('EXISTS', ARGV[7] .. ':' .. successor)")
      // The record is recovered by splitting on the FIRST colon — a fixed width would
      // mis-split any hash that is not exactly sha256-hex.
      expect(script).toContain("string.find(grace, ':', 1, true)")
      expect(script).toContain('string.sub(grace, sep + 1)')
      // The pointer is consumed regardless of the probe's answer, so a dead successor cannot
      // leave a pointer behind for a later attempt.
      expect(script.indexOf("redis.call('DEL', KEYS[3])")).toBeLessThan(
        script.indexOf("redis.call('EXISTS', ARGV[7]")
      )
    })

    // Verifies a record naming no lineage still recovers: there is nothing to check, so no
    // `EXISTS` round trip is spent on it.
    it('recovers a grace record that carries no family', async () => {
      mockRedis.eval.mockResolvedValue('GRACE:{"userId":"u1"}')

      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toEqual({
        kind: 'grace',
        sessionJson: '{"userId":"u1"}'
      })
      expect(mockRedis.exists).not.toHaveBeenCalled()
    })

    // Verifies an empty family id is treated like an absent one — `fam:` with no id is a key
    // every familyless session would share, so checking it would be meaningless.
    it('recovers a grace record whose family id is empty', async () => {
      mockRedis.eval.mockResolvedValue('GRACE:{"userId":"u1","familyId":""}')

      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toMatchObject({ kind: 'grace' })
      expect(mockRedis.exists).not.toHaveBeenCalled()
    })

    // Verifies a malformed grace record is passed through rather than swallowed here: the
    // session parser downstream rejects it as REFRESH_TOKEN_INVALID with its own warning, and
    // reporting it as a family revocation would be a misleading theft signal.
    it('passes a malformed grace record through to the session parser', async () => {
      mockRedis.eval.mockResolvedValue('GRACE:not-json{{{')

      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toEqual({
        kind: 'grace',
        sessionJson: 'not-json{{{'
      })
      expect(mockRedis.exists).not.toHaveBeenCalled()
    })

    // Verifies a non-string reply (Redis renders the script's `false` as nil) reads as invalid
    // rather than as a session payload.
    it('treats a nil reply as an invalid refresh', async () => {
      mockRedis.eval.mockResolvedValue(null)

      await expect(service.rotateRefreshSession(BUNDLE)).resolves.toEqual({ kind: 'invalid' })
    })
  })

  // ---------------------------------------------------------------------------
  // revokeFamily
  // ---------------------------------------------------------------------------

  describe('revokeFamily', () => {
    // Verifies the revocation targets the family index, resolves the owner from a member
    // record, and hands the script the prefixes it needs to rebuild each member's keys.
    it('runs the revocation over the dashboard family keyspace', async () => {
      mockRedis.smembers.mockResolvedValue(['h1', 'h2'])
      mockRedis.get.mockResolvedValue('{"userId":"u1","tenantId":"tenant-1"}')
      mockRedis.eval.mockResolvedValue(2)

      await expect(service.revokeFamily('fam-1')).resolves.toEqual({ removed: 2, ownerId: 'u1' })

      // The membership is read from the family index itself — a wrong key here would revoke
      // nothing while still reporting success.
      expect(mockRedis.smembers).toHaveBeenCalledWith(prefixed('fam:fam-1'))
      expect(mockRedis.get).toHaveBeenCalledWith(prefixed('rt:h1'))
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining("redis.call('SMEMBERS', KEYS[1])"),
        1,
        prefixed('fam:fam-1'),
        NAMESPACE,
        'rt',
        'sd',
        prefixed(`sess:${hmacSha256('dashboard:tenant-1:u1', HMAC_KEY)}`)
      )
    })

    // Verifies the platform plane revokes its own family index with its own prefixes.
    it('runs the revocation over the platform family keyspace', async () => {
      mockRedis.smembers.mockResolvedValue(['h1'])
      mockRedis.get.mockResolvedValue('{"userId":"admin-1"}')
      mockRedis.eval.mockResolvedValue(1)

      await expect(service.revokeFamily('fam-1', 'platform')).resolves.toEqual({
        removed: 1,
        ownerId: 'admin-1'
      })

      expect(mockRedis.get).toHaveBeenCalledWith(prefixed('prt:h1'))
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        1,
        prefixed('pfam:fam-1'),
        NAMESPACE,
        'prt',
        'psd',
        prefixed(`psess:${hmacSha256('platform:admin-1', HMAC_KEY)}`)
      )
    })

    // Verifies the owner lookup skips members whose record is gone or unreadable and keeps
    // looking. A family outlives individual sessions, so the first member is not always the
    // one that still names its owner.
    it('skips expired and malformed member records when resolving the owner', async () => {
      mockRedis.smembers.mockResolvedValue(['gone', 'broken', 'noUser', 'blank', 'good'])
      mockRedis.get.mockImplementation((key: string) => {
        if (key.endsWith('gone')) return Promise.resolve(null)
        if (key.endsWith('broken')) return Promise.resolve('not-json{{{')
        if (key.endsWith('noUser')) return Promise.resolve('{"role":"member"}')
        // An empty owner would build `sess:` with no id — a key every ownerless family would
        // share, so it must be skipped like an absent one rather than pruned against.
        if (key.endsWith('blank')) return Promise.resolve('{"userId":""}')
        return Promise.resolve('{"userId":"u9","tenantId":"tenant-1"}')
      })
      mockRedis.eval.mockResolvedValue(1)

      await service.revokeFamily('fam-1')

      const call = mockRedis.eval.mock.calls[0] as string[]
      expect(call[call.length - 1]).toBe(
        prefixed(`sess:${hmacSha256('dashboard:tenant-1:u9', HMAC_KEY)}`)
      )
    })

    // Verifies that a family whose members have all expired still drops its own index, with an
    // empty owner telling the script there is no index left to prune.
    it('passes an empty owner index when no member record is readable', async () => {
      mockRedis.smembers.mockResolvedValue(['h1'])
      mockRedis.get.mockResolvedValue(null)
      mockRedis.eval.mockResolvedValue(0)

      await service.revokeFamily('fam-1')

      const call = mockRedis.eval.mock.calls[0] as string[]
      expect(call[call.length - 1]).toBe('')
    })

    // Verifies that a DASHBOARD family whose readable record names no tenant prunes no index.
    // Deriving one would build `dashboard:undefined:{ownerId}` — a key belonging to no tenant,
    // which nothing writes — so the prune would succeed against nothing while the real index kept
    // every member, and the revocation would report a cleanup that never reached it. This is the
    // shape a pre-upgrade record has, which is exactly the state a live deployment is in while
    // migrating. Logout already answers the same way.
    it('prunes no index when a dashboard family record names no tenant', async () => {
      mockRedis.smembers.mockResolvedValue(['h1'])
      // `Once`, not a standing value: the mock is shared across this describe, and a standing
      // arm here changed the owner a later test read.
      mockRedis.get.mockResolvedValueOnce('{"userId":"u9"}')
      mockRedis.eval.mockResolvedValueOnce(1)

      await service.revokeFamily('fam-1')

      const call = mockRedis.eval.mock.calls[0] as string[]
      expect(call[call.length - 1]).toBe('')
    })

    // The PLATFORM twin of the same record does prune, because a platform subject carries no
    // tenant segment: absence there is the correct shape, not a missing field. Without this the
    // plane check reads as dead weight and a mutation dropping it would survive.
    it('still prunes the platform index when the record names no tenant', async () => {
      mockRedis.smembers.mockResolvedValue(['h1'])
      mockRedis.get.mockResolvedValueOnce('{"userId":"admin-9"}')
      mockRedis.eval.mockResolvedValueOnce(1)

      await service.revokeFamily('fam-1', 'platform')

      const call = mockRedis.eval.mock.calls[0] as string[]
      expect(call[call.length - 1]).toBe(
        prefixed(`psess:${hmacSha256('platform:admin-9', HMAC_KEY)}`)
      )
    })

    // Blank and absent are one shape. A record carrying `tenantId: ''` names no tenant either —
    // `dashboard::{ownerId}` is a keyspace belonging to nobody, exactly as `dashboard:undefined:`
    // is — and an unset environment variable arrives as `''` by the time it reaches a key builder.
    // Testing only for `undefined` let the blank form through.
    it('prunes no index when a dashboard family record carries a blank tenant', async () => {
      mockRedis.smembers.mockResolvedValueOnce(['h1'])
      mockRedis.get.mockResolvedValueOnce('{"userId":"u9","tenantId":""}')
      mockRedis.eval.mockResolvedValueOnce(1)

      await service.revokeFamily('fam-1')

      const call = mockRedis.eval.mock.calls[0] as string[]
      expect(call[call.length - 1]).toBe('')
    })

    // The owner clause carries its own weight on the PLATFORM plane, where the tenant clause is
    // satisfied by the plane alone. Without this case, dropping `ownerId !== ''` still reads as
    // correct on every dashboard test — and a platform family whose members have all expired
    // would derive `psess:{hmac('platform:')}`, an index for the empty admin.
    it('prunes no platform index when no member record is readable', async () => {
      mockRedis.smembers.mockResolvedValueOnce(['h1'])
      mockRedis.get.mockResolvedValueOnce(null)
      mockRedis.eval.mockResolvedValueOnce(0)

      await service.revokeFamily('fam-1', 'platform')

      const call = mockRedis.eval.mock.calls[0] as string[]
      expect(call[call.length - 1]).toBe('')
    })

    // Verifies an empty family id short-circuits: `fam:` with no id is a key every familyless
    // session would share, so revoking it would be an unbounded blast radius.
    it('is a no-op for an empty family id', async () => {
      await expect(service.revokeFamily('')).resolves.toEqual({ removed: 0, ownerId: '' })

      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // Verifies a non-numeric reply reads as zero removals rather than leaking through.
    it('reports zero removals when the script returns a non-numeric reply', async () => {
      mockRedis.eval.mockResolvedValue(null)

      await expect(service.revokeFamily('fam-1')).resolves.toEqual({ removed: 0, ownerId: '' })
    })
  })

  // ---------------------------------------------------------------------------
  // getdel
  // ---------------------------------------------------------------------------

  describe('getdel', () => {
    // Verifies that getdel returns the stored value and triggers deletion via the Lua script.
    it('should return the value and delete the key atomically', async () => {
      mockRedis.eval.mockResolvedValue('stored-value')
      const result = await service.getdel('token:abc')
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining('GET'),
        1,
        prefixed('token:abc')
      )
      expect(result).toBe('stored-value')
    })

    // Verifies that getdel returns null when the key does not exist.
    it('should return null when the key does not exist', async () => {
      mockRedis.eval.mockResolvedValue(null)
      const result = await service.getdel('token:missing')
      expect(result).toBeNull()
    })

    // Verifies that getdel returns null when the Lua script returns a non-string value (defensive branch).
    it('should return null when eval returns a non-string value', async () => {
      mockRedis.eval.mockResolvedValue(0)
      const result = await service.getdel('token:weird')
      expect(result).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // setIfAbsent
  // ---------------------------------------------------------------------------

  describe('setIfAbsent', () => {
    // Verifies that setIfAbsent returns true when the key is newly set (redis returns 'OK').
    it('should call redis.set with EX and NX flags and return true when OK', async () => {
      mockRedis.set.mockResolvedValue('OK')
      const result = await service.setIfAbsent('mfa_setup:user1', 'setup-data', 600)
      expect(mockRedis.set).toHaveBeenCalledWith(
        prefixed('mfa_setup:user1'),
        'setup-data',
        'EX',
        600,
        'NX'
      )
      expect(result).toBe(true)
    })

    // Verifies that setIfAbsent returns false when the key already existed (redis returns null).
    it('should return false when the key already existed (redis returns null)', async () => {
      mockRedis.set.mockResolvedValue(null)
      const result = await service.setIfAbsent('mfa_setup:user1', 'setup-data', 600)
      expect(result).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // invalidateUserSessions
  // ---------------------------------------------------------------------------

  describe('invalidateUserSessions', () => {
    // Verifies that invalidateUserSessions calls eval with the sess:{userId} key and namespace as ARGV.
    it('should sweep sess:{userId} with the dashboard member prefixes', async () => {
      mockRedis.eval.mockResolvedValue(null)
      await service.invalidateUserSessions('user-1', 'tenant-1', 'dashboard')
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining('SMEMBERS'),
        1,
        prefixed(`sess:${hmacSha256('dashboard:tenant-1:user-1', HMAC_KEY)}`),
        NAMESPACE,
        'rt:',
        'rp:',
        'sd:'
      )
    })

    // Scenario: a platform revoke on an id that a dashboard user also owns. Expected: exactly
    // one sweep, over `psess:` only, carrying only the prt:/prp: prefixes. Why: the two id
    // spaces come from different repositories and may collide, so an unfiltered sweep — or a
    // second pass over the dashboard index — would log the unrelated user out. `rust-auth`
    // sweeps the one index too; a second pass here would also break that parity.
    it('should sweep only the platform index, with platform-only prefixes', async () => {
      mockRedis.eval.mockResolvedValue(null)

      await service.invalidateUserSessions('admin-1', undefined, 'platform')

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining('SMEMBERS'),
        1,
        prefixed(`psess:${hmacSha256('platform:admin-1', HMAC_KEY)}`),
        NAMESPACE,
        'prt:',
        'prp:',
        'psd:'
      )
    })

    // Scenario: the dashboard sweep must not touch platform members. Expected: no eval
    // carries the prt:/prp: prefixes. Why: this is the other half of the collision fix —
    // revoking a dashboard user must leave a same-id admin's sessions alone.
    it('should never pass platform prefixes on a dashboard revoke', async () => {
      mockRedis.eval.mockResolvedValue(null)

      await service.invalidateUserSessions('shared-id', 'tenant-1', 'dashboard')

      const prefixArgs = mockRedis.eval.mock.calls.flatMap((call) => call.slice(3) as string[])
      expect(prefixArgs).not.toContain('prt:')
      expect(prefixArgs).not.toContain('prp:')
    })
  })

  // ---------------------------------------------------------------------------
  // incrWithFixedTtl
  // ---------------------------------------------------------------------------

  describe('incrWithFixedTtl', () => {
    // Verifies that incrWithFixedTtl increments the counter and returns the new value.
    it('should increment the counter and return the new value', async () => {
      mockRedis.eval.mockResolvedValue(1)
      const result = await service.incrWithFixedTtl('counter:key', 900)
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining('INCR'),
        1,
        prefixed('counter:key'),
        '900'
      )
      expect(result).toBe(1)
    })

    // Verifies that incrWithFixedTtl returns 0 when the Lua script returns a non-number (defensive branch).
    it('should return 0 when eval returns a non-number value', async () => {
      mockRedis.eval.mockResolvedValue(null)
      const result = await service.incrWithFixedTtl('counter:key', 900)
      expect(result).toBe(0)
    })

    // Verifies that the TTL is passed as a string ARGV argument to the Lua script.
    it('should pass ttl as string ARGV to the Lua script', async () => {
      mockRedis.eval.mockResolvedValue(3)
      await service.incrWithFixedTtl('lf:abc', 300)
      const call = mockRedis.eval.mock.calls[0] as unknown[]
      // Last argument is the TTL string passed as ARGV[1]
      expect(call[call.length - 1]).toBe('300')
    })
  })

  describe('token epoch', () => {
    // Verifies the epoch is read from `ep:{userId}` and parsed to a number.
    it('should return the stored epoch for the dashboard plane', async () => {
      mockRedis.get.mockResolvedValue('3')

      expect(await service.getUserTokenEpoch('user-1', 'tenant-1', 'dashboard')).toBe(3)
      expect(mockRedis.get).toHaveBeenCalledWith(
        prefixed(`ep:${hmacSha256('dashboard:tenant-1:user-1', HMAC_KEY)}`)
      )
    })

    // Verifies the platform plane carries its own counter. The two planes are keyed by ids
    // from different repositories that may collide, so one shared counter would let a reset
    // on one plane invalidate the other plane's tokens.
    it('should read the platform epoch from its own keyspace', async () => {
      mockRedis.get.mockResolvedValue('1')

      expect(await service.getUserTokenEpoch('admin-1', undefined, 'platform')).toBe(1)
      expect(mockRedis.get).toHaveBeenCalledWith(
        prefixed(`pep:${hmacSha256('platform:admin-1', HMAC_KEY)}`)
      )
    })

    // Verifies an unbumped user reads as 0, which keeps the mechanism inert: every token is
    // stamped 0 too, so nothing is rejected until the first bump.
    it('should return 0 when no epoch is stored', async () => {
      mockRedis.get.mockResolvedValue(null)

      expect(await service.getUserTokenEpoch('user-1', 'tenant-1', 'dashboard')).toBe(0)
    })

    // Verifies a corrupt or negative stored value reads as 0 rather than NaN. Comparing
    // against NaN is always false, which would silently disable bulk revocation for that user.
    it('should return 0 when the stored epoch is unusable', async () => {
      mockRedis.get.mockResolvedValue('not-a-number')
      expect(await service.getUserTokenEpoch('user-1', 'tenant-1', 'dashboard')).toBe(0)

      mockRedis.get.mockResolvedValue('1.5')
      expect(await service.getUserTokenEpoch('user-1', 'tenant-1', 'dashboard')).toBe(0)

      mockRedis.get.mockResolvedValue('-2')
      expect(await service.getUserTokenEpoch('user-1', 'tenant-1', 'dashboard')).toBe(0)
    })

    // Verifies the bump increments atomically and pins the key lifetime to 30 days — far
    // longer than any access token lives, so the bump stays in force for every pre-bump
    // token's remaining lifetime. rust-auth applies the same value on a shared Redis.
    it('should increment the epoch and pin a 30-day lifetime', async () => {
      mockRedis.eval.mockResolvedValue(1)

      expect(await service.bumpUserTokenEpoch('user-1', 'tenant-1', 'dashboard')).toBe(1)

      const call = mockRedis.eval.mock.calls[0] as unknown[]
      expect(call[0]).toEqual(expect.stringContaining("redis.call('INCR'"))
      expect(call[2]).toBe(prefixed(`ep:${hmacSha256('dashboard:tenant-1:user-1', HMAC_KEY)}`))
      expect(call[call.length - 1]).toBe(String(30 * 24 * 60 * 60))
    })

    // The expiry is applied on EVERY increment, not only the first. Under a first-increment-only
    // TTL — which is what `incrWithFixedTtl` does, and what this used to call — the retention
    // window would be anchored to the first bump a user ever took: a password reset on day 0
    // and a "sign out everywhere" on day 29 would share one expiry, the key would vanish on day
    // 30 while the tokens the second bump revoked were still inside their lifetime, and
    // `getUserTokenEpoch` would answer 0 — under which `stamped < epoch` is false for every
    // token and the revocation quietly stops applying. rust-auth issues the unconditional
    // `EXPIRE`; a shared Redis cannot have the two libs disagree about when the key dies.
    it('should re-apply the lifetime on every bump, not only the first', async () => {
      mockRedis.eval.mockResolvedValue(7)

      await service.bumpUserTokenEpoch('user-1', 'tenant-1', 'dashboard')

      const script = (mockRedis.eval.mock.calls[0] as unknown[])[0] as string
      expect(script).toContain("redis.call('EXPIRE'")
      // No `if v == 1` guard around the EXPIRE — that guard is what makes the fixed-window
      // limiter refuse to extend, and it is exactly wrong here.
      expect(script).not.toContain('v == 1')
    })

    // A non-numeric reply falls back to 0. Redis returns an integer for INCR, so this is the
    // shape guard for a mock, a proxy, or a future script edit — and 0 is the safe answer:
    // it reads as "no epoch", which refuses nothing rather than revoking everything.
    it('should answer 0 when the script returns a non-numeric reply', async () => {
      mockRedis.eval.mockResolvedValue('not-a-number')

      expect(await service.bumpUserTokenEpoch('user-1', 'tenant-1', 'dashboard')).toBe(0)
    })

    // Verifies the platform bump targets the platform counter.
    it('should increment the platform epoch in its own keyspace', async () => {
      mockRedis.eval.mockResolvedValue(2)

      expect(await service.bumpUserTokenEpoch('admin-1', undefined, 'platform')).toBe(2)
      expect((mockRedis.eval.mock.calls[0] as unknown[])[2]).toBe(
        prefixed(`pep:${hmacSha256('platform:admin-1', HMAC_KEY)}`)
      )
    })
  })

  // ---------------------------------------------------------------------------
  // WebSocket upgrade tickets
  // ---------------------------------------------------------------------------

  describe('WebSocket upgrade tickets', () => {
    // Scenario: minting a ticket. Expected: the raw ticket is 64 lowercase hex, only its
    // sha256 becomes a key, and the value is the snapshot under the agreed TTL. Why: the raw
    // ticket appears in a URL by design, so a store that keyed on it would turn one access log
    // into a set of live credentials.
    it('should key on the hash and never on the raw ticket', async () => {
      mockRedis.set.mockResolvedValue('OK')
      const snapshot = {
        sub: 'user-1',
        tenantId: 'tenant-1',
        role: 'MEMBER',
        status: 'ACTIVE',
        mfaEnabled: false,
        mfaVerified: false
      }

      const ticket = await service.mintWsTicket(snapshot, 30)

      expect(ticket).toMatch(/^[0-9a-f]{64}$/)
      const hashed = createHash('sha256').update(ticket).digest('hex')
      expect(mockRedis.set).toHaveBeenCalledWith(
        prefixed(`wst:${hashed}`),
        JSON.stringify(snapshot),
        'EX',
        30
      )
      // The raw ticket must appear in no argument of the write.
      expect(JSON.stringify(mockRedis.set.mock.calls[0])).not.toContain(ticket)
    })

    // Scenario: two mints. Expected: different tickets. Why: a ticket derived from anything
    // stable — the user, the clock — would be predictable by whoever knows that input.
    it('should mint a distinct ticket every time', async () => {
      mockRedis.set.mockResolvedValue('OK')
      const snapshot = {
        sub: 'user-1',
        role: 'MEMBER',
        status: 'ACTIVE',
        mfaEnabled: false,
        mfaVerified: false
      }

      const seen = new Set<string>()
      for (let i = 0; i < 16; i++) {
        seen.add(await service.mintWsTicket(snapshot, 30))
      }
      expect(seen.size).toBe(16)
    })

    // Scenario: redeeming a live ticket. Expected: the snapshot, read through GETDEL so the
    // ticket is consumed in the same round trip. Why: a read-then-delete would let two
    // concurrent upgrades both win the race with one ticket.
    it('should redeem through getdel so the ticket is single-use', async () => {
      const snapshot = {
        sub: 'user-2',
        tenantId: 't',
        role: 'ADMIN',
        status: 'ACTIVE',
        mfaEnabled: true,
        mfaVerified: true
      }
      mockRedis.eval.mockResolvedValue(JSON.stringify(snapshot))

      await expect(service.redeemWsTicket('raw')).resolves.toStrictEqual(snapshot)
      const evalArgs = mockRedis.eval.mock.calls[0] as unknown[]
      expect(String(evalArgs[0])).toContain('DEL')
      expect(evalArgs[2]).toBe(prefixed(`wst:${createHash('sha256').update('raw').digest('hex')}`))
    })

    // Scenario: a ticket that is absent, expired, or already consumed. Expected: null.
    it('should return null when there is nothing to redeem', async () => {
      mockRedis.eval.mockResolvedValue(null)
      await expect(service.redeemWsTicket('gone')).resolves.toBeNull()
    })

    // Scenario: a stored value that is not valid JSON, and one that parses but is missing a
    // required field. Expected: null for both. Why: the record is written by whichever backend
    // minted it, so it is parsed defensively — a snapshot without `mfaVerified` would otherwise
    // authorize a socket as second-factor-satisfied through an absent field read as false.
    it.each([
      ['not json at all', 'not-json'],
      ['a JSON scalar', '"just-a-string"'],
      ['null', 'null'],
      ['a record missing mfaVerified', '{"sub":"u","role":"r","status":"s","mfaEnabled":true}'],
      [
        'a record whose mfaEnabled is a string',
        '{"sub":"u","role":"r","status":"s","mfaEnabled":"true","mfaVerified":true}'
      ],
      [
        'a record whose tenantId is a number',
        '{"sub":"u","role":"r","status":"s","mfaEnabled":true,"mfaVerified":true,"tenantId":1}'
      ],
      // The three identity fields. A snapshot authorizes a socket for its whole lifetime with
      // no per-message gate behind it, so a missing `sub` is a socket bound to nobody, and a
      // missing `role` or `status` is one whose authorization fields read as `undefined` at
      // every check the consumer makes.
      ['a record missing sub', '{"role":"r","status":"s","mfaEnabled":true,"mfaVerified":true}'],
      ['a record missing role', '{"sub":"u","status":"s","mfaEnabled":true,"mfaVerified":true}'],
      ['a record missing status', '{"sub":"u","role":"r","mfaEnabled":true,"mfaVerified":true}'],
      [
        'a record whose sub is a number',
        '{"sub":1,"role":"r","status":"s","mfaEnabled":true,"mfaVerified":true}'
      ]
    ])('should refuse %s', async (_label, stored) => {
      mockRedis.eval.mockResolvedValue(stored)
      await expect(service.redeemWsTicket('raw')).resolves.toBeNull()
    })

    // Scenario: a tenant-less (platform-shaped) snapshot. Expected: accepted. Why: the contract
    // omits `tenantId` entirely rather than writing null, so requiring it would reject a record
    // the sibling backend writes.
    it('should accept a snapshot with no tenant scope', async () => {
      const snapshot = {
        sub: 'admin-1',
        role: 'SUPER_ADMIN',
        status: 'ACTIVE',
        mfaEnabled: true,
        mfaVerified: true
      }
      mockRedis.eval.mockResolvedValue(JSON.stringify(snapshot))
      await expect(service.redeemWsTicket('raw')).resolves.toStrictEqual(snapshot)
    })
  })
  it('keeps the Redis client out of every serialization path', () => {
    // An ioredis instance carries `options.password` as a plain field, and this
    // service is injected into roughly a dozen guards and services, so exposing
    // the client puts the Redis credentials one render away from any of them.
    const password = 'r3d1s-canary'
    const client = { options: { password } } as unknown as Redis
    const service = new AuthRedisService(client, {
      redisNamespace: 'auth',
      hmacKey: 'test-hmac-key'
    } as ResolvedOptions)

    expect(JSON.stringify(service)).not.toContain(password)
    expect(JSON.stringify({ ...service })).not.toContain(password)
    expect(inspect(service, { depth: null, showHidden: true })).not.toContain(password)
  })
})
