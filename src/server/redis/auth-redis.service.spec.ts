/**
 * @fileoverview Tests for AuthRedisService, which wraps an ioredis client and
 * automatically namespaces all keys with the configured prefix. Covers all
 * string, set, counter, expiry, Lua eval, and atomic compound operations.
 */

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REDIS_CLIENT } from '../bymax-one-nest-auth.constants'
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
  eval: jest.fn()
}

// Note: setnx in AuthRedisService calls redis.set(..., 'NX'), not a separate redis.setnx method.

const mockOptions = { redisNamespace: NAMESPACE }

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
    it('should call eval with sess:{userId} key and namespace as ARGV[1]', async () => {
      mockRedis.eval.mockResolvedValue(null)
      await service.invalidateUserSessions('user-1')
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining('SMEMBERS'),
        1,
        prefixed('sess:user-1'),
        NAMESPACE
      )
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
})
