import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const mockRedis = {
  get: jest.fn(),
  del: jest.fn(),
  ttl: jest.fn(),
  incrWithFixedTtl: jest.fn()
}

const mockOptions = {
  bruteForce: {
    maxAttempts: 5,
    windowSeconds: 900
  }
}

/** Valid hashed identifier (no colons, no newlines). */
const IDENTIFIER = 'a3f2b8c1d4e5f6071234567890abcdef'
const KEY = `lf:${IDENTIFIER}`

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('BruteForceService', () => {
  let service: BruteForceService

  beforeEach(async () => {
    jest.clearAllMocks()
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

    const module = await Test.createTestingModule({
      providers: [
        BruteForceService,
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    service = module.get(BruteForceService)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // ---------------------------------------------------------------------------
  // isLockedOut
  // ---------------------------------------------------------------------------

  describe('isLockedOut', () => {
    // Verifies that a null Redis value (no attempts yet) results in isLockedOut returning false.
    it('should return false when no attempts have been recorded', async () => {
      mockRedis.get.mockResolvedValue(null)

      expect(await service.isLockedOut(IDENTIFIER)).toBe(false)
      expect(mockRedis.get).toHaveBeenCalledWith(KEY)
    })

    // Verifies that an attempt count below the threshold does not trigger lockout.
    it('should return false when attempts are below the threshold', async () => {
      mockRedis.get.mockResolvedValue('4')

      expect(await service.isLockedOut(IDENTIFIER)).toBe(false)
    })

    // Verifies that reaching exactly the max-attempts threshold triggers lockout.
    it('should return true when attempts equal the threshold', async () => {
      mockRedis.get.mockResolvedValue('5')

      expect(await service.isLockedOut(IDENTIFIER)).toBe(true)
    })

    // Verifies that exceeding the threshold also triggers lockout (not just equality).
    it('should return true when attempts exceed the threshold', async () => {
      mockRedis.get.mockResolvedValue('10')

      expect(await service.isLockedOut(IDENTIFIER)).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // recordFailure
  // ---------------------------------------------------------------------------

  describe('recordFailure', () => {
    // Verifies that recordFailure uses the atomic incrWithFixedTtl with the correct key and window TTL.
    it('should call incrWithFixedTtl with the correct key and window TTL', async () => {
      mockRedis.incrWithFixedTtl.mockResolvedValue(1)

      await service.recordFailure(IDENTIFIER)

      expect(mockRedis.incrWithFixedTtl).toHaveBeenCalledWith(KEY, 900)
    })

    // Verifies that recordFailure does not call get, del, or ttl — only the atomic increment.
    it('should not call get, del, or ttl directly', async () => {
      mockRedis.incrWithFixedTtl.mockResolvedValue(2)

      await service.recordFailure(IDENTIFIER)

      expect(mockRedis.get).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
      expect(mockRedis.ttl).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // resetFailures
  // ---------------------------------------------------------------------------

  describe('resetFailures', () => {
    // Verifies that resetFailures deletes the failure counter key from Redis.
    it('should call del with the correct key', async () => {
      mockRedis.del.mockResolvedValue(1)

      await service.resetFailures(IDENTIFIER)

      expect(mockRedis.del).toHaveBeenCalledWith(KEY)
    })
  })

  // ---------------------------------------------------------------------------
  // getRemainingLockoutSeconds
  // ---------------------------------------------------------------------------

  describe('getRemainingLockoutSeconds', () => {
    // Verifies that the remaining TTL is returned as-is when the key exists and is locked.
    it('should return the TTL when the key is locked', async () => {
      mockRedis.ttl.mockResolvedValue(543)

      expect(await service.getRemainingLockoutSeconds(IDENTIFIER)).toBe(543)
      expect(mockRedis.ttl).toHaveBeenCalledWith(KEY)
    })

    // Verifies that a TTL of -2 (key does not exist) is normalized to 0.
    it('should return 0 when the key does not exist (TTL = -2)', async () => {
      mockRedis.ttl.mockResolvedValue(-2)

      expect(await service.getRemainingLockoutSeconds(IDENTIFIER)).toBe(0)
    })

    // Verifies that a TTL of -1 (key exists but has no expiry set) is normalized to 0.
    it('should return 0 when the key has no TTL set (TTL = -1)', async () => {
      mockRedis.ttl.mockResolvedValue(-1)

      expect(await service.getRemainingLockoutSeconds(IDENTIFIER)).toBe(0)
    })
  })

  // ---------------------------------------------------------------------------
  // validateIdentifier (via isLockedOut / recordFailure / resetFailures)
  // ---------------------------------------------------------------------------

  describe('validateIdentifier', () => {
    // Verifies that an identifier containing a colon is rejected to prevent Redis key injection.
    it('should throw AuthException when identifier contains a colon', async () => {
      await expect(service.isLockedOut('user:id')).rejects.toThrow(AuthException)
    })

    // Verifies that an identifier containing a newline is rejected to prevent Redis key injection.
    it('should throw AuthException when identifier contains a newline', async () => {
      await expect(service.recordFailure('user\nid')).rejects.toThrow(AuthException)
    })

    // Verifies that an identifier containing a carriage return is rejected to prevent Redis key injection.
    it('should throw AuthException when identifier contains a carriage return', async () => {
      await expect(service.resetFailures('user\rid')).rejects.toThrow(AuthException)
    })

    // Verifies that an identifier exceeding 512 bytes is rejected to prevent memory exhaustion.
    it('should throw AuthException when identifier exceeds 512 bytes', async () => {
      const longId = 'a'.repeat(513)
      await expect(service.isLockedOut(longId)).rejects.toThrow(AuthException)
    })

    // Verifies that an identifier of exactly 512 bytes is accepted (boundary case).
    it('should accept a 512-byte identifier without throwing', async () => {
      mockRedis.get.mockResolvedValue(null)
      const exactId = 'a'.repeat(512)
      await expect(service.isLockedOut(exactId)).resolves.toBe(false)
    })
  })
})
