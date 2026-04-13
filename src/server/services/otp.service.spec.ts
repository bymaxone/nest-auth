import { Test } from '@nestjs/testing'

import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { OtpService } from './otp.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  ttl: jest.fn(),
  eval: jest.fn()
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('OtpService', () => {
  let service: OtpService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [OtpService, { provide: AuthRedisService, useValue: mockRedis }]
    }).compile()

    service = module.get(OtpService)
  })

  // ---------------------------------------------------------------------------
  // generate
  // ---------------------------------------------------------------------------

  describe('generate', () => {
    // Verifies that the default generate() call produces a 6-digit numeric string.
    it('should produce a 6-digit string by default', () => {
      const otp = service.generate()
      expect(otp).toMatch(/^\d{6}$/)
    })

    // Verifies that passing a custom length produces a numeric string of exactly that length.
    it('should produce a string of the specified length', () => {
      expect(service.generate(4)).toMatch(/^\d{4}$/)
      expect(service.generate(8)).toMatch(/^\d{8}$/)
    })

    // Verifies that small random values are left-padded with zeros to maintain the specified length.
    it('should pad with leading zeros when the number is small', () => {
      // Mock randomInt to return 42 → padded to '000042' for length 6
      jest.spyOn(require('node:crypto'), 'randomInt').mockReturnValueOnce(42)
      expect(service.generate(6)).toBe('000042')
    })
  })

  // ---------------------------------------------------------------------------
  // store
  // ---------------------------------------------------------------------------

  describe('store', () => {
    // Verifies that store writes the OTP record JSON under the correct namespaced key with the given TTL.
    it('should store the OTP record with correct key and TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.store('email_verification', 'user-hash', '123456', 600)

      expect(mockRedis.set).toHaveBeenCalledWith(
        'otp:email_verification:user-hash',
        expect.stringContaining('"code":"123456"'),
        600
      )
    })

    // Verifies that a freshly stored OTP record initializes the attempt counter to 0.
    it('should initialize attempts to 0', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.store('password_reset', 'user-hash', '654321', 300)

      const storedJson = mockRedis.set.mock.calls[0]?.[1] as string
      const record = JSON.parse(storedJson) as { code: string; attempts: number }
      expect(record.attempts).toBe(0)
    })
  })

  // ---------------------------------------------------------------------------
  // verify — success
  // ---------------------------------------------------------------------------

  describe('verify', () => {
    const OTP_KEY = 'otp:email_verification:user-hash'
    const STORED_RECORD = JSON.stringify({ code: '123456', attempts: 0 })

    // Verifies that a correct OTP resolves without error and the key is deleted after successful verification.
    it('should resolve and delete the key on correct code', async () => {
      mockRedis.get.mockResolvedValue(STORED_RECORD)
      mockRedis.del.mockResolvedValue(1)

      await expect(
        service.verify('email_verification', 'user-hash', '123456')
      ).resolves.toBeUndefined()

      expect(mockRedis.del).toHaveBeenCalledWith(OTP_KEY)
    })

    // ---------------------------------------------------------------------------
    // verify — OTP expired
    // ---------------------------------------------------------------------------

    // Verifies that attempting to verify when the key does not exist in Redis throws OTP_EXPIRED.
    it('should throw OTP_EXPIRED when key is not in Redis', async () => {
      mockRedis.get.mockResolvedValue(null)

      await expect(service.verify('email_verification', 'user-hash', '123456')).rejects.toThrow(
        AuthException
      )
    })

    // ---------------------------------------------------------------------------
    // verify — wrong code
    // ---------------------------------------------------------------------------

    // Verifies that a wrong code throws OTP_INVALID and increments the attempt counter via Lua eval.
    it('should throw OTP_INVALID and increment attempts on wrong code', async () => {
      mockRedis.get.mockResolvedValue(STORED_RECORD)
      mockRedis.eval.mockResolvedValue(undefined)

      await expect(service.verify('email_verification', 'user-hash', '999999')).rejects.toThrow(
        AuthException
      )

      // incrementAttempts called via eval Lua script — verify the updated record is passed as arg
      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const updatedJson = mockRedis.eval.mock.calls[0]?.[2]?.[0] as string
      const record = JSON.parse(updatedJson) as { attempts: number }
      expect(record.attempts).toBe(1)
    })

    // ---------------------------------------------------------------------------
    // verify — max attempts
    // ---------------------------------------------------------------------------

    // Verifies that when the attempt counter reaches 5 (MAX_ATTEMPTS), OTP_MAX_ATTEMPTS is thrown.
    it('should throw OTP_MAX_ATTEMPTS when attempts >= 5', async () => {
      const exhaustedRecord = JSON.stringify({ code: '123456', attempts: 5 })
      mockRedis.get.mockResolvedValue(exhaustedRecord)

      await expect(service.verify('email_verification', 'user-hash', '123456')).rejects.toThrow(
        AuthException
      )
    })

    // ---------------------------------------------------------------------------
    // verify — different-length code
    // ---------------------------------------------------------------------------

    // Verifies that a code with a different length than the stored code throws OTP_INVALID safely.
    it('should throw OTP_INVALID without error for different-length code', async () => {
      mockRedis.get.mockResolvedValue(STORED_RECORD)
      mockRedis.eval.mockResolvedValue(undefined)

      // '12345' is only 5 chars vs stored '123456' (6 chars)
      await expect(service.verify('email_verification', 'user-hash', '12345')).rejects.toThrow(
        AuthException
      )
    })
  })
})
