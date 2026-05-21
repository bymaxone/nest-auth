import { Test } from '@nestjs/testing'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { sleep } from '../utils/sleep'
import { OtpService } from './otp.service'

// Mock the timing-normalization sleep so anti-timing-attack delays are observable and instant.
jest.mock('../utils/sleep', () => ({ sleep: jest.fn().mockResolvedValue(undefined) }))

const mockSleep = sleep as jest.MockedFunction<typeof sleep>

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

/**
 * Extracts the stable error code from a thrown AuthException response so tests
 * can pin the exact thrown code (callers branch on `error.code`, not message).
 */
const errorCodeOf = (e: unknown): string =>
  ((e as AuthException).getResponse() as { error: { code: string } }).error.code

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

    // Verifies that a corrupted Redis payload (invalid JSON) is opaquely surfaced as
    // OTP_EXPIRED (matching the response for missing-key) so an attacker with Redis
    // write access cannot distinguish corruption from natural expiry, and the unusable
    // key is deleted to free Redis space sooner than its natural TTL.
    it('should throw OTP_EXPIRED and delete key when Redis value is corrupted JSON', async () => {
      mockRedis.get.mockResolvedValue('{not-valid-json')
      mockRedis.del.mockResolvedValue(1)

      await expect(service.verify('email_verification', 'user-hash', '123456')).rejects.toThrow(
        AuthException
      )
      expect(mockRedis.del).toHaveBeenCalledWith(OTP_KEY)
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

    // ---------------------------------------------------------------------------
    // verify — exact thrown error codes (pin the specific AuthException code)
    // ---------------------------------------------------------------------------

    // Scenario: missing key. Expected: thrown code is exactly OTP_EXPIRED. Why: pins the
    // error code so a swap to any other code (or a corrupted-path divergence) is caught.
    it('should throw exactly OTP_EXPIRED when the key is missing', async () => {
      expect.assertions(1)
      mockRedis.get.mockResolvedValue(null)
      try {
        await service.verify('email_verification', 'user-hash', '123456')
      } catch (e) {
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_EXPIRED)
      }
    })

    // Scenario: attempts already at MAX_ATTEMPTS (5). Expected: thrown code is exactly
    // OTP_MAX_ATTEMPTS. Why: pins the boundary outcome distinct from OTP_INVALID/OTP_EXPIRED.
    it('should throw exactly OTP_MAX_ATTEMPTS at the attempt boundary', async () => {
      expect.assertions(1)
      mockRedis.get.mockResolvedValue(JSON.stringify({ code: '123456', attempts: 5 }))
      mockRedis.del.mockResolvedValue(1)
      try {
        await service.verify('email_verification', 'user-hash', '123456')
      } catch (e) {
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_MAX_ATTEMPTS)
      }
    })

    // Scenario: wrong code with attempts below limit. Expected: thrown code is exactly
    // OTP_INVALID. Why: pins the wrong-code outcome distinct from OTP_MAX_ATTEMPTS/OTP_EXPIRED.
    it('should throw exactly OTP_INVALID for a wrong code below the attempt limit', async () => {
      expect.assertions(1)
      mockRedis.get.mockResolvedValue(STORED_RECORD)
      mockRedis.eval.mockResolvedValue(undefined)
      try {
        await service.verify('email_verification', 'user-hash', '999999')
      } catch (e) {
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
      }
    })

    // ---------------------------------------------------------------------------
    // verify — incrementAttempts Lua eval shape (key, script, args are significant)
    // ---------------------------------------------------------------------------

    // Scenario: wrong code triggers incrementAttempts. Expected: redis.eval is called with
    // the namespaced KEYS=[otp:purpose:identifier], the TTL-preserving Lua script, and the
    // updated record JSON. Why: kills the empty-key (line 175), empty-script (line 179) and
    // empty-KEYS-array (line 181) mutants, which all change the atomic counter update.
    it('should call redis.eval with the namespaced key, TTL-preserving Lua, and updated record', async () => {
      mockRedis.get.mockResolvedValue(STORED_RECORD)
      mockRedis.eval.mockResolvedValue(undefined)

      await expect(service.verify('email_verification', 'user-hash', '999999')).rejects.toThrow(
        AuthException
      )

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const call = mockRedis.eval.mock.calls[0] as unknown as
        | [string, string[], string[]]
        | undefined
      const script = call?.[0] ?? ''
      const keys = call?.[1] ?? []
      const args = call?.[2] ?? []
      // KEYS array must be the single namespaced OTP key (not empty — line 181/175 mutants).
      expect(keys).toEqual([OTP_KEY])
      // Lua must read the TTL and re-SET preserving it (not an empty script — line 179 mutant).
      expect(script).toContain("redis.call('TTL', KEYS[1])")
      expect(script).toContain("'SET', KEYS[1], ARGV[1], 'EX', ttl")
      // The incremented record is forwarded as ARGV[1].
      const record = JSON.parse(args[0] ?? '{}') as { code: string; attempts: number }
      expect(record).toEqual({ code: '123456', attempts: 1 })
    })

    // ---------------------------------------------------------------------------
    // verify — timing-normalization sleep duration (kills Math.max/min + arithmetic mutants)
    // ---------------------------------------------------------------------------

    describe('timing normalization sleep argument', () => {
      let nowSpy: jest.SpyInstance

      beforeEach(() => {
        // Pin Date.now: the FIRST call is `start`, every later call is 50 ms after (elapsed=50,
        // < 100 ms MIN_VERIFY_MS). With elapsed=50: original Math.max(0, 100 - 50) = 50;
        // Math.min(0, 50) = 0; (100 + 50) = 150; (100 - (now + start)) = huge-negative -> 0.
        // Asserting exactly 50 kills every Math.min/min-vs-max and +/- arithmetic mutant on
        // each sleep call site. mockReturnValueOnce pins only `start`, so extra Date.now calls
        // by the runtime stay at start+50 and do not perturb the assertion.
        nowSpy = jest.spyOn(Date, 'now')
        nowSpy.mockReturnValue(1_000_050)
        nowSpy.mockReturnValueOnce(1_000_000)
      })

      afterEach(() => {
        nowSpy.mockRestore()
      })

      // Scenario: missing key path. Expected: sleep(50). Why: pins the normalization delay so
      // the Math.max->min and -/+ arithmetic mutants on line 117 are killed.
      it('should sleep for the remaining MIN_VERIFY_MS on the OTP_EXPIRED path', async () => {
        mockRedis.get.mockResolvedValue(null)
        await expect(service.verify('email_verification', 'user-hash', '123456')).rejects.toThrow(
          AuthException
        )
        expect(mockSleep).toHaveBeenCalledWith(50)
      })

      // Scenario: corrupted JSON path. Expected: sleep(50). Why: pins line 129 normalization delay.
      it('should sleep for the remaining MIN_VERIFY_MS on the corrupted-JSON path', async () => {
        mockRedis.get.mockResolvedValue('{not-json')
        mockRedis.del.mockResolvedValue(1)
        await expect(service.verify('email_verification', 'user-hash', '123456')).rejects.toThrow(
          AuthException
        )
        expect(mockSleep).toHaveBeenCalledWith(50)
      })

      // Scenario: max-attempts path. Expected: sleep(50). Why: pins line 136 normalization delay.
      it('should sleep for the remaining MIN_VERIFY_MS on the OTP_MAX_ATTEMPTS path', async () => {
        mockRedis.get.mockResolvedValue(JSON.stringify({ code: '123456', attempts: 5 }))
        mockRedis.del.mockResolvedValue(1)
        await expect(service.verify('email_verification', 'user-hash', '123456')).rejects.toThrow(
          AuthException
        )
        expect(mockSleep).toHaveBeenCalledWith(50)
      })

      // Scenario: wrong-code path. Expected: sleep(50). Why: pins line 146 normalization delay.
      it('should sleep for the remaining MIN_VERIFY_MS on the OTP_INVALID path', async () => {
        mockRedis.get.mockResolvedValue(STORED_RECORD)
        mockRedis.eval.mockResolvedValue(undefined)
        await expect(service.verify('email_verification', 'user-hash', '999999')).rejects.toThrow(
          AuthException
        )
        expect(mockSleep).toHaveBeenCalledWith(50)
      })

      // Scenario: success path. Expected: sleep(50). Why: pins line 152 normalization delay
      // even on the happy path where the OTP is consumed.
      it('should sleep for the remaining MIN_VERIFY_MS on the success path', async () => {
        mockRedis.get.mockResolvedValue(STORED_RECORD)
        mockRedis.del.mockResolvedValue(1)
        await expect(
          service.verify('email_verification', 'user-hash', '123456')
        ).resolves.toBeUndefined()
        expect(mockSleep).toHaveBeenCalledWith(50)
      })
    })
  })
})
