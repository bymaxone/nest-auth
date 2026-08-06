import { Test } from '@nestjs/testing'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { sleep } from '../utils/sleep'
import { OtpService } from './otp.service'

// Mock the timing-normalization sleep so anti-timing-attack delays are observable and instant.
jest.mock('../utils/sleep', () => ({ sleep: jest.fn().mockResolvedValue(undefined) }))

const mockSleep = sleep as jest.MockedFunction<typeof sleep>

/**
 * The service's own timing floor, mirrored here because it is module-private there.
 *
 * Exporting it only for a test would make it look like configuration; the floor is a fixed
 * property of the anti-enumeration contract, so it is restated with this note instead.
 */
const MIN_VERIFY_MS = 100

/** How far the mocked Redis step advances the test clock — any non-zero value under the floor. */
const REDIS_STEP_MS = 30

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
    // Verifies the record goes in under the correct namespaced key, with the code and a zeroed
    // counter, and its TTL.
    it('should store the code and a zeroed counter under the namespaced key', async () => {
      mockRedis.eval.mockResolvedValue(undefined)

      await service.store('email_verification', 'user-hash', '123456', 600)

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining("redis.call('HSET', KEYS[1], 'code', ARGV[1], 'attempts', 0)"),
        ['otp:email_verification:user-hash'],
        ['123456', '600']
      )
    })

    // Scenario: the write. Expected: record and expiry set by ONE script. Why: an `HSET`
    // followed by a separate `EXPIRE` leaves a window where a crash strands a record with no
    // TTL, and an OTP that never expires is one an attacker can grind against forever — the
    // keyspace's "every key carries a TTL" invariant exists for exactly that.
    it('should write the record and its expiry in a single step', async () => {
      mockRedis.eval.mockResolvedValue(undefined)

      await service.store('password_reset', 'user-hash', '654321', 300)

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      expect(mockRedis.set).not.toHaveBeenCalled()
      const script = mockRedis.eval.mock.calls[0]?.[0] as string
      expect(script).toContain("redis.call('EXPIRE', KEYS[1], ARGV[2])")
    })
  })

  // ---------------------------------------------------------------------------
  // verify — success
  // ---------------------------------------------------------------------------

  describe('verify', () => {
    const OTP_KEY = 'otp:email_verification:user-hash'
    const CODE = '123456'

    /** Arm the atomic script's reply. */
    function armScript(tag: 'EXPIRED' | 'MAX' | 'PRESENT', storedCode = ''): void {
      mockRedis.eval.mockResolvedValue([tag, storedCode])
    }

    // Scenario: the correct code. Expected: resolves. Why: the script consumes the record on a
    // plain match, so the service must not delete anything itself — a second DEL here would be
    // a wasted round trip and a lie about who owns the consume.
    it('should resolve on the correct code without a separate delete', async () => {
      armScript('PRESENT', CODE)

      await expect(service.verify('email_verification', 'user-hash', CODE)).resolves.toBeUndefined()
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Scenario: verification of any kind. Expected: exactly ONE Redis round trip, carrying the
    // namespaced key, the submitted code, and the ceiling. Why: the read, the ceiling check and
    // the bump-or-consume have to be one atomic step. They used to be a GET here, a decision in
    // JS, and a SET back — so N concurrent wrong guesses all read `attempts: 0`, all wrote
    // `attempts: 1`, and the ceiling could be exceeded arbitrarily by submitting in parallel
    // for the OTP's whole lifetime. Pinning the arity is what keeps a future refactor from
    // quietly splitting it apart again.
    it('should verify in a single atomic script call', async () => {
      armScript('PRESENT', CODE)

      await service.verify('email_verification', 'user-hash', CODE)

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      expect(mockRedis.get).not.toHaveBeenCalled()
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining("redis.call('HGET', KEYS[1], 'code')"),
        [OTP_KEY],
        [CODE, '5']
      )
    })

    // Scenario: a static guard on the script itself. Expected: it bumps from the value IT read,
    // re-stores under the residual PTTL, and consumes on a match. Why: computing the bump
    // anywhere else is the race; re-storing with a fresh TTL would let a wrong guess extend the
    // OTP's lifetime; and the ceiling check has to precede the comparison so an exhausted
    // record cannot be probed further.
    it('should carry a script that bumps under the residual TTL and consumes on a match', async () => {
      armScript('PRESENT', CODE)
      await service.verify('email_verification', 'user-hash', CODE)
      const script = mockRedis.eval.mock.calls[0]?.[0] as string

      // The bump is in place. Computing it in the caller is the race this replaced, and
      // re-writing the whole record would reset the TTL — letting a wrong guess buy extra
      // OTP lifetime. `HINCRBY` does neither.
      expect(script).toContain("redis.call('HINCRBY', KEYS[1], 'attempts', 1)")
      // The ceiling is checked before the comparison, so an exhausted record cannot be
      // probed further.
      expect(script.indexOf('attempts >= tonumber(ARGV[2])')).toBeLessThan(
        script.indexOf('code == ARGV[1]')
      )
      // A correct code consumes the record: single-use.
      expect(script).toContain("redis.call('DEL', KEYS[1])")
      // No `cjson` in the executable body — the in-memory Redis the e2e tier runs against
      // does not provide it, which is why the record is a HASH.
      const executable = script
        .split('\n')
        .filter((line) => !line.trimStart().startsWith('--'))
        .join('\n')
      expect(executable).not.toContain('cjson')
    })

    // Scenario: every way an OTP verification can fail. Expected: one answer, `OTP_INVALID`,
    // for all of them.
    //
    // Telling them apart defeated the anti-enumeration in front of this. `forgot-password`
    // answers the same whether or not the address exists, but only writes an OTP record when
    // it does — so a caller could request a reset for an address and submit one wrong code:
    // `OTP_EXPIRED` meant "no record was ever written, no account here", `OTP_INVALID` meant
    // "there is one". `OTP_MAX_ATTEMPTS` said the same thing more slowly, since only a record
    // that exists can reach a ceiling. One extra request turned a uniform answer definitive.
    it.each([
      ['the record is gone', 'EXPIRED' as const, CODE],
      ['the attempt ceiling was reached', 'MAX' as const, CODE],
      ['the code is simply wrong', 'PRESENT' as const, '999999']
    ])('answers OTP_INVALID when %s', async (_label, tag, submitted) => {
      armScript(tag, CODE)

      try {
        await service.verify('email_verification', 'user-hash', submitted)
        throw new Error('expected a rejection')
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
      }
    })

    // Scenario: a wrong code while under the ceiling. Expected: OTP_INVALID.
    it('should throw OTP_INVALID for a wrong code below the ceiling', async () => {
      armScript('PRESENT', CODE)

      try {
        await service.verify('email_verification', 'user-hash', '999999')
        throw new Error('expected a rejection')
      } catch (e) {
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
      }
    })

    // Scenario: a submitted code of a different length. Expected: OTP_INVALID, not a crash.
    // Why: `crypto.timingSafeEqual` throws a RangeError on differing buffer sizes, so the
    // length check has to come first — and it leaks nothing, since the digit count is already
    // implied by the configured flow.
    it('should reject a length mismatch as OTP_INVALID rather than throwing', async () => {
      armScript('PRESENT', CODE)

      try {
        await service.verify('email_verification', 'user-hash', '1')
        throw new Error('expected a rejection')
      } catch (e) {
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
      }
    })

    // Scenario: the script answers with something outside its documented contract — a shape a
    // corrupt record or a future script change could produce. Expected: the same OTP_INVALID
    // every other failure gets. Why: any other answer would tell a caller that *something* is
    // stored under their identifier, which is the enumeration oracle the timing floor and the
    // single error code exist to close.
    it.each([
      ['a non-array reply', 'nonsense'],
      ['a short array', ['PRESENT']],
      ['an unknown tag', ['WAT', 'x']],
      ['a null reply', null]
    ])('should treat %s as a plain failure', async (_label, reply) => {
      mockRedis.eval.mockResolvedValue(reply)

      try {
        await service.verify('email_verification', 'user-hash', CODE)
        throw new Error('expected a rejection')
      } catch (e) {
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
      }
    })

    // Scenario: a PRESENT reply whose stored code is not a string. Expected: OTP_INVALID —
    // the comparison runs against the empty string and fails, rather than crashing on
    // `undefined.length`.
    it('should treat a non-string stored code as a mismatch', async () => {
      mockRedis.eval.mockResolvedValue(['PRESENT', 42])

      try {
        await service.verify('email_verification', 'user-hash', CODE)
        throw new Error('expected a rejection')
      } catch (e) {
        expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.OTP_INVALID)
      }
    })

    // ---------------------------------------------------------------------------
    // Timing normalization
    // ---------------------------------------------------------------------------

    // An empty submitted code must never verify, whatever the store answered.
    //
    // This is the case that separates "refused on the EXPIRED tag" from "fell through to the
    // comparison and happened to refuse there", because the comparison does NOT refuse it:
    // `crypto.timingSafeEqual` returns true for two empty buffers, so an empty code matches an
    // empty stored one. Every reply below therefore has to be refused by its own tag, before any
    // comparison is reached — if the tag arm stops working, these are the inputs that walk
    // straight through it into a successful verification.
    it.each([
      ['an expired record', ['EXPIRED', '']],
      ['an exhausted record', ['MAX', '']],
      ['a reply missing its second element', ['PRESENT']],
      ['a record whose stored code is not a string', ['PRESENT', 42]],
      ['a record whose stored code is empty', ['PRESENT', '']],
      ['a reply that is not an array at all', null]
    ])('should refuse an empty code against %s', async (_label, reply) => {
      mockRedis.eval.mockResolvedValue(reply)

      await expect(service.verify('email_verification', 'user-hash', '')).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.OTP_INVALID } }
      })
    })

    describe('timing normalization', () => {
      // Every outcome waits out the same floor, so response time cannot distinguish "no such
      // record" from "wrong code" from "exhausted" — the three answers an attacker probing for
      // a valid identifier would otherwise separate.
      it.each([
        ['success', ['PRESENT', CODE] as const, CODE],
        ['wrong code', ['PRESENT', CODE] as const, '999999'],
        ['expired', ['EXPIRED', ''] as const, CODE],
        ['max attempts', ['MAX', ''] as const, CODE]
      ])(
        'should pad the %s path to exactly the remaining floor',
        async (_label, reply, submitted) => {
          // The pad is asserted to the millisecond, against a clock this test drives. Anything
          // looser passes for a floor that does not hold: "some non-negative number" is equally
          // true of no padding at all (0), of a pad that grows with the work instead of
          // shrinking, and of one computed from a nonsense elapsed time.
          //
          // The elapsed time must be non-zero for the assertion to separate them — at elapsed 0,
          // `floor - elapsed` and `floor + elapsed` are the same number — so the Redis step
          // advances the clock by a known amount, which is also where the real time goes.
          let now = 1_700_000_000_000
          const nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => now)
          mockRedis.eval.mockImplementation(async () => {
            now += REDIS_STEP_MS
            return [...reply]
          })

          await service.verify('email_verification', 'user-hash', submitted).catch(() => undefined)

          expect(mockSleep).toHaveBeenCalledTimes(1)
          expect(mockSleep).toHaveBeenCalledWith(MIN_VERIFY_MS - REDIS_STEP_MS)
          nowSpy.mockRestore()
        }
      )

      // The other side of the clamp: work that already outran the floor is not padded further.
      // Without this the floor could be a negative sleep, which `sleep` would clamp for it —
      // masking the sign error until some other caller did not.
      it.each([
        ['success', ['PRESENT', CODE] as const, CODE],
        ['expired', ['EXPIRED', ''] as const, CODE]
      ])('should not pad the %s path when the work outran the floor', async (_l, reply, sent) => {
        let now = 1_700_000_000_000
        const nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => now)
        mockRedis.eval.mockImplementation(async () => {
          now += MIN_VERIFY_MS + 50
          return [...reply]
        })

        await service.verify('email_verification', 'user-hash', sent).catch(() => undefined)

        expect(mockSleep).toHaveBeenCalledWith(0)
        nowSpy.mockRestore()
      })
    })
  })
})
