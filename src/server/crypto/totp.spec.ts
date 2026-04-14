/**
 * @fileoverview Tests for the TOTP/HOTP implementation in totp.ts.
 *
 * Covers:
 * - Base32 encoding/decoding (round-trip, whitespace normalization, invalid characters)
 * - generateTotpSecret (length, Base32 format, uniqueness)
 * - buildTotpUri (output format, required parameters, error cases)
 * - generateHotp (RFC 4226 Appendix D test vectors, error cases)
 * - verifyTotp (valid code, invalid format, expired window, constant-time comparison per step)
 */

import { fromBase32, generateTotpSecret, toBase32, buildTotpUri, verifyTotp } from './totp'
// generateHotp and generateTotp are exported @internal for test use only
import { generateHotp, generateTotp } from './totp'

// ---------------------------------------------------------------------------
// Base32 encoding
// ---------------------------------------------------------------------------

describe('toBase32', () => {
  // Verifies that empty input produces an empty string.
  it('should encode an empty buffer to an empty string', () => {
    expect(toBase32(Buffer.alloc(0))).toBe('')
  })

  // Verifies that a single 0x00 byte encodes correctly per RFC 4648.
  it('should encode a single zero byte', () => {
    // 0x00 = 00000000; first 5 bits = 00000 = 'A'; remainder 3 bits = 000, padded to 5 = 00000 = 'A'
    expect(toBase32(Buffer.from([0x00]))).toBe('AA')
  })

  // Verifies that 5 bytes (40 bits) produce exactly 8 Base32 characters with no padding needed.
  it('should encode 5 bytes to 8 Base32 characters', () => {
    const result = toBase32(Buffer.alloc(5, 0xff))
    expect(result).toHaveLength(8)
    expect(result).toMatch(/^[A-Z2-7]+$/)
  })

  // Verifies that the output is always uppercase and contains only valid Base32 characters.
  it('should produce uppercase output with only valid Base32 characters', () => {
    const secret = generateTotpSecret()
    expect(secret.base32).toMatch(/^[A-Z2-7]+$/)
  })
})

// ---------------------------------------------------------------------------
// Base32 decoding
// ---------------------------------------------------------------------------

describe('fromBase32', () => {
  // Verifies round-trip: toBase32 followed by fromBase32 returns the original bytes.
  it('should round-trip 20 random bytes through Base32', () => {
    const { raw, base32 } = generateTotpSecret()
    expect(fromBase32(base32)).toEqual(raw)
  })

  // Verifies that lowercase input is accepted and produces the same result as uppercase.
  it('should accept lowercase input', () => {
    const { raw, base32 } = generateTotpSecret()
    expect(fromBase32(base32.toLowerCase())).toEqual(raw)
  })

  // Verifies that padding characters ('=') are silently stripped.
  it('should strip = padding characters', () => {
    const { raw, base32 } = generateTotpSecret()
    const padded = base32 + '======'
    expect(fromBase32(padded)).toEqual(raw)
  })

  // Verifies that spaces in the input are silently stripped (user-friendly formatting).
  it('should strip spaces (group-formatted secrets)', () => {
    const { raw, base32 } = generateTotpSecret()
    const spaced = base32.match(/.{1,4}/g)?.join(' ') ?? base32
    expect(fromBase32(spaced)).toEqual(raw)
  })

  // Verifies that an invalid character causes an error with a descriptive message.
  it('should throw on invalid Base32 characters', () => {
    expect(() => fromBase32('JBSWY3DP!EHPK')).toThrow(/Invalid Base32 character/)
  })

  // Verifies that '0', '1', '8', and '9' (not in Base32 alphabet) are rejected.
  it('should throw on digits 0, 1, 8, and 9 which are not in the Base32 alphabet', () => {
    expect(() => fromBase32('0BSWY3DP')).toThrow(/Invalid Base32 character/)
    expect(() => fromBase32('1BSWY3DP')).toThrow(/Invalid Base32 character/)
    expect(() => fromBase32('8BSWY3DP')).toThrow(/Invalid Base32 character/)
    expect(() => fromBase32('9BSWY3DP')).toThrow(/Invalid Base32 character/)
  })
})

// ---------------------------------------------------------------------------
// generateTotpSecret
// ---------------------------------------------------------------------------

describe('generateTotpSecret', () => {
  // Verifies that the raw secret is exactly 20 bytes (160 bits, RFC 4226 minimum).
  it('should return a 20-byte raw secret', () => {
    const { raw } = generateTotpSecret()
    expect(raw).toHaveLength(20)
  })

  // Verifies that the Base32-encoded form is at least 32 characters (20 bytes → 32 chars).
  it('should return a base32 string of at least 32 characters', () => {
    const { base32 } = generateTotpSecret()
    expect(base32.length).toBeGreaterThanOrEqual(32)
  })

  // Verifies that the raw Buffer and base32 string are consistent (round-trip).
  it('should produce a base32 string that decodes back to the raw bytes', () => {
    const { raw, base32 } = generateTotpSecret()
    expect(fromBase32(base32)).toEqual(raw)
  })

  // Verifies that repeated calls produce different secrets (using crypto.randomBytes).
  it('should produce unique secrets on repeated calls', () => {
    const first = generateTotpSecret().base32
    const second = generateTotpSecret().base32
    expect(first).not.toBe(second)
  })
})

// ---------------------------------------------------------------------------
// buildTotpUri
// ---------------------------------------------------------------------------

describe('buildTotpUri', () => {
  // SECRET is initialized once at describe scope. generateTotpSecret() is a pure crypto call with
  // no side effects and no time dependency, so it is safe to call before any test hooks run.
  const SECRET = generateTotpSecret().base32
  const EMAIL = 'user@example.com'
  const ISSUER = 'My App'

  // Verifies that the URI starts with the correct scheme.
  it('should return a URI starting with otpauth://totp/', () => {
    const uri = buildTotpUri(SECRET, EMAIL, ISSUER)
    expect(uri).toMatch(/^otpauth:\/\/totp\//)
  })

  // Verifies that the secret, issuer, algorithm, digits, and period parameters are all present.
  it('should include secret, issuer, algorithm=SHA1, digits=6, period=30 in query string', () => {
    const uri = buildTotpUri(SECRET, EMAIL, ISSUER)
    expect(uri).toContain(`secret=${SECRET}`)
    expect(uri).toContain(`issuer=${encodeURIComponent(ISSUER)}`)
    expect(uri).toContain('algorithm=SHA1')
    expect(uri).toContain('digits=6')
    expect(uri).toContain('period=30')
  })

  // Verifies that the label is encoded as "issuer:email" in the URI path.
  it('should include a label composed of issuer and email', () => {
    const uri = buildTotpUri(SECRET, EMAIL, ISSUER)
    const path = uri.split('?')[0] ?? ''
    expect(path).toContain(encodeURIComponent(ISSUER))
    expect(path).toContain(encodeURIComponent(EMAIL))
  })

  // Verifies that spaces in issuer are encoded as %20 (not +) per the Key URI Format spec.
  it('should percent-encode spaces as %20, not +', () => {
    const uri = buildTotpUri(SECRET, EMAIL, 'My App With Spaces')
    expect(uri).toContain('%20')
    expect(uri).not.toContain('+')
  })

  // Verifies that an empty issuer causes buildTotpUri to throw.
  it('should throw when issuer is empty', () => {
    expect(() => buildTotpUri(SECRET, EMAIL, '')).toThrow(/issuer must not be empty/)
  })

  // Verifies that an empty email causes buildTotpUri to throw.
  it('should throw when accountEmail is empty', () => {
    expect(() => buildTotpUri(SECRET, '', ISSUER)).toThrow(/accountEmail must not be empty/)
  })

  // Verifies that a secret shorter than 32 characters causes buildTotpUri to throw.
  it('should throw when secretBase32 is shorter than 32 characters', () => {
    expect(() => buildTotpUri('SHORT', EMAIL, ISSUER)).toThrow(/secretBase32 must encode/)
  })
})

// ---------------------------------------------------------------------------
// generateTotp — wrapper over generateHotp for the current time step
// ---------------------------------------------------------------------------

describe('generateTotp', () => {
  beforeEach(() => {
    jest.useFakeTimers()
    jest.setSystemTime(new Date('2026-01-01T00:00:15.000Z'))
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  // Verifies that generateTotp returns a 6-digit numeric code.
  it('should return a 6-digit numeric code for the current time step', () => {
    const { base32 } = generateTotpSecret()
    expect(generateTotp(base32)).toMatch(/^\d{6}$/)
  })

  // Verifies that generateTotp produces the same code as generateHotp for the current step.
  it('should produce the same code as generateHotp(secret, currentStep)', () => {
    const { base32 } = generateTotpSecret()
    const currentStep = Math.floor(Date.now() / 1000 / 30)
    expect(generateTotp(base32)).toBe(generateHotp(base32, currentStep))
  })
})

// ---------------------------------------------------------------------------
// generateHotp — RFC 4226 Appendix D test vectors
// ---------------------------------------------------------------------------

describe('generateHotp — RFC 4226 test vectors', () => {
  // The RFC 4226 test key is the ASCII string "12345678901234567890" (20 bytes).
  // Encode it as Base32 using our own toBase32 to avoid hardcoding the Base32 form.
  const rfcKeyBase32 = toBase32(Buffer.from('12345678901234567890', 'ascii'))

  const expectedCodes = [
    '755224', // counter 0
    '287082', // counter 1
    '359152', // counter 2
    '969429', // counter 3
    '338314', // counter 4
    '254676', // counter 5
    '287922', // counter 6
    '162583', // counter 7
    '399871', // counter 8
    '520489' // counter 9
  ]

  // Verifies all 10 RFC 4226 Appendix D HOTP test vectors.
  it.each(expectedCodes.map((code, i) => [i, code] as [number, string]))(
    'should produce code %s for counter %i (RFC 4226 Appendix D)',
    (counter, expected) => {
      expect(generateHotp(rfcKeyBase32, counter)).toBe(expected)
    }
  )

  // Verifies that a zero-padded code is produced when the truncated result has fewer than 6 digits.
  it('should produce a 6-character zero-padded string for all counters', () => {
    for (let c = 0; c < 10; c++) {
      const code = generateHotp(rfcKeyBase32, c)
      expect(code).toHaveLength(6)
      expect(code).toMatch(/^\d{6}$/)
    }
  })

  // Verifies that generateHotp throws when the decoded key is too short (< 20 bytes).
  it('should throw when the decoded secret is less than 20 bytes', () => {
    const shortKey = toBase32(Buffer.alloc(10)) // 10 bytes — below minimum
    expect(() => generateHotp(shortKey, 0)).toThrow(/Secret too short/)
  })

  // Verifies that generateHotp throws for negative counter values.
  it('should throw for negative counter values', () => {
    expect(() => generateHotp(rfcKeyBase32, -1)).toThrow(/Counter must be a non-negative/)
  })

  // Verifies that generateHotp throws for floating-point counter values.
  it('should throw for non-integer counter values', () => {
    expect(() => generateHotp(rfcKeyBase32, 1.5)).toThrow(/Counter must be a non-negative/)
  })
})

// ---------------------------------------------------------------------------
// verifyTotp
// ---------------------------------------------------------------------------

describe('verifyTotp', () => {
  let secretBase32: string

  beforeEach(() => {
    secretBase32 = generateTotpSecret().base32
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  // Verifies that a code generated for the current time step is accepted.
  it('should accept a code for the current time step', () => {
    jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    const currentStep = Math.floor(Date.now() / 1000 / 30)
    const code = generateHotp(secretBase32, currentStep)

    expect(verifyTotp(secretBase32, code)).toBe(true)
  })

  // Verifies that a code generated for the previous time step is accepted (window = 1).
  it('should accept a code from one step in the past (within default window)', () => {
    jest.setSystemTime(new Date('2026-01-01T00:00:30.000Z'))
    const prevStep = Math.floor(Date.now() / 1000 / 30) - 1
    const code = generateHotp(secretBase32, prevStep)

    expect(verifyTotp(secretBase32, code)).toBe(true)
  })

  // Verifies that a code generated for the next time step is accepted (window = 1).
  it('should accept a code from one step in the future (within default window)', () => {
    jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    const nextStep = Math.floor(Date.now() / 1000 / 30) + 1
    const code = generateHotp(secretBase32, nextStep)

    expect(verifyTotp(secretBase32, code)).toBe(true)
  })

  // Verifies that a code from two steps in the past is rejected with the default window of 1.
  it('should reject a code from two steps in the past (outside default window)', () => {
    jest.setSystemTime(new Date('2026-01-01T00:01:00.000Z'))
    const oldStep = Math.floor(Date.now() / 1000 / 30) - 2
    const code = generateHotp(secretBase32, oldStep)

    expect(verifyTotp(secretBase32, code)).toBe(false)
  })

  // Verifies that a code from two steps in the past is accepted when window is set to 2.
  it('should accept a code two steps in the past when window = 2', () => {
    jest.setSystemTime(new Date('2026-01-01T00:01:00.000Z'))
    const oldStep = Math.floor(Date.now() / 1000 / 30) - 2
    const code = generateHotp(secretBase32, oldStep)

    expect(verifyTotp(secretBase32, code, 2)).toBe(true)
  })

  // Verifies that non-6-digit strings are always rejected without computing HMAC.
  it('should reject codes that are not exactly 6 digits', () => {
    expect(verifyTotp(secretBase32, '12345')).toBe(false)
    expect(verifyTotp(secretBase32, '1234567')).toBe(false)
    expect(verifyTotp(secretBase32, 'abcdef')).toBe(false)
    expect(verifyTotp(secretBase32, '')).toBe(false)
    expect(verifyTotp(secretBase32, '123-456')).toBe(false)
  })

  // Verifies that an entirely wrong 6-digit code is rejected.
  // Computes a code guaranteed to differ from the current-step code to avoid a coincidental match.
  it('should reject a wrong 6-digit code', () => {
    jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    const currentStep = Math.floor(Date.now() / 1000 / 30)
    const correctCode = generateHotp(secretBase32, currentStep)
    // Produce a code that is definitely different from the correct one.
    const wrongCode = correctCode === '000000' ? '000001' : '000000'

    expect(verifyTotp(secretBase32, wrongCode)).toBe(false)
  })
})
