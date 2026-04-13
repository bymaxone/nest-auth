/**
 * @fileoverview Tests for AES-256-GCM encrypt/decrypt functions in aes-gcm.ts.
 * Covers round-trip correctness, IV uniqueness, output format, tamper detection,
 * wrong-key rejection, and input validation — including the branch paths for
 * invalid IV length and invalid auth tag length that complete branch coverage.
 */

import { decrypt, encrypt } from './aes-gcm'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Valid 32-byte AES-256 key encoded in base64. */
const VALID_KEY = Buffer.alloc(32, 0xab).toString('base64')

/** A different valid 32-byte key for wrong-key tests. */
const WRONG_KEY = Buffer.alloc(32, 0xcd).toString('base64')

// ---------------------------------------------------------------------------
// Round-trip (encrypt → decrypt)
// ---------------------------------------------------------------------------

describe('aes-gcm — round-trip', () => {
  // Verifies that encrypt followed by decrypt reproduces the original TOTP-like string.
  it('should decrypt to the original plaintext (standard input)', () => {
    const plaintext = 'JBSWY3DPEHPK3PXP'
    expect(decrypt(encrypt(plaintext, VALID_KEY), VALID_KEY)).toBe(plaintext)
  })

  // Verifies that an empty string is a valid plaintext (no crash, round-trip correct).
  it('should handle an empty string', () => {
    expect(decrypt(encrypt('', VALID_KEY), VALID_KEY)).toBe('')
  })

  // Verifies that a single-character plaintext survives the round-trip.
  it('should handle a short string (1 character)', () => {
    const plaintext = 'x'
    expect(decrypt(encrypt(plaintext, VALID_KEY), VALID_KEY)).toBe(plaintext)
  })

  // Verifies that large plaintexts are handled correctly without truncation.
  it('should handle a long string (10 000 characters)', () => {
    const plaintext = 'a'.repeat(10_000)
    expect(decrypt(encrypt(plaintext, VALID_KEY), VALID_KEY)).toBe(plaintext)
  })

  // Verifies that multi-byte unicode and special characters survive the UTF-8 round-trip.
  it('should handle special characters and unicode', () => {
    const plaintext = '😀 special chars: \n\t\r<>&"'
    expect(decrypt(encrypt(plaintext, VALID_KEY), VALID_KEY)).toBe(plaintext)
  })

  // Verifies that JSON-serialized objects are correctly encrypted and decrypted.
  it('should handle JSON payloads', () => {
    const plaintext = JSON.stringify({ userId: '123', secret: 'TOTP_SECRET_BASE32' })
    expect(decrypt(encrypt(plaintext, VALID_KEY), VALID_KEY)).toBe(plaintext)
  })
})

// ---------------------------------------------------------------------------
// IV uniqueness (encrypt produces different ciphertexts)
// ---------------------------------------------------------------------------

describe('aes-gcm — IV uniqueness', () => {
  // Verifies that two encryptions of the same plaintext produce different ciphertexts due to the random IV.
  it('should produce different ciphertexts for the same plaintext (random IV)', () => {
    const plaintext = 'same-input'
    const first = encrypt(plaintext, VALID_KEY)
    const second = encrypt(plaintext, VALID_KEY)
    expect(first).not.toBe(second)
  })

  // Verifies that the IV segment differs between consecutive encrypt calls.
  it('should produce different IVs across consecutive calls', () => {
    const extractIv = (ct: string): string => ct.split(':')[0] ?? ''
    const iv1 = extractIv(encrypt('data', VALID_KEY))
    const iv2 = extractIv(encrypt('data', VALID_KEY))
    expect(iv1).not.toBe(iv2)
  })
})

// ---------------------------------------------------------------------------
// Output format
// ---------------------------------------------------------------------------

describe('aes-gcm — output format', () => {
  // Verifies that the wire format is three colon-separated base64 segments.
  it('should produce output in base64:base64:base64 format', () => {
    const ciphertext = encrypt('test', VALID_KEY)
    const parts = ciphertext.split(':')
    expect(parts).toHaveLength(3)
    const base64Re = /^[A-Za-z0-9+/]+=*$/
    for (const part of parts) {
      expect(part).toMatch(base64Re)
    }
  })

  // Verifies that the IV segment decodes to exactly 12 bytes as required by AES-GCM NIST recommendation.
  it('should produce a 12-byte (16 base64 char) IV', () => {
    const ciphertext = encrypt('test', VALID_KEY)
    const iv = ciphertext.split(':')[0] ?? ''
    // 12 bytes → 16 base64 chars (with padding)
    expect(Buffer.from(iv, 'base64')).toHaveLength(12)
  })

  // Verifies that the auth tag segment decodes to exactly 16 bytes (NIST recommended maximum).
  it('should produce a 16-byte (24 base64 char) auth tag', () => {
    const ciphertext = encrypt('test', VALID_KEY)
    const authTag = ciphertext.split(':')[1] ?? ''
    expect(Buffer.from(authTag, 'base64')).toHaveLength(16)
  })
})

// ---------------------------------------------------------------------------
// Tamper detection (GCM auth tag)
// ---------------------------------------------------------------------------

describe('aes-gcm — tamper detection', () => {
  // Verifies that flipping a byte in the GCM auth tag causes decryption to throw (integrity protected).
  it('should throw when the auth tag is tampered', () => {
    const ciphertext = encrypt('sensitive-data', VALID_KEY)
    const [iv, authTag, payload] = ciphertext.split(':') as [string, string, string]

    // Flip a byte in the auth tag
    const tagBytes = Buffer.from(authTag, 'base64')
    tagBytes[0] = (tagBytes[0] ?? 0) ^ 0xff
    const tamperedCt = [iv, tagBytes.toString('base64'), payload].join(':')

    expect(() => decrypt(tamperedCt, VALID_KEY)).toThrow()
  })

  // Verifies that flipping a byte in the ciphertext payload causes auth tag verification to fail.
  it('should throw when the ciphertext payload is tampered', () => {
    const ciphertext = encrypt('sensitive-data', VALID_KEY)
    const [iv, authTag, payload] = ciphertext.split(':') as [string, string, string]

    const payloadBytes = Buffer.from(payload, 'base64')
    payloadBytes[0] = (payloadBytes[0] ?? 0) ^ 0xff
    const tamperedCt = [iv, authTag, payloadBytes.toString('base64')].join(':')

    expect(() => decrypt(tamperedCt, VALID_KEY)).toThrow()
  })
})

// ---------------------------------------------------------------------------
// Wrong key
// ---------------------------------------------------------------------------

describe('aes-gcm — wrong key', () => {
  // Verifies that using a different key for decryption causes GCM auth tag verification to fail.
  it('should throw when decrypting with a different key', () => {
    const ciphertext = encrypt('secret-mfa-token', VALID_KEY)
    expect(() => decrypt(ciphertext, WRONG_KEY)).toThrow()
  })
})

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

describe('aes-gcm — input validation', () => {
  // Verifies that encrypt rejects a key shorter than 32 bytes to prevent weak encryption.
  it('should throw on encrypt when key does not decode to 32 bytes', () => {
    const shortKey = Buffer.alloc(16).toString('base64') // 16 bytes, not 32
    expect(() => encrypt('test', shortKey)).toThrow(/32 bytes/)
  })

  // Verifies that decrypt rejects a short key before attempting decryption.
  it('should throw on decrypt when key does not decode to 32 bytes', () => {
    const ciphertext = encrypt('test', VALID_KEY)
    const shortKey = Buffer.alloc(16).toString('base64')
    expect(() => decrypt(ciphertext, shortKey)).toThrow(/32 bytes/)
  })

  // Verifies that decrypt rejects ciphertexts that do not have exactly three colon-separated segments.
  it('should throw on decrypt when ciphertext has wrong segment count', () => {
    expect(() => decrypt('only-two:parts', VALID_KEY)).toThrow(/Invalid ciphertext format/)
    expect(() => decrypt('one', VALID_KEY)).toThrow(/Invalid ciphertext format/)
    expect(() => decrypt('a:b:c:d', VALID_KEY)).toThrow(/Invalid ciphertext format/)
  })

  // Verifies that decrypt rejects a ciphertext whose IV segment decodes to the wrong length (not 12 bytes).
  it('should throw on decrypt when IV decodes to wrong length', () => {
    // Build a fake ciphertext where the IV is only 6 bytes (not the required 12).
    const shortIv = Buffer.alloc(6).toString('base64')
    const validAuthTag = Buffer.alloc(16).toString('base64')
    const validPayload = Buffer.alloc(8).toString('base64')
    const fakeCiphertext = `${shortIv}:${validAuthTag}:${validPayload}`
    expect(() => decrypt(fakeCiphertext, VALID_KEY)).toThrow(/Invalid IV length/)
  })

  // Verifies that decrypt rejects a ciphertext whose auth tag segment decodes to the wrong length (not 16 bytes).
  it('should throw on decrypt when auth tag decodes to wrong length', () => {
    // Build a fake ciphertext with a valid 12-byte IV but only 8-byte auth tag.
    const validIv = Buffer.alloc(12).toString('base64')
    const shortAuthTag = Buffer.alloc(8).toString('base64')
    const validPayload = Buffer.alloc(8).toString('base64')
    const fakeCiphertext = `${validIv}:${shortAuthTag}:${validPayload}`
    expect(() => decrypt(fakeCiphertext, VALID_KEY)).toThrow(/Invalid auth tag length/)
  })
})
