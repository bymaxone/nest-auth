import { generateSecureToken, sha256, timingSafeCompare } from './secure-token'

// ---------------------------------------------------------------------------
// generateSecureToken
// ---------------------------------------------------------------------------

describe('generateSecureToken', () => {
  // Verifies that the default call (32 bytes) returns a 64-character lowercase hex string.
  it('should return a hex string of the correct length for the default 32 bytes', () => {
    const token = generateSecureToken()
    // 32 bytes × 2 hex chars per byte = 64 characters
    expect(token).toHaveLength(64)
    expect(token).toMatch(/^[0-9a-f]{64}$/)
  })

  // Verifies that passing a custom byte count produces a hex string of the correct derived length.
  it('should return a hex string of the correct length for a custom byte count', () => {
    expect(generateSecureToken(16)).toHaveLength(32)
    expect(generateSecureToken(48)).toHaveLength(96)
    expect(generateSecureToken(1)).toHaveLength(2)
  })

  // Verifies that all output characters are lowercase hex digits (no uppercase).
  it('should return lowercase hex characters only', () => {
    const token = generateSecureToken()
    expect(token).toMatch(/^[0-9a-f]+$/)
  })

  // Verifies that consecutive calls produce different tokens (cryptographically random output).
  it('should produce different tokens on each call', () => {
    const t1 = generateSecureToken()
    const t2 = generateSecureToken()
    expect(t1).not.toBe(t2)
  })

  // Verifies that passing 0 bytes throws with a clear error about requiring a positive integer.
  it('should throw when bytes is 0', () => {
    expect(() => generateSecureToken(0)).toThrow(/positive integer/)
  })

  // Verifies that a negative byte count throws with a clear error message.
  it('should throw when bytes is negative', () => {
    expect(() => generateSecureToken(-1)).toThrow(/positive integer/)
  })

  // Verifies that a non-integer float throws because crypto.randomBytes requires an integer.
  it('should throw when bytes is a float', () => {
    expect(() => generateSecureToken(1.5)).toThrow(/positive integer/)
  })

  // Verifies that NaN is rejected as it would produce an invalid buffer size.
  it('should throw when bytes is NaN', () => {
    expect(() => generateSecureToken(NaN)).toThrow(/positive integer/)
  })
})

// ---------------------------------------------------------------------------
// sha256
// ---------------------------------------------------------------------------

describe('sha256', () => {
  // Verifies that the output is a 64-character lowercase hex string (256 bits / 4 bits per hex char).
  it('should return a 64-character lowercase hex digest', () => {
    const hash = sha256('hello world')
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  // Verifies that the same input always produces the same hash (deterministic).
  it('should return a consistent hash for the same input', () => {
    const input = 'user@example.com'
    expect(sha256(input)).toBe(sha256(input))
  })

  // Verifies the known SHA-256 digest for 'hello world' against a reference implementation.
  it('should return the known SHA-256 hash for "hello world"', () => {
    // Computed with node:crypto reference — verified with Node.js v20
    expect(sha256('hello world')).toBe(
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    )
  })

  // Verifies that different inputs produce different digests (collision avoidance).
  it('should return different hashes for different inputs', () => {
    expect(sha256('input-a')).not.toBe(sha256('input-b'))
  })

  // Verifies that the empty string produces the well-known SHA-256 empty-string digest.
  it('should handle an empty string', () => {
    // sha256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const hash = sha256('')
    expect(hash).toHaveLength(64)
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  // Verifies that multi-byte unicode characters are correctly digested without truncation.
  it('should handle unicode input', () => {
    const hash = sha256('hello 😀')
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })
})

// ---------------------------------------------------------------------------
// timingSafeCompare
// ---------------------------------------------------------------------------

describe('timingSafeCompare', () => {
  // Verifies that two identical strings produce a true result from the constant-time comparison.
  it('should return true for identical strings', () => {
    const hash = sha256('same-token')
    expect(timingSafeCompare(hash, hash)).toBe(true)
  })

  // Verifies that two different strings of the same length return false (no short-circuit on length).
  it('should return false for different strings of the same length', () => {
    const a = sha256('token-a')
    const b = sha256('token-b')
    expect(timingSafeCompare(a, b)).toBe(false)
  })

  // Verifies that strings of different lengths return false without throwing.
  it('should return false for strings of different lengths', () => {
    expect(timingSafeCompare('short', 'longer-string')).toBe(false)
  })

  // Verifies that two empty strings compare as equal (both convert to zero-length Buffers).
  it('should return true for empty strings', () => {
    expect(timingSafeCompare('', '')).toBe(true)
  })

  // Verifies that an empty string does not match a non-empty string in either argument position.
  it('should return false when one string is empty and the other is not', () => {
    expect(timingSafeCompare('', 'nonempty')).toBe(false)
    expect(timingSafeCompare('nonempty', '')).toBe(false)
  })
})
