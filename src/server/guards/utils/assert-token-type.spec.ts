import { AuthException } from '../../errors/auth-exception'
import { assertTokenType, assertValidJti, assertValidSub } from './assert-token-type'

describe('assertTokenType', () => {
  // Verifies that no exception is thrown when the payload type matches the expected type exactly.
  it('should not throw when payload.type matches expectedType', () => {
    expect(() => assertTokenType({ type: 'dashboard' }, 'dashboard')).not.toThrow()
  })

  // Verifies that an AuthException is thrown when payload.type does not match the expected type.
  it('should throw TOKEN_INVALID when payload.type does not match', () => {
    expect(() => assertTokenType({ type: 'platform' }, 'dashboard')).toThrow(AuthException)
  })

  // Verifies that a missing type property causes TOKEN_INVALID to be thrown.
  it('should throw TOKEN_INVALID when payload.type is missing', () => {
    expect(() => assertTokenType({}, 'dashboard')).toThrow(AuthException)
  })

  // Verifies that an omitted type property (undefined via missing key) also throws TOKEN_INVALID.
  it('should throw TOKEN_INVALID when payload.type is absent (property missing)', () => {
    // exactOptionalPropertyTypes: use {} (omitted property) instead of { type: undefined }
    expect(() => assertTokenType({}, 'dashboard')).toThrow(AuthException)
  })

  // Verifies that platform tokens pass validation when the expected type is 'platform'.
  it('should not throw for platform type when expectedType is platform', () => {
    expect(() => assertTokenType({ type: 'platform' }, 'platform')).not.toThrow()
  })

  // Verifies that an mfa_challenge token is rejected when a dashboard token is expected.
  it('should throw when mfa_challenge type is used against dashboard', () => {
    expect(() => assertTokenType({ type: 'mfa_challenge' }, 'dashboard')).toThrow(AuthException)
  })
})

describe('assertValidSub', () => {
  // Accepts common legitimate subject shapes: UUIDs, ULIDs, numeric IDs, composite strings.
  it.each([
    'bf9d3a10-5c33-4a72-9f31-83dc7c7e2b44',
    '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    '42',
    'tenant-a:user-123',
    'user@example.com'
  ])('should accept well-formed sub value %p', (value) => {
    expect(() => assertValidSub(value)).not.toThrow()
  })

  // Rejects empty strings — they produce degenerate Redis keys like `us:` which collapse
  // into a single shared namespace across users.
  it('should throw when sub is an empty string', () => {
    expect(() => assertValidSub('')).toThrow(AuthException)
  })

  // Rejects non-string values — a forged or misconfigured signer emitting `sub` as a
  // number or object would otherwise flow into string-concatenation and produce keys
  // like `us:[object Object]`.
  it.each([null, undefined, 42, {}, []])('should throw when sub is %p', (value) => {
    expect(() => assertValidSub(value)).toThrow(AuthException)
  })

  // Rejects pathologically long strings that would bloat Redis key space without
  // carrying legitimate identifier information.
  it('should throw when sub exceeds the 256-character upper bound', () => {
    expect(() => assertValidSub('a'.repeat(257))).toThrow(AuthException)
  })

  // Accepts exactly the upper-bound length — the boundary is inclusive.
  it('should accept sub at exactly the 256-character upper bound', () => {
    expect(() => assertValidSub('a'.repeat(256))).not.toThrow()
  })
})

describe('assertValidJti', () => {
  const VALID_JTI = 'bf9d3a10-5c33-4a72-9f31-83dc7c7e2b44'

  /**
   * Canonical acceptance — pins every character class and segment-length
   * quantifier in the UUID v4 pattern at once: any mutation that narrows a hex
   * class, negates one, or drops a `{n}` quantifier causes this valid value to
   * be rejected and fails this test.
   */
  it('should accept a well-formed lowercase UUID v4', () => {
    expect(() => assertValidJti(VALID_JTI)).not.toThrow()
  })

  // The pattern is case-insensitive (/i flag) — uppercase UUIDs are valid jti.
  it('should accept a well-formed uppercase UUID v4', () => {
    expect(() => assertValidJti(VALID_JTI.toUpperCase())).not.toThrow()
  })

  /**
   * Leading-anchor enforcement.
   *
   * Pins the `^` anchor: without it, a UUID embedded at the end of a longer
   * string would be accepted, enabling key-shape injection via `rv:${jti}`.
   */
  it('should throw when a valid UUID is preceded by extra characters', () => {
    expect(() => assertValidJti(`zz${VALID_JTI}`)).toThrow(AuthException)
  })

  /**
   * Trailing-anchor enforcement.
   *
   * Pins the `$` anchor: without it, a UUID followed by arbitrary suffix
   * characters would be accepted.
   */
  it('should throw when a valid UUID is followed by extra characters', () => {
    expect(() => assertValidJti(`${VALID_JTI}zz`)).toThrow(AuthException)
  })

  /**
   * Single-position near-misses — each value differs from a valid UUID v4 in
   * exactly one structural element, pinning that segment's length and alphabet.
   */
  it.each([
    ['non-hex char in the first block', 'gf9d3a10-5c33-4a72-9f31-83dc7c7e2b44'],
    ['7-char first block', 'bf9d3a1-5c33-4a72-9f31-83dc7c7e2b44'],
    ['3-char second block', 'bf9d3a10-5c3-4a72-9f31-83dc7c7e2b44'],
    ['version nibble not 4', 'bf9d3a10-5c33-5a72-9f31-83dc7c7e2b44'],
    ['variant nibble not [89ab]', 'bf9d3a10-5c33-4a72-7f31-83dc7c7e2b44'],
    ['11-char final block', 'bf9d3a10-5c33-4a72-9f31-83dc7c7e2b4'],
    ['hyphens removed', 'bf9d3a105c334a729f3183dc7c7e2b44']
  ])('should throw for a malformed jti (%s)', (_label, value) => {
    expect(() => assertValidJti(value)).toThrow(AuthException)
  })

  // Non-string values must be rejected before any Redis key is built from jti.
  it.each([null, undefined, 42, {}, []])('should throw when jti is %p', (value) => {
    expect(() => assertValidJti(value)).toThrow(AuthException)
  })
})
