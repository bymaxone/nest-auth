import { AuthException } from '../../errors/auth-exception'
import { assertTokenType, assertValidSub } from './assert-token-type'

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
