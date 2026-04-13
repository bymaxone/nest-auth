import { AuthException } from '../../errors/auth-exception'
import { assertTokenType } from './assert-token-type'

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
