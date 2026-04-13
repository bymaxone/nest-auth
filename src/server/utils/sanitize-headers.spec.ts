import { sanitizeHeaders } from './sanitize-headers'

describe('sanitizeHeaders', () => {
  // ---------------------------------------------------------------------------
  // Exact-match blocklist
  // ---------------------------------------------------------------------------

  describe('exact-match blocklist', () => {
    // Verifies that the 'authorization' header is removed from the output.
    it('should remove "authorization" header', () => {
      const result = sanitizeHeaders({ authorization: 'Bearer secret-token' })
      expect(result).not.toHaveProperty('authorization')
    })

    // Verifies that the 'cookie' header is removed to prevent session token leakage.
    it('should remove "cookie" header', () => {
      const result = sanitizeHeaders({ cookie: 'session=abc123' })
      expect(result).not.toHaveProperty('cookie')
    })

    // Verifies that 'x-api-key' is removed even when passed with mixed-case (case-insensitive blocklist).
    it('should remove "x-api-key" header (case-insensitive input)', () => {
      const result = sanitizeHeaders({ 'X-Api-Key': 'my-key' })
      expect(result).not.toHaveProperty('x-api-key')
    })

    // Verifies that the 'x-auth-token' header is removed from the sanitized output.
    it('should remove "x-auth-token" header', () => {
      const result = sanitizeHeaders({ 'x-auth-token': 'tok' })
      expect(result).not.toHaveProperty('x-auth-token')
    })

    // Verifies that the 'x-csrf-token' header is removed to prevent CSRF token leakage.
    it('should remove "x-csrf-token" header', () => {
      const result = sanitizeHeaders({ 'x-csrf-token': 'csrf' })
      expect(result).not.toHaveProperty('x-csrf-token')
    })

    // Verifies that the 'proxy-authorization' header is removed to prevent proxy credential leakage.
    it('should remove "proxy-authorization" header', () => {
      const result = sanitizeHeaders({ 'proxy-authorization': 'Basic abc' })
      expect(result).not.toHaveProperty('proxy-authorization')
    })

    // Verifies that the 'www-authenticate' header is removed from the sanitized output.
    it('should remove "www-authenticate" header', () => {
      const result = sanitizeHeaders({ 'www-authenticate': 'Basic realm="test"' })
      expect(result).not.toHaveProperty('www-authenticate')
    })

    // Verifies that the 'x-session-id' header is removed to prevent session ID leakage.
    it('should remove "x-session-id" header', () => {
      const result = sanitizeHeaders({ 'x-session-id': 'session-123' })
      expect(result).not.toHaveProperty('x-session-id')
    })
  })

  // ---------------------------------------------------------------------------
  // Pattern-based blocklist (x-*-(token|secret|key|...) suffix)
  // ---------------------------------------------------------------------------

  describe('pattern-based blocklist', () => {
    // Verifies that 'x-refresh-token' is removed by the wildcard *-token pattern.
    it('should remove "x-refresh-token" (matches *-token pattern)', () => {
      const result = sanitizeHeaders({ 'x-refresh-token': 'refresh-abc' })
      expect(result).not.toHaveProperty('x-refresh-token')
    })

    // Verifies that 'x-access-token' is removed by the wildcard *-token pattern.
    it('should remove "x-access-token" (matches *-token pattern)', () => {
      const result = sanitizeHeaders({ 'x-access-token': 'access-abc' })
      expect(result).not.toHaveProperty('x-access-token')
    })

    // Verifies that 'x-client-secret' is removed by the wildcard *-secret pattern.
    it('should remove "x-client-secret" (matches *-secret pattern)', () => {
      const result = sanitizeHeaders({ 'x-client-secret': 'secret-value' })
      expect(result).not.toHaveProperty('x-client-secret')
    })

    // Verifies that 'x-service-key' is removed by the wildcard *-key pattern.
    it('should remove "x-service-key" (matches *-key pattern)', () => {
      const result = sanitizeHeaders({ 'x-service-key': 'key-value' })
      expect(result).not.toHaveProperty('x-service-key')
    })

    // Verifies that 'x-api-password' is removed by the wildcard *-password pattern.
    it('should remove "x-api-password" (matches *-password pattern)', () => {
      const result = sanitizeHeaders({ 'x-api-password': 'pass' })
      expect(result).not.toHaveProperty('x-api-password')
    })

    // Verifies that 'x-webhook-signature' is removed by the wildcard *-signature pattern.
    it('should remove "x-webhook-signature" (matches *-signature pattern)', () => {
      const result = sanitizeHeaders({ 'x-webhook-signature': 'sha256=abc' })
      expect(result).not.toHaveProperty('x-webhook-signature')
    })

    // Verifies that 'x-hub-signature' is removed by the wildcard *-signature pattern.
    it('should remove "x-hub-signature" (matches *-signature pattern)', () => {
      const result = sanitizeHeaders({ 'x-hub-signature': 'sha1=abc' })
      expect(result).not.toHaveProperty('x-hub-signature')
    })
  })

  // ---------------------------------------------------------------------------
  // Safe headers — must pass through
  // ---------------------------------------------------------------------------

  describe('safe headers passthrough', () => {
    // Verifies that 'x-request-id' is not sensitive and passes through the sanitizer unchanged.
    it('should pass through "x-request-id"', () => {
      const result = sanitizeHeaders({ 'x-request-id': 'req-123' })
      expect(result).toHaveProperty('x-request-id', 'req-123')
    })

    // Verifies that 'content-type' is not sensitive and passes through (with key lowercased).
    it('should pass through "content-type"', () => {
      const result = sanitizeHeaders({ 'Content-Type': 'application/json' })
      expect(result).toHaveProperty('content-type', 'application/json')
    })

    // Verifies that 'accept' passes through the sanitizer unchanged.
    it('should pass through "accept"', () => {
      const result = sanitizeHeaders({ Accept: 'application/json' })
      expect(result).toHaveProperty('accept', 'application/json')
    })

    // Verifies that 'user-agent' passes through the sanitizer unchanged.
    it('should pass through "user-agent"', () => {
      const result = sanitizeHeaders({ 'User-Agent': 'Chrome/120' })
      expect(result).toHaveProperty('user-agent', 'Chrome/120')
    })

    // Verifies that array-valued safe headers are preserved as-is in the output.
    it('should pass through array-valued safe headers', () => {
      const result = sanitizeHeaders({ 'x-forwarded-for': ['1.2.3.4', '5.6.7.8'] })
      expect(result).toHaveProperty('x-forwarded-for', ['1.2.3.4', '5.6.7.8'])
    })
  })

  // ---------------------------------------------------------------------------
  // Key normalization
  // ---------------------------------------------------------------------------

  describe('key normalization', () => {
    // Verifies that all output keys are lowercased regardless of the input casing.
    it('should lowercase all output keys', () => {
      const result = sanitizeHeaders({ 'Content-Type': 'text/plain', 'X-Request-Id': 'abc' })
      expect(Object.keys(result)).toEqual(expect.arrayContaining(['content-type', 'x-request-id']))
      expect(Object.keys(result)).not.toContain('Content-Type')
    })

    // Verifies that lowercasing prevents a blocklist bypass via mixed-case 'Authorization'.
    it('should prevent blocklist bypass via mixed-case (Authorization)', () => {
      const result = sanitizeHeaders({ Authorization: 'Bearer token' })
      expect(result).not.toHaveProperty('authorization')
      expect(result).not.toHaveProperty('Authorization')
    })
  })

  // ---------------------------------------------------------------------------
  // Edge cases
  // ---------------------------------------------------------------------------

  describe('edge cases', () => {
    // Verifies that sanitizeHeaders returns an empty object when given an empty input object.
    it('should return an empty object for empty input', () => {
      expect(sanitizeHeaders({})).toEqual({})
    })

    // Verifies that the original headers object is not mutated by the sanitizer.
    it('should not mutate the original headers object', () => {
      const original = { authorization: 'Bearer tok', 'x-request-id': 'abc' }
      sanitizeHeaders(original)
      expect(original).toHaveProperty('authorization')
    })

    // Verifies that undefined-valued headers are kept without crashing (value preserved as undefined).
    it('should handle undefined-valued headers without crashing', () => {
      const result = sanitizeHeaders({ 'x-custom': undefined })
      expect(result).toHaveProperty('x-custom', undefined)
    })

    // Verifies that sensitive headers are removed while safe ones remain in a mixed-input scenario.
    it('should remove sensitive headers and keep safe ones in mixed input', () => {
      const result = sanitizeHeaders({
        Authorization: 'Bearer secret',
        'Content-Type': 'application/json',
        'x-request-id': 'abc-123'
      })
      expect(result).not.toHaveProperty('authorization')
      expect(result).toHaveProperty('content-type', 'application/json')
      expect(result).toHaveProperty('x-request-id', 'abc-123')
    })
  })
})
