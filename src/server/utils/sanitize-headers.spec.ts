import { createEmptyHookContext, sanitizeHeaders } from './sanitize-headers'

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

    // Verifies that 'x-forwarded-for' is stripped — the framework's trusted-proxy
    // resolver populates HookContext.ip; raw forwarding headers are spoofable and
    // must not reach hooks or audit logs as authoritative IP information.
    it('should remove "x-forwarded-for" header (spoofable forwarding)', () => {
      const result = sanitizeHeaders({ 'x-forwarded-for': '203.0.113.1, 198.51.100.2' })
      expect(result).not.toHaveProperty('x-forwarded-for')
    })

    // Verifies that 'x-forwarded-host' is stripped to prevent host-header injection
    // pretending to be authoritative routing metadata in audit logs.
    it('should remove "x-forwarded-host" header', () => {
      const result = sanitizeHeaders({ 'x-forwarded-host': 'attacker.example.com' })
      expect(result).not.toHaveProperty('x-forwarded-host')
    })

    // Verifies that 'x-real-ip' is stripped — same rationale as x-forwarded-for.
    it('should remove "x-real-ip" header', () => {
      const result = sanitizeHeaders({ 'x-real-ip': '203.0.113.1' })
      expect(result).not.toHaveProperty('x-real-ip')
    })

    // Verifies that 'x-original-forwarded-for' (envoy-style nested forward chain)
    // is stripped to prevent attackers from injecting fake upstream IP chains.
    it('should remove "x-original-forwarded-for" header', () => {
      const result = sanitizeHeaders({ 'x-original-forwarded-for': '203.0.113.1' })
      expect(result).not.toHaveProperty('x-original-forwarded-for')
    })

    // Verifies that 'cf-connecting-ip' (Cloudflare) is stripped — when running
    // behind a Cloudflare proxy, the trusted-proxy resolver should already inject
    // the real IP into req.ip; the raw header must not be re-trusted by hooks.
    it('should remove "cf-connecting-ip" header', () => {
      const result = sanitizeHeaders({ 'cf-connecting-ip': '203.0.113.1' })
      expect(result).not.toHaveProperty('cf-connecting-ip')
    })

    // Verifies that 'true-client-ip' (Akamai/Cloudflare Enterprise) is stripped.
    it('should remove "true-client-ip" header', () => {
      const result = sanitizeHeaders({ 'true-client-ip': '203.0.113.1' })
      expect(result).not.toHaveProperty('true-client-ip')
    })

    // Verifies that 'x-cluster-client-ip' (legacy/cluster-aware proxies) is stripped.
    it('should remove "x-cluster-client-ip" header', () => {
      const result = sanitizeHeaders({ 'x-cluster-client-ip': '203.0.113.1' })
      expect(result).not.toHaveProperty('x-cluster-client-ip')
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
      const result = sanitizeHeaders({ accept: ['application/json', 'text/plain'] })
      expect(result).toHaveProperty('accept', ['application/json', 'text/plain'])
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

describe('createEmptyHookContext', () => {
  // Verifies the factory returns all three required HookContext fields populated with
  // empty defaults — never undefined — so hook implementations reading context.ip or
  // context.userAgent never receive a surprise undefined at runtime.
  it('should return a context with ip/userAgent/sanitizedHeaders as empty values', () => {
    const ctx = createEmptyHookContext()
    expect(ctx).toEqual({ ip: '', userAgent: '', sanitizedHeaders: {} })
    expect(typeof ctx.ip).toBe('string')
    expect(typeof ctx.userAgent).toBe('string')
    expect(ctx.sanitizedHeaders).toEqual({})
  })

  // Verifies that each invocation returns a fresh object so callers cannot accidentally
  // pollute a shared reference by mutating their copy.
  it('should return a fresh object on each call (no shared reference)', () => {
    const a = createEmptyHookContext()
    const b = createEmptyHookContext()
    expect(a).not.toBe(b)
    expect(a.sanitizedHeaders).not.toBe(b.sanitizedHeaders)
  })
})
