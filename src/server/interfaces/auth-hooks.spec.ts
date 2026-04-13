import { sanitizeHeaders } from '../utils/sanitize-headers'

describe('sanitizeHeaders', () => {
  // Verifies that the 'authorization' header is removed to prevent bearer token leakage in hook context.
  it('should remove authorization header', () => {
    const result = sanitizeHeaders({ authorization: 'Bearer secret-token' })
    expect(result).not.toHaveProperty('authorization')
  })

  // Verifies that the 'cookie' header is removed to prevent session cookie leakage.
  it('should remove cookie header', () => {
    const result = sanitizeHeaders({ cookie: 'session=abc123; other=value' })
    expect(result).not.toHaveProperty('cookie')
  })

  // Verifies that the 'x-api-key' header is removed from the sanitized output.
  it('should remove x-api-key header', () => {
    const result = sanitizeHeaders({ 'x-api-key': 'my-api-key' })
    expect(result).not.toHaveProperty('x-api-key')
  })

  // Verifies that the 'x-auth-token' header is removed from the sanitized output.
  it('should remove x-auth-token header', () => {
    const result = sanitizeHeaders({ 'x-auth-token': 'some-auth-token' })
    expect(result).not.toHaveProperty('x-auth-token')
  })

  // Verifies that the 'x-csrf-token' header is removed to prevent CSRF token leakage.
  it('should remove x-csrf-token header', () => {
    const result = sanitizeHeaders({ 'x-csrf-token': 'csrf-value' })
    expect(result).not.toHaveProperty('x-csrf-token')
  })

  // Verifies that the 'x-session-id' header is removed to prevent session ID leakage.
  it('should remove x-session-id header', () => {
    const result = sanitizeHeaders({ 'x-session-id': 'session-identifier' })
    expect(result).not.toHaveProperty('x-session-id')
  })

  // Verifies that the 'proxy-authorization' header is removed from the sanitized output.
  it('should remove proxy-authorization header', () => {
    const result = sanitizeHeaders({ 'proxy-authorization': 'Basic dXNlcjpwYXNz' })
    expect(result).not.toHaveProperty('proxy-authorization')
  })

  // Verifies that the 'www-authenticate' header is removed from the sanitized output.
  it('should remove www-authenticate header', () => {
    const result = sanitizeHeaders({ 'www-authenticate': 'Bearer realm="api"' })
    expect(result).not.toHaveProperty('www-authenticate')
  })

  // Verifies that custom x-*-token headers are removed by the wildcard pattern.
  it('should remove custom x-*-token headers (pattern match)', () => {
    const result = sanitizeHeaders({
      'x-refresh-token': 'refresh-value',
      'x-access-token': 'access-value',
      'x-custom-token': 'custom-value'
    })
    expect(result).not.toHaveProperty('x-refresh-token')
    expect(result).not.toHaveProperty('x-access-token')
    expect(result).not.toHaveProperty('x-custom-token')
  })

  // Verifies that custom x-*-secret headers are removed by the extended wildcard pattern.
  it('should remove custom x-*-secret headers (extended pattern)', () => {
    const result = sanitizeHeaders({
      'x-client-secret': 'secret-value',
      'x-service-secret': 'another-secret'
    })
    expect(result).not.toHaveProperty('x-client-secret')
    expect(result).not.toHaveProperty('x-service-secret')
  })

  // Verifies that custom x-*-key headers are removed by the extended wildcard pattern.
  it('should remove custom x-*-key headers (extended pattern)', () => {
    const result = sanitizeHeaders({
      'x-service-key': 'key-value',
      'x-api-private-key': 'private-key'
    })
    expect(result).not.toHaveProperty('x-service-key')
    expect(result).not.toHaveProperty('x-api-private-key')
  })

  // Verifies that custom x-*-password headers are removed by the extended wildcard pattern.
  it('should remove custom x-*-password headers (extended pattern)', () => {
    const result = sanitizeHeaders({ 'x-api-password': 'pass123' })
    expect(result).not.toHaveProperty('x-api-password')
  })

  // Verifies that custom x-*-credential headers are removed by the extended wildcard pattern.
  it('should remove custom x-*-credential headers (extended pattern)', () => {
    const result = sanitizeHeaders({ 'x-service-credential': 'cred-value' })
    expect(result).not.toHaveProperty('x-service-credential')
  })

  // Verifies that non-sensitive headers such as accept and content-type pass through unchanged.
  it('should keep non-sensitive headers', () => {
    const input = {
      accept: 'application/json',
      'content-type': 'application/json',
      'x-request-id': 'abc-123'
    }
    const result = sanitizeHeaders(input)
    expect(result).toEqual(input)
  })

  // Verifies that case-insensitive matching correctly removes headers regardless of input casing.
  it('should handle case-insensitive header keys', () => {
    const result = sanitizeHeaders({
      Authorization: 'Bearer secret',
      COOKIE: 'session=abc123',
      'X-API-KEY': 'my-api-key'
    })
    expect(result).not.toHaveProperty('Authorization')
    expect(result).not.toHaveProperty('COOKIE')
    expect(result).not.toHaveProperty('X-API-KEY')
  })

  // Verifies that all output keys are lowercased even when the input uses mixed case.
  it('should normalize non-sensitive header keys to lowercase in the output', () => {
    const result = sanitizeHeaders({
      'Content-Type': 'application/json',
      'X-Request-ID': 'abc-123'
    })
    expect(result).not.toHaveProperty('Content-Type')
    expect(result).not.toHaveProperty('X-Request-ID')
    expect(result).toHaveProperty('content-type', 'application/json')
    expect(result).toHaveProperty('x-request-id', 'abc-123')
  })

  // Verifies that when all provided headers are sensitive, the result is an empty object.
  it('should return empty object when all headers are sensitive', () => {
    const result = sanitizeHeaders({
      authorization: 'Bearer token',
      cookie: 'session=abc',
      'x-api-key': 'key',
      'x-auth-token': 'auth',
      'x-csrf-token': 'csrf',
      'x-session-id': 'sid',
      'x-refresh-token': 'refresh',
      'proxy-authorization': 'Basic xyz',
      'www-authenticate': 'Bearer realm="api"'
    })
    expect(result).toEqual({})
  })

  // Verifies that sanitizeHeaders returns a new object and does not mutate the original headers object.
  it('should return a new object without mutating the original headers', () => {
    const input: Record<string, string | string[] | undefined> = {
      authorization: 'Bearer secret',
      'content-type': 'application/json'
    }
    const original = { ...input }
    const result = sanitizeHeaders(input)
    expect(input).toEqual(original)
    expect(result).not.toBe(input)
  })

  // Verifies that array-valued non-sensitive headers are preserved as-is in the output.
  it('should handle array header values for non-sensitive headers', () => {
    const result = sanitizeHeaders({
      'accept-language': ['en', 'pt-BR'],
      cookie: 'session=abc'
    })
    expect(result).toEqual({ 'accept-language': ['en', 'pt-BR'] })
  })

  // Verifies that undefined-valued non-sensitive headers are passed through without crashing.
  it('should handle undefined header values for non-sensitive headers', () => {
    const result = sanitizeHeaders({
      'x-forwarded-for': undefined,
      authorization: 'Bearer token'
    })
    expect(result).toEqual({ 'x-forwarded-for': undefined })
  })
})
