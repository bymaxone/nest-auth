/**
 * handshakeRequest — unit tests
 *
 * The shim is what a `tenantIdResolver` sees on a WebSocket upgrade, so the cases pin both what it
 * provides and what it deliberately does not.
 */

import type { TenantResolverRequest } from '../interfaces/auth-module-options.interface'
import { handshakeRequest } from './handshake-request'

describe('handshakeRequest', () => {
  // Scenario: header names arrive in mixed case. Expected: lowercased, values untouched. Why: a
  // resolver written against Express reads `req.headers['x-tenant-id']`, and Node lowercases there.
  it('should lowercase header names and keep their values', () => {
    const req = handshakeRequest({ headers: { 'X-Tenant-Id': 'Tenant-A', Host: 'a.example.com' } })

    expect(req.headers).toStrictEqual({ 'x-tenant-id': 'Tenant-A', host: 'a.example.com' })
  })

  // Scenario: the transport exposes a URL, or none. Expected: the URL, else the empty string.
  it.each([
    ['/socket.io/?EIO=4', '/socket.io/?EIO=4'],
    [undefined, '']
  ])('should expose url %p as %p', (url, expected) => {
    expect(handshakeRequest({ headers: {}, ...(url === undefined ? {} : { url }) }).url).toBe(
      expected
    )
  })

  // Scenario: every Host shape Express's `req.hostname` distinguishes. Expected: the same answer.
  // Why: a resolver that splits on the subdomain must see what it sees over HTTP.
  it.each([
    ['a.example.com', 'a.example.com'],
    ['a.example.com:3000', 'a.example.com'],
    ['[::1]', '[::1]'],
    ['[::1]:3000', '[::1]'],
    // A literal whose closing bracket sits right after its colons: the scan for the port must
    // start after the bracket, not inside the address.
    ['[::]', '[::]'],
    ['[::]:80', '[::]'],
    // A colon before a stray `]` in a host that is not bracketed: only a leading `[` moves the scan.
    ['a:b]:c', 'a'],
    ['', '']
  ])('should derive hostname from Host %p as %p', (host, expected) => {
    expect(handshakeRequest({ headers: { host } }).hostname).toBe(expected)
  })

  // Scenario: no usable Host (absent, or repeated). Expected: the empty string, never a guess.
  // Why: a resolver deriving a tenant from it then resolves nothing and the upgrade is refused.
  it.each([
    ['absent', {}],
    ['repeated', { host: ['a.example.com', 'b.example.com'] }]
  ])('should give an empty hostname when Host is %s', (_why, headers) => {
    expect(handshakeRequest({ headers }).hostname).toBe('')
  })

  // The result is a `TenantResolverRequest` with no cast, so a resolver written against that type
  // alone is accepted by the compiler here — the contract a consumer's resolver is held to.
  it('should satisfy a resolver typed against TenantResolverRequest only', () => {
    const resolver: (req: TenantResolverRequest) => string = (req) => String(req.headers['x-t'])

    expect(resolver(handshakeRequest({ headers: { 'X-T': 'a' } }))).toBe('a')
  })

  // Scenario: a forwarded host is present. Expected: ignored — trust-proxy semantics are absent.
  it('should not honour X-Forwarded-Host', () => {
    const req = handshakeRequest({
      headers: { host: 'edge.internal', 'x-forwarded-host': 'a.example.com' }
    })

    expect(req.hostname).toBe('edge.internal')
  })

  // Scenario: the fields the shim documents as absent. Expected: really absent, so a resolver that
  // reads them gets `undefined` and is refused rather than silently mis-bound.
  it.each(['cookies', 'ip', 'ips', 'protocol', 'subdomains'])('should not provide %s', (field) => {
    expect(field in handshakeRequest({ headers: { host: 'a.example.com' } })).toBe(false)
  })
})
