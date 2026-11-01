/**
 * handshakeRequest — unit tests
 *
 * The shim is what a `tenantIdResolver` sees on a WebSocket upgrade, so the cases pin both what it
 * provides and what it deliberately does not.
 */

import { Test } from '@nestjs/testing'
import express from 'express'

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

  // -------------------------------------------------------------------------
  // The trusted-proxy hostname
  // -------------------------------------------------------------------------

  describe('with a trusted-proxy predicate', () => {
    const PEER = '10.0.0.1'
    const trusting = (): jest.Mock<boolean, [string]> => jest.fn((peer: string) => peer === PEER)

    /** A handshake as a Host-rewriting proxy forwards it: the upstream Host, the public one beside it. */
    const behindProxy = (extra: Record<string, string | string[] | undefined> = {}) => ({
      headers: { host: 'upstream.internal', 'x-forwarded-host': 'a.example.com', ...extra },
      remoteAddress: PEER
    })

    // Scenario: the immediate peer is trusted and sent one X-Forwarded-Host. Expected: that value is
    // the hostname. Why: it is what Express's req.hostname returns for the same request, so the
    // resolver answers the same on HTTP and on the stream.
    it('takes X-Forwarded-Host when the peer is trusted', () => {
      expect(handshakeRequest(behindProxy(), trusting()).hostname).toBe('a.example.com')
    })

    // Scenario: the predicate is handed the peer exactly as the transport reported it. Why: the host
    // owns the policy, and normalising the address here would second-guess it.
    it('hands the predicate the raw peer string', () => {
      const predicate = trusting()

      handshakeRequest({ ...behindProxy(), remoteAddress: '::ffff:10.0.0.1' }, predicate)

      expect(predicate).toHaveBeenCalledTimes(1)
      expect(predicate).toHaveBeenCalledWith('::ffff:10.0.0.1')
    })

    // Scenario: an untrusted peer sends the same header. Expected: the Host header, as without the
    // option. Why: this is the only security property — a client must not choose its own host.
    it('ignores X-Forwarded-Host from a peer the predicate does not trust', () => {
      const req = handshakeRequest({ ...behindProxy(), remoteAddress: '203.0.113.9' }, trusting())

      expect(req.hostname).toBe('upstream.internal')
    })

    // Scenario: no predicate configured. Expected: the Host header whatever the peer and header say.
    it('never reads X-Forwarded-Host without a predicate', () => {
      expect(handshakeRequest(behindProxy()).hostname).toBe('upstream.internal')
    })

    // Scenario: the transport reported no peer, or an empty one. Expected: untrusted, so the Host
    // header, and the predicate is not asked about a peer that does not exist.
    it.each([undefined, '', '   '])('treats the peer %p as untrusted', (remoteAddress) => {
      const predicate = trusting()
      const { remoteAddress: _peer, ...withoutPeer } = behindProxy()
      const handshake =
        remoteAddress === undefined ? withoutPeer : { ...withoutPeer, remoteAddress }

      const req = handshakeRequest(handshake, predicate)

      expect(req.hostname).toBe('upstream.internal')
      expect(predicate).not.toHaveBeenCalled()
    })

    // Scenario: only the exact boolean `true` trusts a peer. Why: a predicate returning a truthy
    // string or a number is a bug in the host's code, and trust is not the safe way to read it.
    it.each(['yes', 1, {}, undefined])('does not trust a predicate answer of %p', (answer) => {
      const predicate = jest.fn(() => answer as never)

      expect(handshakeRequest(behindProxy(), predicate).hostname).toBe('upstream.internal')
    })

    // Scenario: the predicate throws. Expected: untrusted, so the Host header. Why: a refusal of the
    // binding downstream is the stricter outcome; an exception escaping the guard is not.
    it('treats a throwing predicate as untrusted', () => {
      const predicate = jest.fn(() => {
        throw new Error('bad policy')
      })

      expect(handshakeRequest(behindProxy(), predicate).hostname).toBe('upstream.internal')
    })

    // Scenario: the shapes of X-Forwarded-Host that do not name one host. Expected: the Host header.
    it.each([
      ['a repeated header', ['a.example.com', 'b.example.com']],
      ['an empty value', ''],
      ['a blank value', '   '],
      ['an empty first element', ', a.example.com'],
      ['a blank first element', '  , a.example.com']
    ])('falls back to Host for %s', (_why, value) => {
      expect(
        handshakeRequest(behindProxy({ 'x-forwarded-host': value }), trusting()).hostname
      ).toBe('upstream.internal')
    })

    // Scenario: a list, as Express reads it. Expected: the first element, trimmed.
    it('takes the first element of a comma list, trimmed', () => {
      const req = handshakeRequest(
        behindProxy({ 'x-forwarded-host': '  a.example.com , b.example.com' }),
        trusting()
      )

      expect(req.hostname).toBe('a.example.com')
    })

    // Scenario: the forwarded value carries a port or is a bracketed IPv6 literal. Expected: the same
    // treatment as Host — port cut, brackets kept. Why: Express runs both through one rule.
    it.each([
      ['a.example.com:8443', 'a.example.com'],
      ['[::1]:8443', '[::1]'],
      ['[::1]', '[::1]']
    ])('cuts the port from the forwarded value %p', (forwarded, expected) => {
      const req = handshakeRequest(behindProxy({ 'x-forwarded-host': forwarded }), trusting())

      expect(req.hostname).toBe(expected)
    })

    // Scenario: the header name arrives in mixed case. Expected: still read.
    it('reads the forwarded header whatever its case', () => {
      const req = handshakeRequest(
        {
          headers: { Host: 'upstream.internal', 'X-Forwarded-Host': 'a.example.com' },
          remoteAddress: PEER
        },
        trusting()
      )

      expect(req.hostname).toBe('a.example.com')
    })

    // Scenario: the untrusted fallback with no Host either. Expected: '' as without the option.
    it('gives an empty hostname when the peer is untrusted and Host is absent', () => {
      const req = handshakeRequest(
        { headers: { 'x-forwarded-host': 'a.example.com' }, remoteAddress: '203.0.113.9' },
        trusting()
      )

      expect(req.hostname).toBe('')
    })

    // Scenario: an IPv4-mapped IPv6 peer, which is what a dual-stack listener reports for an IPv4
    // client, judged by Express's own compiled `trust proxy` function. Expected: trusted when the
    // mapped address falls in the trusted range. Why: the predicate gets the raw string, so the
    // host's policy has to understand the mapped form, and this shows the recipe that does.
    it('works with Express trust proxy function for an IPv4-mapped peer', () => {
      const app = express()
      app.set('trust proxy', 'loopback, 10.0.0.0/8')
      const trust = app.get('trust proxy fn') as (address: string, hop: number) => boolean
      const isTrustedProxy = (peer: string): boolean => trust(peer, 0)

      const mapped = handshakeRequest(
        { ...behindProxy(), remoteAddress: '::ffff:10.1.2.3' },
        isTrustedProxy
      )
      const loopback = handshakeRequest(
        { ...behindProxy(), remoteAddress: '::ffff:127.0.0.1' },
        isTrustedProxy
      )
      const outside = handshakeRequest(
        { ...behindProxy(), remoteAddress: '::ffff:203.0.113.9' },
        isTrustedProxy
      )

      expect(mapped.hostname).toBe('a.example.com')
      expect(loopback.hostname).toBe('a.example.com')
      expect(outside.hostname).toBe('upstream.internal')
    })

    // Scenario: the policy as the README wires it for a Nest application, read from the Express
    // instance behind the adapter. Expected: it answers for mapped and plain loopback peers.
    // Why: this is the recipe a host copies, so it is run against a real Nest application and not
    // a bare Express one.
    it('works with the Express instance of a Nest application', async () => {
      const moduleRef = await Test.createTestingModule({}).compile()
      const app = moduleRef.createNestApplication()
      const expressApp = app.getHttpAdapter().getInstance() as express.Express
      expressApp.set('trust proxy', 'loopback')
      const isTrustedProxy = (peer: string): boolean =>
        (expressApp.get('trust proxy fn') as (address: string, hop: number) => boolean)(peer, 0)

      expect(
        handshakeRequest({ ...behindProxy(), remoteAddress: '::ffff:127.0.0.1' }, isTrustedProxy)
          .hostname
      ).toBe('a.example.com')
      expect(
        handshakeRequest({ ...behindProxy(), remoteAddress: '203.0.113.9' }, isTrustedProxy)
          .hostname
      ).toBe('upstream.internal')
      await app.close()
    })

    // Scenario: the same lookup through `app.get()` on the Nest application. Expected: it throws.
    // Why: on a Nest application `get()` resolves a provider from the container and does not read an
    // Express setting, which is why the recipe reads the Express instance instead.
    it('does not find the policy through app.get() on a Nest application', async () => {
      const moduleRef = await Test.createTestingModule({}).compile()
      const app = moduleRef.createNestApplication()
      app.getHttpAdapter().getInstance().set('trust proxy', 'loopback')

      expect(() => app.get('trust proxy fn')).toThrow()
      await app.close()
    })
  })
})
