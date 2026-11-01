/**
 * @fileoverview Tests for resolveClientAddress, which turns the address channels of a request into
 * one validated client address.
 */

import { isIP } from 'node:net'

import express from 'express'
import type { Request } from 'express'
import request from 'supertest'

import { resolveClientAddress } from './client-address'

describe('resolveClientAddress', () => {
  describe('over hand-built requests', () => {
    // Scenario: req.ip is an address. Expected: it is returned unchanged, whatever its family.
    it.each(['203.0.113.4', '2001:db8::7', '::ffff:198.51.100.7', '::1'])(
      'returns the address %s unchanged',
      (ip) => {
        expect(resolveClientAddress({ ip, ips: [ip], socket: { remoteAddress: '10.0.0.1' } })).toBe(
          ip
        )
      }
    )

    // Scenario: req.ip is a string the caller wrote and the next hop toward the socket is an
    // address. Expected: that hop. Why: `req.ips` runs from the client end toward the socket, so
    // the entry after the first is the nearest trusted hop.
    it('resolves a non-address client entry to the nearest trusted hop', () => {
      expect(
        resolveClientAddress({
          ip: 'garbage',
          ips: ['garbage', '10.0.0.2', '10.0.0.3'],
          socket: { remoteAddress: '10.0.0.1' }
        })
      ).toBe('10.0.0.2')
    })

    // Scenario: a non-address client entry with no trusted hop recorded in `ips`. Expected: the
    // socket peer, which is the hop that delivered the request.
    it('falls back to the socket peer when no hop in ips is an address', () => {
      expect(
        resolveClientAddress({
          ip: 'not-an-ip',
          ips: ['not-an-ip'],
          socket: { remoteAddress: '10.0.0.1' }
        })
      ).toBe('10.0.0.1')
    })

    // Scenario: entries after the first are not addresses either. Expected: the walk continues to
    // the first that is, rather than stopping at the second candidate.
    it('keeps walking past further entries that are not addresses', () => {
      expect(
        resolveClientAddress({
          ip: 'junk',
          ips: ['junk', 'also-junk', '10.0.0.3'],
          socket: { remoteAddress: '10.0.0.1' }
        })
      ).toBe('10.0.0.3')
    })

    // Scenario: nothing is an address. Expected: an empty string, which callers read as "no
    // address" and which the limiter maps to its shared bucket.
    it.each([
      [{}],
      [{ ip: '', ips: [], socket: { remoteAddress: '' } }],
      [{ ip: 'junk', ips: ['junk'], socket: { remoteAddress: 'also junk' } }],
      [{ ip: undefined, ips: undefined, socket: undefined }],
      [{ ip: 'junk', ips: ['junk', 7 as unknown as string], socket: {} }]
    ])('returns an empty string when there is no address to be had: %j', (source) => {
      expect(resolveClientAddress(source)).toBe('')
    })

    // Scenario: an IPv6 address with a zone index. Expected: the bare address. Why: `isIP` accepts
    // the zone at any length, so without the cut a caller could make the value arbitrarily long;
    // and the zone is link-local scope, not identity.
    it.each([
      ['fe80::1%eth0', 'fe80::1'],
      [`fe80::1%${'z'.repeat(5000)}`, 'fe80::1']
    ])('cuts the zone index from %s', (ip, expected) => {
      const resolved = resolveClientAddress({ ip, ips: [ip], socket: {} })

      expect(resolved).toBe(expected)
      expect(resolved.length).toBeLessThanOrEqual(45)
    })

    // Scenario: a zone on the socket peer. Expected: the same cut.
    it('cuts the zone index from the socket peer', () => {
      expect(
        resolveClientAddress({
          ip: 'junk',
          ips: ['junk'],
          socket: { remoteAddress: 'fe80::2%en0' }
        })
      ).toBe('fe80::2')
    })

    // Scenario: a `%` suffix on something that is not IPv6. Expected: it is not an address. Why:
    // only an IPv6 literal carries a zone, and stripping it from anything else would turn
    // caller-written text into an address.
    it('does not accept a zone suffix on an IPv4 literal', () => {
      expect(resolveClientAddress({ ip: '1.2.3.4%eth0', ips: [], socket: {} })).toBe('')
    })

    // Scenario: an ordinary request on a host that never set `trust proxy`. Expected: Express
    // leaves `ips` empty and `ip` is the socket address, which is what is returned.
    it('returns the socket address when trust proxy is unset', () => {
      expect(
        resolveClientAddress({ ip: '10.0.0.9', ips: [], socket: { remoteAddress: '10.0.0.9' } })
      ).toBe('10.0.0.9')
    })
  })

  // The fixtures above describe what Express produces; this block checks that they do. Each case
  // is the framework's own `req.ip` and `req.ips` behind a trust predicate, so a change in how
  // Express fills them in fails here and not in production.
  describe('over a real Express request', () => {
    const trusted = (address: string): boolean =>
      address === '127.0.0.1' ||
      address === '::1' ||
      address === '::ffff:127.0.0.1' ||
      address.startsWith('10.')

    interface Seen {
      readonly resolved: string
      readonly ip: string | undefined
      readonly ips: readonly string[]
      readonly peer: string | undefined
    }

    async function resolveBehindProxy(forwardedFor: string | undefined): Promise<Seen> {
      const app = express()
      app.set('trust proxy', trusted)
      app.get('/', (req: Request, res) => {
        res.json({
          resolved: resolveClientAddress(req),
          ip: req.ip,
          ips: req.ips,
          peer: req.socket.remoteAddress
        })
      })
      const call = request(app).get('/')
      const response = await (forwardedFor === undefined
        ? call
        : call.set('X-Forwarded-For', forwardedFor))
      return response.body as Seen
    }

    // Mirrors rust-auth's `an_entry_that_is_not_an_address_ends_the_walk_at_the_last_hop_that_was_one`
    // (crates/bymax-auth-axum/src/client_ip/tests.rs), which asserts that behind a trusted peer
    // `198.51.100.7, garbage, 10.0.0.2` resolves to 10.0.0.2. The first request here is that
    // input; Express reports the entry the trust setting stopped at as `req.ip`.
    it('resolves a non-address client entry to the hop nearest the client', async () => {
      const seen = await resolveBehindProxy('198.51.100.7, garbage, 10.0.0.2')

      expect(seen.ip).toBe('garbage')
      expect(seen.ips).toEqual(['garbage', '10.0.0.2'])
      expect(seen.resolved).toBe('10.0.0.2')
    })

    // The second assertion of the same rust test: a header with no address in it resolves to the
    // peer itself.
    it('resolves a header with no address in it to the peer', async () => {
      const seen = await resolveBehindProxy('not-an-ip')

      expect(seen.ip).toBe('not-an-ip')
      expect(seen.resolved).toBe(seen.peer)
      expect(isIP(seen.resolved)).not.toBe(0)
    })

    // With several trusted hops, the hop nearest the client is the one after the client entry,
    // not the one nearest the socket.
    it('picks the hop nearest the client among several trusted hops', async () => {
      const seen = await resolveBehindProxy('garbage, 10.0.0.7, 10.0.0.8')

      expect(seen.ips).toEqual(['garbage', '10.0.0.7', '10.0.0.8'])
      expect(seen.resolved).toBe('10.0.0.7')
    })

    // A well-formed chain is unaffected: the client is the first entry the trust setting stops
    // at, exactly as Express reports it.
    it('returns the client Express reports for a well-formed chain', async () => {
      const seen = await resolveBehindProxy('198.51.100.7, 10.0.0.2')

      expect(seen.ip).toBe('198.51.100.7')
      expect(seen.resolved).toBe('198.51.100.7')
    })

    // Without a forwarded header the peer is the client.
    it('returns the peer when there is no forwarded header', async () => {
      const seen = await resolveBehindProxy(undefined)

      expect(seen.resolved).toBe(seen.peer)
      expect(isIP(seen.resolved)).not.toBe(0)
    })
  })
})
