/**
 * @fileoverview Tests for `rateLimitBucket`, which decides what a rate limit is charged
 * against. The security property is that one IPv6 allocation is one budget; the trap it has to
 * avoid is merging every IPv4 client into a single one.
 */

import { rateLimitBucket } from './rate-limit-bucket'

describe('rateLimitBucket', () => {
  // Scenario: two addresses inside one IPv6 /64. Expected: one bucket. Why: a /64 is the
  // smallest subnet a customer is allocated, and every one of its 2^64 addresses is free to mint
  // and rotate. Keying the full address made the per-route counter per-address, so "5 attempts
  // per minute" became 5 per address per minute — no limit at all against anyone holding a
  // routine allocation.
  it('charges two addresses in one IPv6 /64 to the same bucket', () => {
    expect(rateLimitBucket('2001:db8:1:2::1')).toBe(
      rateLimitBucket('2001:db8:1:2:ffff:ffff:ffff:ffff')
    )
  })

  // The converse, so "collapse everything" cannot pass: only the last four groups are discarded.
  it('keeps a different /64 in a different bucket', () => {
    expect(rateLimitBucket('2001:db8:1:2::1')).not.toBe(rateLimitBucket('2001:db8:1:3::1'))
  })

  // Scenario: the exact string the counter is keyed on. Expected: the four prefix groups,
  // then four zeroed ones. Why: every other test here compares one bucket against another, and
  // that shape is satisfied by any consistent mangling — dropping the zero padding, joining on
  // the wrong separator, or keeping the wrong number of groups all leave the two sides equal.
  // Pinning the value once is what makes those failures visible.
  it('produces the /64 prefix followed by four zeroed groups', () => {
    expect(rateLimitBucket('2001:db8:1:2:aaaa:bbbb:cccc:dddd')).toBe('2001:db8:1:2:0:0:0:0')
  })

  // An address with no groups to keep still yields eight groups, not an empty string — which is
  // what a bucket of "" would silently merge every such caller into.
  it('produces a full-width bucket even when the prefix is all zeroes', () => {
    expect(rateLimitBucket('::1')).toBe('0:0:0:0:0:0:0:0')
  })

  // IPv4 is one address per host, so it is charged whole and neighbours never share.
  it('leaves IPv4 addresses untouched and unmerged', () => {
    expect(rateLimitBucket('203.0.113.7')).toBe('203.0.113.7')
    expect(rateLimitBucket('203.0.113.7')).not.toBe(rateLimitBucket('203.0.113.8'))
  })

  // Scenario: the form a dual-stack Node listener reports for every IPv4 peer. Expected: it
  // unwraps to the IPv4 address. Why: this is the trap. Truncating `::ffff:a.b.c.d` to /64
  // yields `::` for EVERY IPv4 client, so the whole IPv4 internet would share one counter and
  // the anti-abuse control would itself become the denial of service — and on Node this is the
  // ordinary shape of `socket.remoteAddress`, not an edge case.
  it('unwraps IPv4-mapped addresses instead of collapsing them to one bucket', () => {
    expect(rateLimitBucket('::ffff:203.0.113.7')).toBe('203.0.113.7')
    expect(rateLimitBucket('::ffff:203.0.113.7')).not.toBe(rateLimitBucket('::ffff:198.51.100.9'))
    expect(rateLimitBucket('::ffff:203.0.113.7')).not.toBe(rateLimitBucket('::'))
  })

  // The same host reaching us mapped and unmapped is one host, so one budget — otherwise it
  // would get two.
  it('gives an IPv4 host one bucket whether it arrives mapped or not', () => {
    expect(rateLimitBucket('::ffff:203.0.113.7')).toBe(rateLimitBucket('203.0.113.7'))
  })

  // The hex form of a mapped address means the same thing as the dotted one and must not open a
  // second budget.
  it('recognises the hexadecimal spelling of a mapped address', () => {
    expect(rateLimitBucket('::ffff:cb00:7107')).toBe(rateLimitBucket('203.0.113.7'))
  })

  // A zone index is link-local scope, not identity: two interfaces onto the same link must not
  // each get their own budget.
  it('ignores a zone index', () => {
    expect(rateLimitBucket('fe80::1%eth0')).toBe(rateLimitBucket('fe80::2%eth1'))
  })

  // Scenario: a zone index on a mapped address. Expected: the plain IPv4 address. Why: this is
  // where dropping the zone stops being cosmetic. `isIPv6` accepts `%eth0`, and on the /64 path
  // the zone lands in a group that gets zeroed anyway — but here it is glued to the final octet
  // (`7%eth0`), which parses as NaN and corrupts the whole address into some other host's
  // bucket.
  it('strips a zone index before reading a mapped IPv4 address', () => {
    expect(rateLimitBucket('::ffff:203.0.113.7%eth0')).toBe('203.0.113.7')
  })

  // Scenario: a mapped address written with an explicit leading group (`0::ffff:…`) rather than
  // a bare `::`. Expected: still the plain IPv4 address. Why: the compressed run has to be
  // filled with exactly the groups that are missing. Padding by any other amount shifts `ffff`
  // out of group 5, the mapped test stops matching, and the address is charged to an IPv6 /64
  // of all zeroes — one bucket shared with everybody else who lands there.
  it('fills a compressed run by exactly the missing groups', () => {
    expect(rateLimitBucket('0::ffff:203.0.113.7')).toBe('203.0.113.7')
  })

  // Scenario: `ffff` sitting in group 5 of an address that is NOT mapped, because its prefix is
  // non-zero. Expected: treated as ordinary IPv6. Why: the mapped range is `::ffff:0:0/96` —
  // ALL five leading groups zero AND group 5 `ffff`. Testing either half alone misreads this
  // address as mapped and answers `0.0.0.0`, which is one bucket for everyone who lands there.
  it('does not mistake a non-zero prefix carrying ffff for a mapped address', () => {
    expect(rateLimitBucket('2001:db8::ffff:0:0')).toBe('2001:db8:0:0:0:0:0:0')
  })

  // Compressed and fully written forms of one address are one address.
  it('treats compressed and expanded spellings of an address alike', () => {
    expect(rateLimitBucket('2001:db8:0:0:0:0:0:1')).toBe(rateLimitBucket('2001:db8::1'))
  })

  // Scenario: values that are not addresses at all — the guard's own "address unavailable"
  // sentinel, and junk. Expected: returned untouched. Why: those callers already share a single
  // bucket by design, and inventing a bucket for an unparseable value risks merging distinct
  // callers into one.
  it.each([['unknown'], [''], ['not-an-address'], ['2001:db8::1::2']])(
    'returns %p unchanged',
    (value) => {
      expect(rateLimitBucket(value)).toBe(value)
    }
  )
})
