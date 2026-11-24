/**
 * @fileoverview The address checks of the rate limit and of the client address use the `net.isIP` and `net.isIPv6` taken when the
 * module loaded, so replacing either afterwards cannot split one network into many buckets or let a made-up address key a counter.
 *
 * @layer Test
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { resolveClientAddress } from './client-address'
import { rateLimitBucket } from './rate-limit-bucket'

// The test's own copies: the windows below replace functions of `node:net`, so nothing inside one may call a live one.
const net = jest.requireActual<Record<string, unknown>>('node:net')
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

/** Runs `run` with `name` of `node:net` replaced by `stub`, and puts it back. */
function withReplaced<T>(name: 'isIP' | 'isIPv6', stub: unknown, run: () => T): T {
  const held = getOwn(net, name) as PropertyDescriptor
  define(net, name, { ...held, value: stub })
  try {
    return run()
  } finally {
    define(net, name, held)
  }
}

/** The files of `src/server` that are not specs, as `[path, text]`. */
function sources(dir = join(__dirname, '..')): [string, string][] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry): [string, string][] => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return entry.name === '__tests__' ? [] : sources(path)
    return /\.ts$/.test(entry.name) && !/\.(spec|test)\.ts$/.test(entry.name)
      ? [[path, readFileSync(path, 'utf8')]]
      : []
  })
}

describe('the address checks while node:net is replaced', () => {
  // Scenario: every source file, read as text. Expected: none but the module that captures the functions imports a value from
  // `node:net`. Why: one direct import is a call the replacement reaches.
  it('imports no value from node:net in any source file but the captured module', () => {
    const direct = sources()
      .filter(([path]) => !path.endsWith('captured-builtins.ts'))
      .filter(([, text]) => /import\s+(?!type\b)[^;]*?from\s*'node:net'/.test(text))
      .map(([path]) => path)

    expect(direct).toEqual([])
  })

  // Scenario: `net.isIPv6` replaced by a function that answers false, then an IPv6 address bucketed. Expected: the bucket of the /64,
  // the same as with nothing replaced. Why: with it replaced every address of one network would be its own bucket, which is a bypass
  // of the throttle.
  it('buckets an IPv6 address by its prefix with isIPv6 replaced', () => {
    const clean = rateLimitBucket('2001:db8:1:2:aaaa:bbbb:cccc:dddd')
    const during = withReplaced(
      'isIPv6',
      () => false,
      () => rateLimitBucket('2001:db8:1:2:aaaa:bbbb:cccc:dddd')
    )

    expect(clean).not.toBe('2001:db8:1:2:aaaa:bbbb:cccc:dddd')
    expect(during).toBe(clean)
  })

  // Scenario: `net.isIP` replaced by a function that answers IPv4 for anything, then a request whose `ip` is not an address and whose
  // socket peer is. Expected: the peer address, as with nothing replaced. Why: with it replaced an arbitrary string would key the
  // counter, so a caller could choose its own bucket.
  it('resolves the peer address, not an arbitrary value, with isIP replaced', () => {
    const request = { ip: 'not-an-address', socket: { remoteAddress: '203.0.113.9' } }
    const clean = resolveClientAddress(request)
    const during = withReplaced(
      'isIP',
      () => 4,
      () => resolveClientAddress(request)
    )

    expect(clean).toBe('203.0.113.9')
    expect(during).toBe(clean)
  })
})
