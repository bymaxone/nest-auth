/**
 * The client address a request is charged to and recorded under (layer: Utils).
 *
 * `X-Forwarded-For` is written by whoever sent the request. Express believes it as far as the
 * app's `trust proxy` setting reaches and `req.ip` is then the first entry that setting does not
 * trust, which is an arbitrary string whenever that entry is not an address: a trust predicate
 * rejects what it cannot parse, so the walk stops there and returns it. One rule serves the rate
 * limiter and every sink that records the address, so a bucket and the address written to a
 * session, a hook payload or an audit event cannot disagree.
 *
 * A header-derived entry is an address only if it parses as one with no zone index, which is what
 * the paired Rust library's `IpAddr::from_str` accepts: that parser has no `%` handling, so a
 * zoned entry ends its walk at the last hop that was an address, and so does this one.
 */

import { isIP } from 'node:net'

/** What `isIP` returns for an IPv6 literal. */
const IPV6 = 6

/**
 * The parts of a request the resolution reads, all optional: an Express request carries them, and
 * a request from a host that has not set `trust proxy` has an empty `ips`.
 */
export interface ClientAddressSource {
  readonly ip?: string | undefined
  readonly ips?: readonly string[] | undefined
  readonly socket?: { readonly remoteAddress?: string | undefined } | undefined
}

/**
 * Whether a header-derived entry is an address. A zone index (`fe80::1%eth0`) disqualifies it even
 * though `isIP` accepts one of any length: a zone names an interface on the machine that wrote
 * it, so it has no meaning across hops.
 */
function isHeaderAddress(candidate: string | undefined): candidate is string {
  return typeof candidate === 'string' && !candidate.includes('%') && isIP(candidate) !== 0
}

/**
 * The socket peer as an address, or `''`. The peer is the one place a zone is legitimate, since a
 * link-local peer is reported as `fe80::1%eth0`; it is cut because it is scope, not identity,
 * which is also how the limiter treats it.
 */
function peerAddress(remoteAddress: string | undefined): string {
  if (typeof remoteAddress !== 'string') return ''
  const zoneIndex = remoteAddress.indexOf('%')
  const bare = zoneIndex === -1 ? remoteAddress : remoteAddress.slice(0, zoneIndex)
  const family = isIP(bare)
  // Only an IPv6 literal carries a zone; a `%` after anything else is not an address.
  if (zoneIndex !== -1) return family === IPV6 ? bare : ''
  return family === 0 ? '' : bare
}

/**
 * Resolves the client address of a request, or `''` when there is none.
 *
 * Candidates are tried in order and the first that is an address wins: `req.ip`, then `req.ips`,
 * then the socket peer. `req.ips` runs from the client end toward the socket and starts with
 * `req.ip` itself; each entry after the first is a hop the trust setting already vouched for, so an
 * unparsable client entry resolves to the nearest trusted hop. That is the same answer as walking the header from
 * the right and ending at the last hop that was an address.
 *
 * The value returned is a textual IPv4 or IPv6 address of at most 45 characters, which no caller
 * needs to bound: header entries cannot carry a zone and the peer's is cut.
 *
 * @param request - The incoming request.
 * @returns A textual IPv4 or IPv6 address, or `''` when neither the header chain nor the socket
 *   yields one.
 */
export function resolveClientAddress(request: ClientAddressSource): string {
  // Stryker disable next-line ArrayDeclaration: a substituted default is not an address, so it is skipped and the result is unchanged
  const hops = request.ips ?? []
  for (const candidate of [request.ip, ...hops]) {
    if (isHeaderAddress(candidate)) return candidate
  }
  return peerAddress(request.socket?.remoteAddress)
}
