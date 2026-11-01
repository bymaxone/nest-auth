/**
 * The client address a request is charged to and recorded under (layer: Utils).
 *
 * `X-Forwarded-For` is written by whoever sent the request. Express believes it as far as the
 * app's `trust proxy` setting reaches and `req.ip` is then the first entry that setting does not
 * trust, which is an arbitrary string whenever that entry is not an address: a trust predicate
 * rejects what it cannot parse, so the walk stops there and returns it. One rule serves the rate
 * limiter and every sink that records the address, so a bucket and the address written to a
 * session, a hook payload or an audit event cannot disagree.
 */

import { isIP } from 'node:net'

/** What `isIP` returns for an IPv6 literal. */
const IPV6 = 6

/** An IPv6 literal without the `%zone` suffix it may carry. */
function withoutZone(address: string): string {
  const zoneIndex = address.indexOf('%')
  return zoneIndex === -1 ? address : address.slice(0, zoneIndex)
}

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
 * Resolves the client address of a request, or `''` when there is none.
 *
 * Candidates are tried in order and the first that is an address wins: `req.ip`, then the rest of
 * `req.ips`, then the socket peer. `req.ips` runs from the client end toward the socket, and each
 * entry after the first is a hop the trust setting already vouched for, so an unparsable client
 * entry resolves to the nearest trusted hop. That is the same answer as walking the header from
 * the right and ending at the last hop that was an address.
 *
 * The value returned has no zone index. `isIP` accepts an IPv6 literal followed by `%` and a zone
 * of any length, and the zone is link-local scope rather than identity (the limiter drops it for
 * the same reason), so it is cut before the address is returned. What remains is a textual IPv4 or
 * IPv6 address of at most 45 characters, which no caller needs to bound.
 *
 * @param request - The incoming request.
 * @returns A textual IPv4 or IPv6 address, or `''` when neither the header chain nor the socket
 *   yields one.
 */
export function resolveClientAddress(request: ClientAddressSource): string {
  const candidates = [request.ip, ...(request.ips ?? []).slice(1), request.socket?.remoteAddress]
  for (const candidate of candidates) {
    if (typeof candidate !== 'string') continue
    const address = isIP(candidate) === IPV6 ? withoutZone(candidate) : candidate
    if (isIP(address) !== 0) return address
  }
  return ''
}
