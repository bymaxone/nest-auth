/**
 * @fileoverview The request a `tenantIdResolver` sees when the caller arrived by WebSocket upgrade.
 *
 * @layer Utility
 */

import type { TenantResolverRequest } from '../interfaces/auth-module-options.interface'

/**
 * The fields {@link handshakeRequest} reads. A Socket.IO `handshake` fits, and so does an Express
 * request.
 */
export interface HandshakeLike {
  headers: Record<string, string | string[] | undefined>
  url?: string
  /**
   * The TCP peer, as the transport reported it, never a header. Read only to decide whether
   * `X-Forwarded-Host` may be believed; absent or empty means it may not.
   */
  remoteAddress?: string
}

/**
 * Builds the {@link TenantResolverRequest} for a caller that arrived by WebSocket upgrade.
 *
 * An upgrade has no Express request: the guard holds a handshake. The resolver must answer the
 * same question for both doors, so it is handed an object carrying the part of a request every
 * transport has, and nothing else.
 *
 * **Provided:** `headers` (as the transport delivered them, names lowercased), `url` (the upgrade
 * URL, `''` when the transport exposes none) and `hostname`, derived with Express's own rule — the
 * port is cut, a bracketed IPv6 literal keeps its brackets — and `''` when there is no usable
 * value, so a resolver deriving a tenant from it resolves nothing and is refused.
 *
 * **Which header.** The `Host` header, unless `isTrustedProxy` approves the TCP peer, in which case
 * the first element of a single `X-Forwarded-Host` replaces it — the check Express makes for the
 * immediate peer. Everything else is the stricter reading: no predicate, no peer, an untrusted
 * peer, a predicate that throws or answers anything but `true`, a header handed over as separate
 * values, or an empty first element all give `Host`. Node joins a header repeated on the wire into
 * one comma-separated string, whose first element is used, as Express does. A client therefore
 * cannot choose its own host.
 *
 * **Absent, by type and at runtime:** `cookies` (an upgrade carries the header but nothing here
 * parses it the way `cookie-parser` does on HTTP, and half an emulation would mis-bind rather than
 * refuse), `ip`, `ips` and the rest of Express's trust-proxy behaviour.
 *
 * @param handshake - The connecting client's handshake.
 * @param isTrustedProxy - The host's trust policy for the immediate peer, if it configured one.
 * @returns The request for the configured `tenantIdResolver`.
 */
export function handshakeRequest(
  handshake: HandshakeLike,
  isTrustedProxy?: (peerAddress: string) => boolean
): TenantResolverRequest {
  const headers: Record<string, string | string[] | undefined> = {}
  for (const [name, value] of Object.entries(handshake.headers)) {
    headers[name.toLowerCase()] = value
  }
  const forwarded = trustedForwardedHost(
    headers['x-forwarded-host'],
    handshake.remoteAddress,
    isTrustedProxy
  )
  return {
    headers,
    url: handshake.url ?? '',
    hostname: hostnameOf(forwarded ?? headers['host'])
  }
}

/**
 * The forwarded host a trusted peer asserted, or `undefined` when the `Host` header stands.
 *
 * @param forwarded - The `x-forwarded-host` header value(s).
 * @param peer - The TCP peer address, if the transport reported one.
 * @param isTrustedProxy - The host's trust policy, if configured.
 */
function trustedForwardedHost(
  forwarded: string | string[] | undefined,
  peer: string | undefined,
  isTrustedProxy: ((peerAddress: string) => boolean) | undefined
): string | undefined {
  if (isTrustedProxy === undefined || typeof forwarded !== 'string') return undefined
  if (peer === undefined || peer.trim() === '') return undefined
  let trusted: unknown
  try {
    trusted = isTrustedProxy(peer)
  } catch {
    return undefined
  }
  if (trusted !== true) return undefined
  const comma = forwarded.indexOf(',')
  const first = (comma === -1 ? forwarded : forwarded.slice(0, comma)).trim()
  return first === '' ? undefined : first
}

/** Express's `req.hostname` rule on a raw `Host` value: strip the port, keep an IPv6 literal whole. */
function hostnameOf(host: string | string[] | undefined): string {
  // Absent, or repeated: a second `Host` is not a hostname, and the first is not a safe pick.
  if (typeof host !== 'string') return ''
  const offset = host.startsWith('[') ? host.indexOf(']') + 1 : 0
  const index = host.indexOf(':', offset)
  return index === -1 ? host : host.substring(0, index)
}
