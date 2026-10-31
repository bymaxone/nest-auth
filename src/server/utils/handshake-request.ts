/**
 * @fileoverview The request a `tenantIdResolver` sees when the caller arrived by WebSocket upgrade.
 *
 * @layer Utility
 */

import type { TenantResolverRequest } from '../interfaces/auth-module-options.interface'

/**
 * The fields {@link handshakeRequest} reads. A Socket.IO `handshake` fits, and so does an Express
 * request, which is why the verifier can take either.
 */
export interface HandshakeLike {
  headers: Record<string, string | string[] | undefined>
  url?: string
}

/**
 * Builds the {@link TenantResolverRequest} for a caller that arrived by WebSocket upgrade.
 *
 * An upgrade has no Express request: the guard holds a handshake. The resolver must answer the
 * same question for both doors, so it is handed an object carrying the part of a request every
 * transport has, and nothing else.
 *
 * **Provided:** `headers` (as the transport delivered them, names lowercased), `url` (the upgrade
 * URL, `''` when the transport exposes none) and `hostname`, derived from the `Host` header with
 * Express's own rule — the port is cut, a bracketed IPv6 literal keeps its brackets — and `''` when
 * there is no usable `Host`, so a resolver deriving a tenant from it resolves nothing and is refused.
 *
 * **Absent, by type and at runtime:** `cookies` (an upgrade carries the header but nothing here
 * parses it the way `cookie-parser` does on HTTP, and half an emulation would mis-bind rather than
 * refuse), `ip`, `ips` and every trust-proxy behaviour — `hostname` is the `Host` header as
 * received, never `X-Forwarded-Host`.
 *
 * @param handshake - The connecting client's handshake.
 * @returns The request for the configured `tenantIdResolver`.
 */
export function handshakeRequest(handshake: HandshakeLike): TenantResolverRequest {
  const headers: Record<string, string | string[] | undefined> = {}
  for (const [name, value] of Object.entries(handshake.headers)) {
    headers[name.toLowerCase()] = value
  }
  return { headers, url: handshake.url ?? '', hostname: hostnameOf(headers['host']) }
}

/** Express's `req.hostname` rule on a raw `Host` value: strip the port, keep an IPv6 literal whole. */
function hostnameOf(host: string | string[] | undefined): string {
  // Absent, or repeated: a second `Host` is not a hostname, and the first is not a safe pick.
  if (typeof host !== 'string') return ''
  const offset = host.startsWith('[') ? host.indexOf(']') + 1 : 0
  const index = host.indexOf(':', offset)
  return index === -1 ? host : host.substring(0, index)
}
