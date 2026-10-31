import type { Request } from 'express'

/**
 * The fields {@link handshakeRequest} reads. A Socket.IO `handshake` fits, and so does an Express
 * request, which is why the verifier can take either.
 */
export interface HandshakeLike {
  headers: Record<string, string | string[] | undefined>
  url?: string
}

/**
 * Builds the request a `tenantIdResolver` sees when the caller arrived by WebSocket upgrade.
 *
 * The resolver is typed against an Express `Request`, and an upgrade has none: the guard holds a
 * handshake. The resolver must answer the same question for both doors, so it is handed an object
 * carrying the part of a request an upgrade actually has, and nothing else.
 *
 * **Provided:** `headers` (as the transport delivered them, names lowercased), `url` (the upgrade
 * URL, `''` when the transport exposes none) and `hostname`, derived from the `Host` header with
 * Express's own rule — the port is cut, a bracketed IPv6 literal keeps its brackets.
 *
 * **Absent, deliberately:** `cookies` (an upgrade carries the header but nothing here parses it
 * the way `cookie-parser` does on HTTP, and half an emulation would mis-bind rather than refuse),
 * `ip`, `ips` and every trust-proxy behaviour — `hostname` is the `Host` header as received, never
 * `X-Forwarded-Host`. A resolver that reads something missing gets `undefined`, and a resolver
 * that throws on it is refused by the guard rather than mis-bound.
 *
 * The cast is the single place the shim claims to be a `Request`; its honesty is the list above.
 *
 * @param handshake - The connecting client's handshake.
 * @returns A request-like object for the configured `tenantIdResolver`.
 */
export function handshakeRequest(handshake: HandshakeLike): Request {
  const headers: Record<string, string | string[] | undefined> = {}
  for (const [name, value] of Object.entries(handshake.headers)) {
    headers[name.toLowerCase()] = value
  }
  const host = headers['host']
  return { headers, url: handshake.url ?? '', hostname: hostnameOf(host) } as unknown as Request
}

/** Express's `req.hostname` rule on a raw `Host` value: strip the port, keep an IPv6 literal whole. */
function hostnameOf(host: string | string[] | undefined): string | undefined {
  // Absent, or repeated: a second `Host` is not a hostname, and the first is not a safe pick.
  if (typeof host !== 'string') return undefined
  const offset = host.startsWith('[') ? host.indexOf(']') + 1 : 0
  const index = host.indexOf(':', offset)
  return index === -1 ? host : host.substring(0, index)
}
