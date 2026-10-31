/**
 * @fileoverview The request headers this library reads, or that feed a field it reads.
 *
 * A service-key header must not be one of these: the key would then travel through a path built
 * for something else (a context field, a client-address derivation, another credential) and
 * reach a place no key should. `apiKeys.header` is refused at startup when it names one.
 *
 * @layer Constants
 */

/**
 * Lowercase names of the request headers the server code reads or derives a field from.
 *
 * An end-to-end walker over the server sources fails when a header literal is read that is
 * missing here, so a new read cannot be forgotten. It runs there, not as a unit spec, because it
 * parses source text and mutation testing instruments that text.
 */
export const LIBRARY_READ_HEADERS: readonly string[] = [
  // The user JWT bearer, on HTTP and on the WebSocket handshake.
  'authorization',
  'proxy-authorization',
  // Session cookies, which the host's cookie parser exposes as `req.cookies`.
  'cookie',
  'set-cookie',
  // Copied into the `userAgent` field of every hook context.
  'user-agent',
  // The cross-site request checks of `TrustedOriginGuard`.
  'origin',
  'sec-fetch-site',
  // What the client address (`request.ip`) is derived from behind a trusted proxy.
  'x-forwarded-for',
  'x-forwarded-host',
  'x-real-ip',
  'x-original-forwarded-for',
  // The `hostname` handed to a `tenantIdResolver` on a WebSocket upgrade, which has no Express request.
  'host'
]
