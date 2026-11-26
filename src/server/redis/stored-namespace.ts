/**
 * @fileoverview The namespace as the server stores it.
 *
 * @layer Infrastructure
 */

/**
 * ioredis puts the client's `keyPrefix` before the keys a command declares, and not before the
 * names a script builds from its arguments. A name handed to a script that way starts with this.
 *
 * The test of the prefix is the truthiness ioredis applies it on. A standalone client and a
 * cluster both carry it in `options.keyPrefix`.
 *
 * @param client - The client the host supplied.
 * @param namespace - The `redisNamespace` option.
 * @returns The client's key prefix followed by the namespace.
 * @throws {Error} When the prefix is not a string: ioredis prepends a `Buffer` as bytes, which a
 *   string argument cannot repeat.
 */
export function storedNamespace(client: unknown, namespace: string): string {
  const prefix = (client as { options?: { keyPrefix?: unknown } }).options?.keyPrefix
  if (!prefix) return namespace
  if (typeof prefix !== 'string') {
    throw new Error('[BymaxAuthModule] The keyPrefix of BYMAX_AUTH_REDIS_CLIENT must be a string.')
  }
  return `${prefix}${namespace}`
}
