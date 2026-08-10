/**
 * Ambient module declaration for ioredis-mock.
 *
 * The upstream `@types/ioredis-mock` package is not hoisted into this workspace's
 * top-level `node_modules`, so the TypeScript compiler cannot resolve declarations
 * for the `ioredis-mock` module. This shim provides a minimal default export typed
 * as a constructor returning a partial ioredis-compatible instance (not fully typed —
 * callers must cast as `unknown as Redis`).
 */

declare module 'ioredis-mock' {
  /**
   * Constructor signature for the ioredis-mock default export.
   *
   * Accepts the same connection options as `ioredis`; only `port` is typed here,
   * used to give each instance its own isolated keyspace (ioredis-mock keys its
   * store by connection). Returns a partial ioredis-compatible instance (not fully
   * typed — callers must cast as `unknown as Redis`).
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const RedisMock: new (options?: { port?: number }) => any

  export default RedisMock
}
