import { Inject, Injectable } from '@nestjs/common'
import type { Redis } from 'ioredis'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REDIS_CLIENT } from '../bymax-one-nest-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'

/**
 * Internal Redis service for @bymax-one/nest-auth.
 *
 * Wraps the host-provided ioredis client and automatically prefixes every key
 * with `{namespace}:` to prevent collisions with the host application's own
 * Redis keys. All operations are exposed as typed async methods.
 *
 * @remarks
 * This service is **internal** — it is NOT exported from the public barrel
 * (`src/server/index.ts`). Consumers interact with it indirectly through the
 * higher-level services (BruteForceService, TokenManagerService, etc.).
 *
 * The namespace is taken from `ResolvedOptions.redisNamespace` (defaults to
 * `'bymaxauth'`). Example key with namespace `'auth'` and key `'rt:abc'`:
 * → `'auth:rt:abc'`
 */
@Injectable()
export class AuthRedisService {
  private readonly namespace: string

  constructor(
    @Inject(BYMAX_AUTH_REDIS_CLIENT) private readonly redis: Redis,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    this.namespace = options.redisNamespace
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private prefix(key: string): string {
    return `${this.namespace}:${key}`
  }

  // ---------------------------------------------------------------------------
  // String operations
  // ---------------------------------------------------------------------------

  /**
   * Gets the string value for a key.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns The stored string, or `null` if the key does not exist.
   */
  async get(key: string): Promise<string | null> {
    return this.redis.get(this.prefix(key))
  }

  /**
   * Sets a string value, optionally with an expiry.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param value - String value to store.
   * @param ttl - Time-to-live in seconds. When omitted the key never expires.
   */
  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl !== undefined) {
      await this.redis.set(this.prefix(key), value, 'EX', ttl)
    } else {
      await this.redis.set(this.prefix(key), value)
    }
  }

  /**
   * Deletes a key.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   */
  async del(key: string): Promise<void> {
    await this.redis.del(this.prefix(key))
  }

  /**
   * Atomically sets a key with an expiry only if the key does not already exist.
   *
   * Equivalent to `SET key "1" EX ttl NX`. Returns `true` if the key was created
   * (first caller), or `false` if the key already existed (subsequent callers).
   *
   * Use this instead of a GET + SET pair to avoid TOCTOU race conditions, e.g.
   * for cooldown guards where only one concurrent caller should succeed.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param ttl - Time-to-live in seconds.
   * @returns `true` if the key was newly set, `false` if it already existed.
   */
  async setnx(key: string, ttl: number): Promise<boolean> {
    const result = await this.redis.set(this.prefix(key), '1', 'EX', ttl, 'NX')
    return result === 'OK'
  }

  // ---------------------------------------------------------------------------
  // Counter / expiry operations
  // ---------------------------------------------------------------------------

  /**
   * Atomically increments an integer counter and returns the new value.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns The value of the key after the increment.
   */
  async incr(key: string): Promise<number> {
    return this.redis.incr(this.prefix(key))
  }

  /**
   * Sets a key's time-to-live in seconds.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param ttl - New time-to-live in seconds.
   */
  async expire(key: string, ttl: number): Promise<void> {
    await this.redis.expire(this.prefix(key), ttl)
  }

  /**
   * Returns the remaining time-to-live of a key in seconds.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns Seconds until expiry, `-1` if no expiry is set, or `-2` if the key
   *   does not exist.
   */
  async ttl(key: string): Promise<number> {
    return this.redis.ttl(this.prefix(key))
  }

  // ---------------------------------------------------------------------------
  // Set operations
  // ---------------------------------------------------------------------------

  /**
   * Adds a member to a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @param member - Member to add.
   * @returns `1` if the member was added, `0` if it already existed.
   */
  async sadd(setKey: string, member: string): Promise<number> {
    return this.redis.sadd(this.prefix(setKey), member)
  }

  /**
   * Removes a member from a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @param member - Member to remove.
   * @returns `1` if the member was removed, `0` if it did not exist.
   */
  async srem(setKey: string, member: string): Promise<number> {
    return this.redis.srem(this.prefix(setKey), member)
  }

  /**
   * Returns all members of a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @returns Array of member strings (empty array if the key does not exist).
   */
  async smembers(setKey: string): Promise<string[]> {
    return this.redis.smembers(this.prefix(setKey))
  }

  /**
   * Tests whether a member belongs to a Redis Set.
   *
   * @param setKey - Set key (namespace prefix is applied automatically).
   * @param member - Member to test.
   * @returns `true` if the member is in the set, `false` otherwise.
   */
  async sismember(setKey: string, member: string): Promise<boolean> {
    const result = await this.redis.sismember(this.prefix(setKey), member)
    return result === 1
  }

  // ---------------------------------------------------------------------------
  // Lua scripting
  // ---------------------------------------------------------------------------

  /**
   * Executes a Lua script via EVAL.
   *
   * @param script - Lua script source.
   * @param keys - Redis keys referenced in the script (automatically prefixed).
   *   Accessible as `KEYS[1]`, `KEYS[2]`, … inside Lua.
   * @param args - Additional arguments. Accessible as `ARGV[1]`, `ARGV[2]`, … in Lua.
   * @returns The script's return value. The concrete type depends on the script —
   *   callers must cast or narrow the result themselves.
   *
   * @remarks
   * The return type is `unknown` rather than `any` to enforce explicit handling
   * at the call site. Use a type assertion or runtime check after calling this method.
   */
  async eval(script: string, keys: string[], args: string[]): Promise<unknown> {
    const prefixedKeys = keys.map((k) => this.prefix(k))
    return this.redis.eval(script, prefixedKeys.length, ...prefixedKeys, ...args)
  }

  // ---------------------------------------------------------------------------
  // Atomic compound operations
  // ---------------------------------------------------------------------------

  /**
   * Atomically gets a key's value and deletes it in a single operation.
   *
   * Equivalent to Redis 6.2+ `GETDEL` command. Implemented via Lua for
   * compatibility with older Redis versions (minimum Redis 2.6 for EVAL).
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @returns The value of the key before deletion, or `null` if it did not exist.
   */
  async getdel(key: string): Promise<string | null> {
    const result = await this.eval(
      `local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]) end; return v`,
      [key],
      []
    )
    return typeof result === 'string' ? result : null
  }

  /**
   * Atomically increments a counter and sets a fixed TTL on the **first** increment.
   *
   * Implements a fixed-window rate-limit counter. The TTL is set only when the
   * counter transitions from 0 → 1, so the window starts at the first failure and
   * does NOT reset on subsequent failures. This prevents an attacker from sending
   * one request per `(windowSeconds - 1)` seconds to avoid ever crossing the
   * threshold.
   *
   * @param key - Application key (namespace prefix is applied automatically).
   * @param ttl - Window duration in seconds. Applied only on the first increment.
   * @returns The value of the counter after incrementing.
   */
  async incrWithFixedTtl(key: string, ttl: number): Promise<number> {
    const result = await this.eval(
      `local v = redis.call('INCR', KEYS[1])
       if v == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
       return v`,
      [key],
      [String(ttl)]
    )
    return typeof result === 'number' ? result : 0
  }
}
