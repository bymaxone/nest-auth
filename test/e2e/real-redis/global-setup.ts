/**
 * @fileoverview Jest global setup for the real-Redis run: starts one Redis container for every
 * worker and publishes its address in `BYMAX_E2E_REDIS_URL`, which the harness in `../setup.ts`
 * reads.
 *
 * @layer Test
 */
import { startRedisContainer, type StartedRedis } from './redis-container'

/** Where the started container is kept so the global teardown can stop it. */
export const STARTED_KEY = '__bymaxE2eRedis'

export default async function globalSetup(): Promise<void> {
  const started = await startRedisContainer()
  ;(globalThis as Record<string, unknown>)[STARTED_KEY] = started
  process.env['BYMAX_E2E_REDIS_URL'] = started.url
}

export type { StartedRedis }
