/**
 * @fileoverview Jest global setup for the real-Redis run: starts one Redis container for every
 * worker and publishes its address in `BYMAX_E2E_REDIS_URL`, which the harness in `../setup.ts`
 * reads.
 *
 * @layer Test
 */
import { startRedisContainer } from './redis-container'

/** Where the started container is kept so the global teardown can stop it. */
export const STARTED_KEY = '__bymaxE2eRedis'

/**
 * Starts the Redis container once for the whole run.
 *
 * The container handle is kept on `globalThis` under {@link STARTED_KEY} for the global teardown,
 * which runs in the same process, and its address is handed to every worker through
 * `BYMAX_E2E_REDIS_URL`, the variable `../setup.ts` reads to choose a real client. A failure to
 * start, such as Docker being unavailable, aborts the run before any suite starts.
 */
export default async function globalSetup(): Promise<void> {
  const started = await startRedisContainer()
  ;(globalThis as Record<string, unknown>)[STARTED_KEY] = started
  process.env['BYMAX_E2E_REDIS_URL'] = started.url
}
