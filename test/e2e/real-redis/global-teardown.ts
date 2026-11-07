/**
 * @fileoverview Jest global teardown for the real-Redis run: stops the container the global
 * setup started.
 *
 * @layer Test
 */
import { STARTED_KEY } from './global-setup'
import type { StartedRedis } from './redis-container'

/**
 * Stops the container the global setup started, if it started one.
 *
 * Runs once after every suite has finished. The handle comes from `globalThis`, where the setup
 * stored it, and a run whose setup never completed has nothing to stop.
 */
export default async function globalTeardown(): Promise<void> {
  const started = (globalThis as Record<string, unknown>)[STARTED_KEY] as StartedRedis | undefined
  await started?.container.stop()
}
