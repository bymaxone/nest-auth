/**
 * @fileoverview Jest global teardown for the real-Redis run: stops the container the global
 * setup started.
 *
 * @layer Test
 */
import { STARTED_KEY, type StartedRedis } from './global-setup'

export default async function globalTeardown(): Promise<void> {
  const started = (globalThis as Record<string, unknown>)[STARTED_KEY] as StartedRedis | undefined
  await started?.container.stop()
}
