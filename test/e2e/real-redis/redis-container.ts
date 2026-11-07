/**
 * @fileoverview Testcontainers wrapper for the real-Redis end-to-end run.
 *
 * The suites run on `ioredis-mock` by default, which is fast and keeps `pnpm test:e2e` free of a
 * container runtime. The Lua scripts behind rotation, revocation, claims and rate limits only
 * mean something against a real server, so `pnpm test:e2e:redis` starts one here and points the
 * harness at it through `BYMAX_E2E_REDIS_URL`.
 *
 * @layer Test
 */
import { GenericContainer, type StartedTestContainer } from 'testcontainers'

/**
 * The Redis image the real-Redis run uses, pinned by digest so the server a run measures against
 * is the one this file names: Redis 8, the version derived backends deploy. `REDIS_IMAGE`
 * overrides it, for trying another server version.
 */
export const REDIS_IMAGE =
  'redis:8-alpine@sha256:71885d8cc6e42f2bc0aa2eb853bfc4be200b5108a46ac50e117ae1df0531fb80'

/** A started Redis container and the `redis://` URL its mapped port answers on. */
export interface StartedRedis {
  /** The container handle; stop it when the run ends. */
  container: StartedTestContainer
  /** The connection URL for the mapped host port. */
  url: string
}

/**
 * Starts a Redis container with persistence off, on a random host port.
 *
 * @returns The started container and its connection URL.
 */
export async function startRedisContainer(): Promise<StartedRedis> {
  const image = process.env['REDIS_IMAGE'] ?? REDIS_IMAGE
  const container = await new GenericContainer(image)
    .withExposedPorts(6379)
    .withCommand(['redis-server', '--save', ''])
    .start()
  return { container, url: `redis://${container.getHost()}:${container.getMappedPort(6379)}` }
}
