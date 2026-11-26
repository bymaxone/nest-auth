/**
 * @fileoverview A host client built with `keyPrefix`, against a REAL Redis.
 *
 * ioredis prefixes the keys a command declares, not the ones a Lua script builds from its
 * arguments, so a script that ends sessions deletes names nothing is stored under. The module
 * refuses such a client at startup.
 *
 * @layer Test
 */

import Redis, { Cluster } from 'ioredis'

import { BYMAX_AUTH_REDIS_CLIENT } from '../../../src/server/bymax-auth.constants'
import { bootstrapTestApp } from '../setup'

/** Boots the application over `client`, and closes it again if it did start. */
async function boot(client: unknown): Promise<void> {
  const booted = await bootstrapTestApp(
    {},
    {
      listen: false,
      mutateBuilder: (builder) => builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(client)
    }
  )
  await booted.app.close()
}

const REFUSAL = '[BymaxAuthModule] BYMAX_AUTH_REDIS_CLIENT has a keyPrefix'

describe('a client built with keyPrefix (E2E, real Redis)', () => {
  const url = (): string => process.env['BYMAX_E2E_REDIS_URL'] as string

  it('refuses to start and names the option to use instead', async () => {
    const client = new Redis(url(), { keyPrefix: 'host:' })

    try {
      await expect(boot(client)).rejects.toThrow(REFUSAL)
      await expect(boot(client)).rejects.toThrow('set the redisNamespace option instead')
    } finally {
      client.disconnect()
    }
  })

  // ioredis reads a cluster's prefix from either of two places into `options.keyPrefix`.
  it.each([
    ['the cluster options', { keyPrefix: 'host:' }],
    ['the node options', { redisOptions: { keyPrefix: 'host:' } }]
  ])('refuses a cluster that takes it from %s', async (_where, options) => {
    const { hostname, port } = new URL(url())
    const client = new Cluster([{ host: hostname, port: Number(port) }], {
      ...options,
      lazyConnect: true
    })

    try {
      await expect(boot(client)).rejects.toThrow(REFUSAL)
    } finally {
      client.disconnect()
    }
  })

  it('starts with a client whose keyPrefix is empty', async () => {
    const client = new Redis(url(), { keyPrefix: '' })

    try {
      await expect(boot(client)).resolves.toBeUndefined()
    } finally {
      client.disconnect()
    }
  })
})
