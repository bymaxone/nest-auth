/**
 * @fileoverview A host client built with `keyPrefix`, against a REAL Redis.
 *
 * ioredis prefixes the keys a command declares, not the ones a Lua script builds from its
 * arguments, so every script that names a key that way has to be given the prefix. Only a real
 * server and a real client show whether the names the two produce are the same.
 *
 * @layer Test
 */

import { createHash, randomUUID } from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import Redis from 'ioredis'
import request from 'supertest'

import {
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../../src/server/bymax-auth.constants'
import { AuthService } from '../../../src/server/services/auth.service'
import { bootstrapTestApp, expectAuthError } from '../setup'

const PREFIX = 'host:'
const TENANT = 'tenant-1'
const PASSWORD = 'SuperSecret123!'

/** One application over a client of its own. */
interface Booted {
  app: INestApplication
  close: () => Promise<void>
}

/** Boots the application with `redisNamespace` over a client built with `keyPrefix`. */
async function boot(
  redisNamespace: string,
  keyPrefix: string,
  options: { graceSeconds?: number; users?: unknown } = {}
): Promise<Booted> {
  const client = new Redis(process.env['BYMAX_E2E_REDIS_URL'] as string, { keyPrefix })
  const grace = options.graceSeconds ?? 30
  const booted = await bootstrapTestApp(
    {
      redisNamespace,
      jwt: {
        secret: 'k3Y!9d_zQ7-wLm2#Vx8pRt4sNf6hJc1B0gUoAeIy5ZbDnMqT',
        refreshGraceWindowSeconds: grace
      }
    },
    {
      mutateBuilder: (builder) => {
        const built = builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(client)
        return options.users === undefined
          ? built
          : built.overrideProvider(BYMAX_AUTH_USER_REPOSITORY).useValue(options.users)
      }
    }
  )
  return {
    app: booted.app,
    close: async () => {
      await booted.app.close()
      client.disconnect()
    }
  }
}

/** Registers an account and returns its id and token pair. */
async function register(
  app: INestApplication
): Promise<{ id: string; accessToken: string; refreshToken: string }> {
  const res = await request(app.getHttpServer())
    .post('/register')
    .send({ email: 'prefix@example.com', password: PASSWORD, name: 'Prefix', tenantId: TENANT })
  const body = res.body as { accessToken: string; refreshToken: string; user: { id: string } }
  return { id: body.user.id, accessToken: body.accessToken, refreshToken: body.refreshToken }
}

/** Presents a refresh token. */
function refresh(app: INestApplication, refreshToken: string): request.Test {
  return request(app.getHttpServer()).post('/refresh').send({ refreshToken })
}

/** Lists the sessions of the caller. */
function list(app: INestApplication, accessToken: string, refreshToken: string): request.Test {
  return request(app.getHttpServer())
    .get('/sessions')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ refreshToken })
}

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex')

describe('a client built with keyPrefix (E2E, real Redis)', () => {
  let namespace: string
  let raw: Redis
  let booted: Booted | undefined

  /** The members of the one session index of this test's namespace, read without a prefix. */
  const indexMembers = async (): Promise<string[]> => {
    const [key] = await raw.keys(`${PREFIX}${namespace}:sess:*`)
    return raw.smembers(key as string)
  }

  beforeEach(() => {
    namespace = `e2e-${randomUUID()}`
    raw = new Redis(process.env['BYMAX_E2E_REDIS_URL'] as string)
  })

  afterEach(async () => {
    await booted?.close()
    booted = undefined
    raw.disconnect()
  })

  it('ends every refresh token on a revoke of all sessions', async () => {
    booted = await boot(namespace, PREFIX)
    const account = await register(booted.app)

    await booted.app.get(AuthService).revokeAllSessions({ userId: account.id, tenantId: TENANT })

    expectAuthError(await refresh(booted.app, account.refreshToken), 'auth.refresh_token_invalid')
  })

  it('revokes the family when a rotated token comes back after its grace window', async () => {
    booted = await boot(namespace, PREFIX, { graceSeconds: 0 })
    const account = await register(booted.app)
    const rotated = await refresh(booted.app, account.refreshToken)
    const successor = (rotated.body as { refreshToken: string }).refreshToken

    expectAuthError(await refresh(booted.app, account.refreshToken), 'auth.refresh_token_invalid')

    expectAuthError(await refresh(booted.app, successor), 'auth.refresh_token_invalid')
  })

  it('serves a rotated token presented again inside its grace window', async () => {
    booted = await boot(namespace, PREFIX)
    const account = await register(booted.app)

    expect((await refresh(booted.app, account.refreshToken)).status).toBe(200)
    expect((await refresh(booted.app, account.refreshToken)).status).toBe(200)
  })

  it('keeps a live grace pointer in the index through a session listing', async () => {
    booted = await boot(namespace, PREFIX)
    const account = await register(booted.app)
    const rotated = await refresh(booted.app, account.refreshToken)
    const pair = rotated.body as { accessToken: string; refreshToken: string }

    expect((await list(booted.app, pair.accessToken, pair.refreshToken)).status).toBe(200)

    await expect(indexMembers()).resolves.toContain(`rp:${sha256(account.refreshToken)}`)
  })

  it('keeps a live token in the index when its session detail is gone', async () => {
    booted = await boot(namespace, PREFIX)
    const account = await register(booted.app)
    const hash = sha256(account.refreshToken)
    await expect(raw.del(`${PREFIX}${namespace}:sd:${hash}`)).resolves.toBe(1)

    expect((await list(booted.app, account.accessToken, account.refreshToken)).status).toBe(200)

    await expect(indexMembers()).resolves.toContain(`rt:${hash}`)
  })

  // The names an application that moved its prefix into `redisNamespace` already reads.
  it('stores the names a client without a prefix reads under prefix plus namespace', async () => {
    booted = await boot(namespace, PREFIX)
    const users = booted.app.get(BYMAX_AUTH_USER_REPOSITORY) as unknown
    const account = await register(booted.app)
    const plain = await boot(`${PREFIX}${namespace}`, '', { users })

    try {
      expect((await refresh(plain.app, account.refreshToken)).status).toBe(200)
    } finally {
      await plain.close()
    }
    await expect(raw.keys(`*${namespace}*`)).resolves.toEqual(
      expect.not.arrayContaining([expect.not.stringMatching(`^${PREFIX}`)])
    )
  })
})
