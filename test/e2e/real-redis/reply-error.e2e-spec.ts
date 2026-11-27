/**
 * @fileoverview A command the server answers with a reply error, against a REAL Redis.
 *
 * Such an error carries the command that failed, key and arguments included. Only a real client in
 * front of a real server builds it, and only an application without the library's exception filter
 * shows what Nest's own handler does with it.
 *
 * @layer Test
 */

import { inspect } from 'node:util'

import { Logger } from '@nestjs/common'
import type { INestApplication } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import Redis from 'ioredis'
import request from 'supertest'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../../src/server/bymax-auth.constants'
import { BymaxAuthModule } from '../../../src/server/bymax-auth.module'
import { AuthExceptionFilter } from '../../../src/server/filters/auth-exception.filter'
import {
  JWT_SECRET,
  createMockEmailProvider,
  createMockUserRepository,
  expectAuthError,
  realRedisNamespace
} from '../setup'

const PASSWORD = 'SuperSecret123!'
const TENANT = 'tenant-1'

/**
 * Boots the auth routes over a real client, with or without the library's exception filter, which
 * the shared bootstrap always registers.
 */
async function boot(
  client: Redis,
  namespace: string,
  withFilter: boolean
): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => ({
          jwt: { secret: JWT_SECRET },
          roles: { hierarchy: { MEMBER: [] } },
          redisNamespace: namespace,
          tokenDelivery: 'bearer' as const,
          emailVerification: { required: false },
          environment: 'test' as const,
          secureCookies: false,
          rateLimit: { enabled: true, clientIpSource: 'peer' as const }
        }),
        controllers: { auth: true },
        extraProviders: [
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: createMockUserRepository() },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: createMockEmailProvider() },
          { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: client }
        ]
      })
    ]
  }).compile()
  const app = moduleRef.createNestApplication()
  if (withFilter) app.useGlobalFilters(new AuthExceptionFilter())
  await app.listen(0)
  return app
}

/** Everything the application's loggers were given at error level, as a console would print it. */
function captureErrors(): { text: () => string; restore: () => void } {
  const lines: string[] = []
  const spy = jest.spyOn(Logger.prototype, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => inspect(arg, { depth: 6 })).join(' '))
  })
  return { text: () => lines.join('\n'), restore: () => spy.mockRestore() }
}

/** The one key the server holds under `prefix`. */
async function keyHolding(client: Redis, prefix: string): Promise<string> {
  const keys = await client.keys(`${prefix}*`)
  expect(keys).toHaveLength(1)
  return keys[0] as string
}

/** Sends one request while `key` holds a list, and checks the answer and what was logged. */
async function expectRefusal(
  client: Redis,
  key: string,
  operation: string,
  send: () => request.Test
): Promise<void> {
  await client.del(key)
  await client.lpush(key, 'planted-value')
  const errors = captureErrors()

  const res = await send()
  errors.restore()
  await client.del(key)

  expectAuthError(res, 'auth.internal')
  expect(errors.text()).toContain(`operation: '${operation}'`)
  expect(errors.text()).toContain("detail: 'ReplyError'")
  expect(errors.text()).not.toContain(key.split(':').at(-1))
  expect(errors.text()).not.toContain('planted-value')
}

describe.each([
  ['with the library filter', true],
  ['with no exception filter', false]
])('a Redis reply error %s (E2E, real Redis)', (_name, withFilter) => {
  let app: INestApplication
  let client: Redis
  const namespace = realRedisNamespace() as string

  beforeAll(async () => {
    client = new Redis(process.env['BYMAX_E2E_REDIS_URL'] as string)
    app = await boot(client, namespace, withFilter)
  })

  afterAll(async () => {
    await app.close()
    client.disconnect()
  })

  const login = (): request.Test =>
    request(app.getHttpServer())
      .post('/login')
      .send({ email: 'reply@example.com', password: 'WrongPassword123!', tenantId: TENANT })

  it.each([
    ['the rate-limit counter', 'rl:AuthController.login:', 'redis:rl'],
    ['the lockout counter', 'lf:', 'redis:lf']
  ])('is auth.internal and logs no key for %s', async (_store, part, operation) => {
    await login()

    const key = await keyHolding(client, `${namespace}:${part}`)

    await expectRefusal(client, key, operation, login)
  })

  it('is auth.internal and logs no key for the token epoch', async () => {
    const registered = await request(app.getHttpServer())
      .post('/register')
      .send({ email: 'epoch@example.com', password: PASSWORD, name: 'Epoch', tenantId: TENANT })
    const { accessToken } = registered.body as { accessToken: string }
    const me = (): request.Test =>
      request(app.getHttpServer()).get('/me').set('Authorization', `Bearer ${accessToken}`)
    const read = jest.spyOn(client, 'get')
    expect((await me()).status).toBe(200)
    const key = read.mock.calls.map(([name]) => String(name)).find((name) => name.includes(':ep:'))
    read.mockRestore()

    await expectRefusal(client, key as string, 'redis:ep', me)
  })
})
