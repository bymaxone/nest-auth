/**
 * @fileoverview The shape a real consumer receives — which nothing in this repository had seen.
 *
 * Measured by the community-core consumer, from outside: this suite carried **3** assertions on
 * the raw `AuthException` body and **0** on the envelope a derived backend actually serves. Every
 * such backend registers `@bymax-one/nest-core`'s filter, which reshapes
 * `{error: {code, message, details}}` into a flat `{statusCode, code, message, details?,
 * timestamp, path, correlationId?}`. This library asserted the pre-filter shape exclusively.
 *
 * That is not a theoretical gap. It is where `POST /password/change` was broken — the handler read
 * a `refreshToken` the pipe refused, and a consumer met the 400 in production because no suite
 * here composed the two libraries. Neither library's own suite can see this: nest-auth's sees its
 * own pipe and exception, nest-core's sees its own filter, and the shape a client parses exists
 * only where the two are wired together.
 *
 * `@bymax-one/nest-core` is a **devDependency** — the same one the OpenAPI contributor's contract
 * types need. Nothing here reaches the published bundle.
 */

import { BymaxCoreModule } from '@bymax-one/nest-core'
import type { INestApplication } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Redis } from 'ioredis'
import request from 'supertest'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { BymaxAuthModule } from '../../src/server/bymax-auth.module'
import type { BymaxAuthModuleOptions } from '../../src/server/interfaces/auth-module-options.interface'
import {
  JWT_SECRET,
  applyComposedMiddleware,
  createMockEmailProvider,
  createMockPlatformUserRepository,
  createMockRedis,
  createMockUserRepository
} from './setup'
import type { MockUserRepository } from './setup'

/** The flat envelope nest-core serves. Modelled loosely — only the parts a client parses. */
interface ComposedEnvelope {
  statusCode: number
  code: string
  message: string
  details?: unknown
  timestamp?: string
  path?: string
}

/**
 * Boots both libraries together, the way a derived backend does.
 *
 * Deliberately NOT built on `bootstrapTestApp`: that harness registers this library's own filter
 * and nothing else, which is the single-library deployment every other spec measures. The point
 * here is the composition, so the wiring is spelled out rather than inherited.
 */
async function bootstrapComposedApp(
  overrides: Partial<BymaxAuthModuleOptions> = {}
): Promise<{ app: INestApplication; repo: MockUserRepository; redis: Redis }> {
  const repo = createMockUserRepository()
  const redis = createMockRedis()

  const moduleRef = await Test.createTestingModule({
    imports: [
      BymaxCoreModule.forRoot({}),
      BymaxAuthModule.registerAsync({
        useFactory: () => ({
          jwt: { secret: JWT_SECRET },
          roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
          tokenDelivery: 'bearer',
          emailVerification: { required: false },
          environment: 'test',
          secureCookies: false,
          rateLimit: { enabled: false },
          ...overrides
        }),
        controllers: { auth: true, passwordReset: true },
        extraProviders: [
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: repo },
          {
            provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
            useValue: createMockPlatformUserRepository()
          },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: createMockEmailProvider() },
          { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: redis }
        ]
      })
    ]
  })
    .setLogger({
      log: () => undefined,
      error: () => undefined,
      warn: () => undefined,
      debug: () => undefined,
      verbose: () => undefined
    })
    .compile()

  const app = moduleRef.createNestApplication()
  applyComposedMiddleware(app)
  await app.init()

  return { app, repo, redis }
}

describe('composed with @bymax-one/nest-core (E2E)', () => {
  let app: INestApplication

  beforeAll(async () => {
    ;({ app } = await bootstrapComposedApp())
  })

  afterAll(async () => {
    await app.close()
  })

  // Verifies a DTO failure survives the composition with its code and its per-field details.
  //
  // The failure mode this pins is precise and has happened: nest-core's filter recognises the
  // framework's validation shape (`{message: string[]}`) and rewrites it to
  // `BYMAX_VALIDATION_FAILED` with `details[].issue`. That is what a derived backend serves when
  // a global `ValidationPipe` shadows this library's — the hazard documented in the CHANGELOG.
  // Composed correctly, the auth code and `details[].field` come through untouched, and asserting
  // BOTH is what separates the two worlds: the wrong one still answers 400 with an envelope.
  it('carries auth.validation through the filter with details[].field intact', async () => {
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({ email: 'not-an-email', password: 'short', name: 'A', tenantId: 't1' })

    const body = res.body as ComposedEnvelope
    expect(res.status).toBe(400)
    expect(body.code).toBe('auth.validation')
    expect(body.details).toEqual(
      expect.arrayContaining([expect.objectContaining({ field: expect.any(String) })])
    )
    // Flat, not nested — the shape a consumer parses. Asserting the absence of the nested form is
    // what proves the filter ran at all; every other spec in this repository sees the nested one.
    expect(body).not.toHaveProperty('error')
    expect(body.statusCode).toBe(400)
  })

  // Verifies a domain code survives the filter unchanged.
  //
  // This composition was broken until nest-core 1.2.0 — every distinct auth failure arrived as one
  // `BYMAX_BAD_REQUEST` reading "Auth Exception", with no details — and **nothing in either
  // repository pins it**. It is pinned here now, in the only place that can see it.
  it('carries a domain AuthException code through the filter unchanged', async () => {
    const res = await request(app.getHttpServer())
      .post('/login')
      .send({ email: 'nobody@example.com', password: 'ProbePass123!-xyz', tenantId: 't1' })

    const body = res.body as ComposedEnvelope
    expect(res.status).toBe(401)
    expect(body.code).toBe('auth.invalid_credentials')
    expect(body).not.toHaveProperty('error')
  })

  // Verifies the status a code carries survives too, not only the code.
  //
  // Thirteen statuses drifted from rust-auth once, and a filter that normalised everything to 400
  // or 500 would reintroduce that silently while every code assertion above stayed green. A 409
  // is the sharpest case: it is the one status a client is most likely to branch on.
  it('preserves the status the code declares, not just the code', async () => {
    const first = await request(app.getHttpServer()).post('/register').send({
      email: 'dup@example.com',
      password: 'ProbePass123!-xyz',
      name: 'Dup',
      tenantId: 't1'
    })
    expect(first.status).toBe(201)

    const second = await request(app.getHttpServer()).post('/register').send({
      email: 'dup@example.com',
      password: 'ProbePass123!-xyz',
      name: 'Dup',
      tenantId: 't1'
    })

    const body = second.body as ComposedEnvelope
    expect(second.status).toBe(409)
    expect(body.code).toBe('auth.email_already_exists')
    expect(body.statusCode).toBe(409)
  })

  // Verifies the request-body flow that only exists under `tokenDelivery: 'bearer'` — the
  // defect's own regression test, in the configuration that exhibited it.
  //
  // `POST /password/change` reads the caller's refresh token from the BODY in bearer mode, and
  // `ChangePasswordDto` did not declare it, so `forbidNonWhitelisted` refused the field the
  // handler needs. A cookie-mode deployment never saw it. Driven here composed, because the
  // consumer who met it was running both libraries.
  it('accepts the bearer-mode refreshToken on password/change, composed', async () => {
    const registered = await request(app.getHttpServer()).post('/register').send({
      email: 'change-composed@example.com',
      password: 'OldSecret123!-xyz',
      name: 'Composed',
      tenantId: 't1'
    })
    expect(registered.status).toBe(201)
    const { accessToken, refreshToken } = registered.body as {
      accessToken: string
      refreshToken: string
    }

    const changed = await request(app.getHttpServer())
      .post('/password/change')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        currentPassword: 'OldSecret123!-xyz',
        newPassword: 'BrandNewSecret456!',
        refreshToken
      })

    expect(changed.status).toBe(204)
  })

  // Verifies a failure this library never raised still composes into one envelope.
  //
  // Two filters are in the chain in a derived backend — nest-auth's, when the host registers it,
  // and nest-core's outermost. Nothing had ever driven that ordering. A 404 is the shortest route
  // to a failure neither library's domain code produced.
  it('gives a route that does not exist a single, well-formed envelope', async () => {
    const res = await request(app.getHttpServer()).get('/no-such-route')

    const body = res.body as ComposedEnvelope
    expect(res.status).toBe(404)
    expect(typeof body.code).toBe('string')
    expect(body).not.toHaveProperty('error')
  })
})
