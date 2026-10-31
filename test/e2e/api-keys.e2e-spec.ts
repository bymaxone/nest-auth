/**
 * @fileoverview Scoped service API keys, driven over HTTP from a host's own controllers.
 *
 * The harness plays the consumer, as `host-mounted-guards.e2e-spec.ts` does: the controllers
 * below are declared in the TEST module, not inside `BymaxAuthModule`, so `@ServiceKey()` binds
 * `ApiKeyGuard` in the host's injector and can only resolve what the module actually exports.
 *
 * The property that matters most is the one a unit test cannot show. `@ServiceKey()` reuses the
 * marker `JwtAuthGuard` skips, so "public" must never become "unauthenticated" on those routes:
 * with a GLOBAL `JwtAuthGuard` bound, a missing or invalid key must still be refused, and a user
 * JWT must not stand in for a key. That is asserted here, end to end.
 */

import { Controller, Get, Module, Post, UseGuards } from '@nestjs/common'
import type { INestApplication } from '@nestjs/common'
import { APP_GUARD } from '@nestjs/core'
import { Test } from '@nestjs/testing'
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler'
import request from 'supertest'

import {
  BYMAX_AUTH_API_KEY_REPOSITORY,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { BymaxAuthModule } from '../../src/server/bymax-auth.module'
import { CurrentApiKey } from '../../src/server/decorators/current-api-key.decorator'
import { Public } from '../../src/server/decorators/public.decorator'
import { ServiceKey } from '../../src/server/decorators/service-key.decorator'
import { AUTH_ERROR_CODES } from '../../src/server/errors/auth-error-codes'
import { ApiKeyGuard } from '../../src/server/guards/api-key.guard'
import { JwtAuthGuard } from '../../src/server/guards/jwt-auth.guard'
import type { ApiKeyPrincipal } from '../../src/server/interfaces/api-key-repository.interface'
import type { ApiKeyAccessEvent } from '../../src/server/interfaces/auth-hooks.interface'
import { ApiKeyLastUsedService } from '../../src/server/services/api-key-last-used.service'
import { ApiKeyService } from '../../src/server/services/api-key.service'
import { MemoryApiKeyRepository } from '../../src/server/services/__tests__/api-key-fixtures'
import {
  JWT_SECRET,
  applyTestMiddleware,
  createMockRedis,
  createMockUserRepository,
  expectAuthError
} from './setup'

const PEPPER = 'pepper-for-e2e-0123456789abcdefABCDEF!!'

// ---------------------------------------------------------------------------
// The host's controllers
// ---------------------------------------------------------------------------

/** What the machine routes answer when admitted. */
interface Admitted {
  label: string
  keyId: string
}

/** Buckets the throttle on the VERIFIED key id, falling back to the address. */
class KeyThrottlerGuard extends ThrottlerGuard {
  protected override async getTracker(req: Record<string, unknown>): Promise<string> {
    const key = req['apiKey'] as ApiKeyPrincipal | undefined
    return key?.id ?? String(req['ip'])
  }
}

@Controller('machine')
class MachineController {
  @ServiceKey('read')
  @Get('videos')
  list(@CurrentApiKey() key: ApiKeyPrincipal | undefined): Admitted {
    return { label: key?.label ?? '', keyId: key?.id ?? '' }
  }

  @ServiceKey('operate')
  @Post('videos')
  create(@CurrentApiKey() key: ApiKeyPrincipal | undefined): Admitted {
    return { label: key?.label ?? '', keyId: key?.id ?? '' }
  }

  @ServiceKey('admin')
  @Get('admin')
  admin(): { ok: true } {
    return { ok: true }
  }

  @ServiceKey('read', 'operate')
  @Get('both')
  both(): { ok: true } {
    return { ok: true }
  }

  /**
   * The host let the route past the user JWT guard and bound the key guard, but forgot the scope
   * declaration. `@Public()` and `@UseGuards(ApiKeyGuard)` are what `@ServiceKey()` does minus
   * the scopes, so this is the exact shape of that mistake: it must be refused, not opened.
   */
  @Public()
  @UseGuards(ApiKeyGuard)
  @Get('undeclared')
  undeclared(): { ok: true } {
    return { ok: true }
  }

  /** A per-key limit placed AFTER the key guard, so the tracker sees the verified key. */
  @UseGuards(KeyThrottlerGuard)
  @ServiceKey('read')
  @Get('limited')
  limited(): { ok: true } {
    return { ok: true }
  }
}

/** A user route, protected by the GLOBAL `JwtAuthGuard` and carrying no decorator at all. */
@Controller('user')
class UserController {
  @Get('profile')
  profile(): { ok: true } {
    return { ok: true }
  }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface Harness {
  app: INestApplication
  repo: MemoryApiKeyRepository
  keys: ApiKeyService
  events: ApiKeyAccessEvent[]
}

async function boot(): Promise<Harness> {
  const repo = new MemoryApiKeyRepository()
  const events: ApiKeyAccessEvent[] = []

  @Module({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => ({
          jwt: { secret: JWT_SECRET },
          roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
          environment: 'test' as const,
          secureCookies: false,
          rateLimit: { enabled: false as const },
          tokenDelivery: 'bearer' as const,
          apiKeys: {
            enabled: true,
            pepper: PEPPER,
            scopes: ['read', 'operate', 'publish-claim', 'admin'],
            lastUsedFlushSeconds: 3600
          }
        }),
        extraProviders: [
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: createMockUserRepository() },
          { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: createMockRedis() },
          { provide: BYMAX_AUTH_API_KEY_REPOSITORY, useValue: repo },
          {
            provide: BYMAX_AUTH_HOOKS,
            useValue: {
              onApiKeyRequest: (event: ApiKeyAccessEvent) => {
                events.push(event)
              }
            }
          }
        ]
      }),
      ThrottlerModule.forRoot([{ name: 'default', ttl: 60_000, limit: 3 }])
    ],
    controllers: [MachineController, UserController],
    // The deployment the feature must survive: a GLOBAL user-JWT guard in front of every route.
    providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }]
  })
  class Host {}

  const moduleRef = await Test.createTestingModule({ imports: [Host] })
    .setLogger({
      log: () => undefined,
      error: () => undefined,
      warn: () => undefined,
      debug: () => undefined,
      verbose: () => undefined
    })
    .compile()
  const app = moduleRef.createNestApplication()
  applyTestMiddleware(app)
  await app.init()
  return { app, repo, keys: moduleRef.get(ApiKeyService, { strict: false }), events }
}

const get = (h: Harness, path: string, key?: string): request.Test => {
  const req = request(h.app.getHttpServer()).get(path)
  return key === undefined ? req : req.set('x-api-key', key)
}

describe('service API keys (e2e)', () => {
  let h: Harness

  beforeEach(async () => {
    h = await boot()
  })

  afterEach(async () => {
    await h.app.close()
  })

  describe('admission', () => {
    // A key holding the declared scope is admitted, past a global user-JWT guard, and the handler
    // receives the principal.
    it('admits a valid key and hands the handler its principal', async () => {
      const { key, record } = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      const res = await get(h, '/machine/videos', key)
      expect(res.status).toBe(200)
      expect(res.body).toEqual({ label: 'automation', keyId: record.id })
    })

    // A POST route with a different scope works the same way.
    it('admits a key on a route declaring another scope', async () => {
      const { key } = await h.keys.issue({ label: 'automation', scopes: ['operate'] })
      const res = await request(h.app.getHttpServer()).post('/machine/videos').set('x-api-key', key)
      expect(res.status).toBe(201)
    })

    // A route needing two scopes admits only a key holding both.
    it('requires every declared scope', async () => {
      const one = await h.keys.issue({ label: 'one', scopes: ['read'] })
      const both = await h.keys.issue({ label: 'both', scopes: ['read', 'operate'] })
      expectAuthError(
        await get(h, '/machine/both', one.key),
        AUTH_ERROR_CODES.API_KEY_SCOPE_INSUFFICIENT
      )
      expect((await get(h, '/machine/both', both.key)).status).toBe(200)
    })

    // Holding admin does not imply read: there is no hierarchy.
    it('does not let admin stand in for another scope', async () => {
      const { key } = await h.keys.issue({ label: 'boss', scopes: ['admin'] })
      expectAuthError(
        await get(h, '/machine/videos', key),
        AUTH_ERROR_CODES.API_KEY_SCOPE_INSUFFICIENT
      )
    })
  })

  describe('"public" never means "unauthenticated" on a service-key route', () => {
    // The route skips the user JWT guard, so ONLY the key guard stands in front of it.
    it('refuses a request with no key even though a global JwtAuthGuard is bound', async () => {
      expectAuthError(await get(h, '/machine/videos'), AUTH_ERROR_CODES.API_KEY_INVALID)
    })

    it('refuses an invalid key', async () => {
      expectAuthError(await get(h, '/machine/videos', 'bak_nope'), AUTH_ERROR_CODES.API_KEY_INVALID)
    })

    // A user session is not a machine credential, in any header it might be sent in.
    it('refuses a user bearer token presented instead of a key', async () => {
      const jwt = 'eyJhbGciOiJIUzI1NiJ9.e30.signature'
      const res = await request(h.app.getHttpServer())
        .get('/machine/videos')
        .set('Authorization', `Bearer ${jwt}`)
        .set('x-api-key', jwt)
      expectAuthError(res, AUTH_ERROR_CODES.API_KEY_INVALID)
    })

    // And the other way round: a valid key does not authenticate a USER route, where the global
    // guard still demands a JWT.
    it('does not let a valid key authenticate a user route', async () => {
      const { key } = await h.keys.issue({ label: 'automation', scopes: ['admin'] })
      const res = await request(h.app.getHttpServer()).get('/user/profile').set('x-api-key', key)
      expectAuthError(res, AUTH_ERROR_CODES.TOKEN_INVALID)
    })
  })

  describe('fail closed', () => {
    // The key guard is bound but nothing declares scopes: refused whatever is presented, and the
    // store is never consulted.
    it('refuses a bound route that declares no scopes, even for a valid key', async () => {
      const { key } = await h.keys.issue({ label: 'automation', scopes: ['admin'] })
      h.repo.calls.length = 0
      expectAuthError(await get(h, '/machine/undeclared', key), AUTH_ERROR_CODES.FORBIDDEN)
      expectAuthError(await get(h, '/machine/undeclared'), AUTH_ERROR_CODES.FORBIDDEN)
      expect(h.repo.calls).toEqual([])
      expect(h.events.map((e) => e.reason)).toEqual(['route_undeclared', 'route_undeclared'])
    })

    // A store outage denies; it never admits and it never leaks the cause.
    it('denies every request while the store is down', async () => {
      const { key } = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      h.repo.failWith = new Error('connection refused to db.internal:5432')
      const res = await get(h, '/machine/videos', key)
      expect(res.status).toBe(500)
      expect(JSON.stringify(res.body)).not.toContain('db.internal')
    })
  })

  describe('no oracle', () => {
    // Every way a credential can fail answers with the identical status and body, so the caller
    // cannot tell an unknown key from a wrong secret, a revoked key or a malformed header.
    it('answers byte-identically for every kind of bad credential', async () => {
      const live = await h.keys.issue({ label: 'live', scopes: ['read'] })
      const revoked = await h.keys.issue({ label: 'revoked', scopes: ['read'] })
      await h.keys.revoke(revoked.record.id)
      const wrongSecret = `${live.key.slice(0, -1)}${live.key.endsWith('A') ? 'B' : 'A'}`
      const unknownId = live.key.replace(live.record.id, '5a1d9e40-7b3c-4f6a-8c21-0e9d4b6a3f12')

      const answers = await Promise.all(
        [undefined, 'garbage', unknownId, wrongSecret, revoked.key].map((k) =>
          get(h, '/machine/videos', k)
        )
      )
      for (const answer of answers) {
        expectAuthError(answer, AUTH_ERROR_CODES.API_KEY_INVALID)
        expect(answer.body).toEqual(answers[0]?.body)
      }
      // The operator still learns which it was.
      expect(h.events.map((e) => e.reason).sort()).toEqual(
        ['malformed', 'missing', 'revoked', 'unknown', 'wrong_secret'].sort()
      )
    })
  })

  describe('lifecycle', () => {
    // Revocation is read on every request, so it takes effect on the very next one.
    it('stops admitting a key the instant it is revoked', async () => {
      const { key, record } = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      expect((await get(h, '/machine/videos', key)).status).toBe(200)
      await h.keys.revoke(record.id)
      expectAuthError(await get(h, '/machine/videos', key), AUTH_ERROR_CODES.API_KEY_INVALID)
    })

    // Rotation with an overlap: both keys work, then the old one is retired.
    it('keeps the old key working during a rotation overlap and retires it after', async () => {
      const first = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      const second = await h.keys.rotate(first.record.id, { overlapSeconds: 3600 })
      expect(second.record.label).toBe('automation')
      expect((await get(h, '/machine/videos', first.key)).status).toBe(200)
      expect((await get(h, '/machine/videos', second.key)).status).toBe(200)
      await h.keys.revoke(first.record.id)
      expectAuthError(await get(h, '/machine/videos', first.key), AUTH_ERROR_CODES.API_KEY_INVALID)
      expect((await get(h, '/machine/videos', second.key)).status).toBe(200)
    })

    // Rotation with no overlap retires the old key immediately.
    it('retires the old key at once when there is no overlap', async () => {
      const first = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      const second = await h.keys.rotate(first.record.id, { overlapSeconds: 0 })
      expectAuthError(await get(h, '/machine/videos', first.key), AUTH_ERROR_CODES.API_KEY_INVALID)
      expect((await get(h, '/machine/videos', second.key)).status).toBe(200)
    })
  })

  describe('last-used tracking', () => {
    // Fifty guarded requests cost the store no write; one flush records the key once.
    it('writes nothing per request and one batch on flush', async () => {
      const { key, record } = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      h.repo.calls.length = 0
      for (let i = 0; i < 50; i++) await get(h, '/machine/videos', key)
      expect(h.repo.calls.filter((c) => c === 'touchLastUsed')).toEqual([])
      expect(h.repo.rows.get(record.id)?.lastUsedAt).toBeNull()

      await h.app.get(ApiKeyLastUsedService, { strict: false }).flush()
      expect(h.repo.calls.filter((c) => c === 'touchLastUsed')).toHaveLength(1)
      expect(h.repo.rows.get(record.id)?.lastUsedAt).toBeInstanceOf(Date)
    })
  })

  describe('audit hook', () => {
    // Every guarded request yields exactly one event, admitted ones included, naming the label and
    // the route PATTERN.
    it('reports label, method and route pattern for every request', async () => {
      const { key } = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      await get(h, '/machine/videos', key)
      await get(h, '/machine/videos')
      expect(h.events).toHaveLength(2)
      expect(h.events[0]).toMatchObject({
        outcome: 'allowed',
        label: 'automation',
        method: 'GET',
        route: '/machine/videos',
        requiredScopes: ['read']
      })
      expect(h.events[1]).toMatchObject({ outcome: 'denied', reason: 'missing', label: null })
    })

    // Nothing the caller sent that is secret reaches the event.
    it('never carries the presented key', async () => {
      const { key } = await h.keys.issue({ label: 'automation', scopes: ['read'] })
      await get(h, '/machine/videos', key)
      await get(h, '/machine/admin', key)
      expect(JSON.stringify(h.events)).not.toContain(key.split('_')[2])
    })
  })

  describe('rate limiting on the verified key (README example)', () => {
    // The limit is bucketed by the verified key id, not the address: two keys behind one address
    // do not share a budget, and one key cannot spend the other's.
    it('limits each key separately once it has verified', async () => {
      const a = await h.keys.issue({ label: 'a', scopes: ['read'] })
      const b = await h.keys.issue({ label: 'b', scopes: ['read'] })
      const statuses: number[] = []
      for (let i = 0; i < 4; i++) statuses.push((await get(h, '/machine/limited', a.key)).status)
      expect(statuses).toEqual([200, 200, 200, 429])
      expect((await get(h, '/machine/limited', b.key)).status).toBe(200)
    })

    // A request that fails verification never reaches the throttler, so garbage cannot burn a
    // real key's budget; flooding is the per-address layer's job and is documented as such.
    it('does not charge a key for a request that failed verification', async () => {
      const a = await h.keys.issue({ label: 'a', scopes: ['read'] })
      for (let i = 0; i < 6; i++) {
        expectAuthError(
          await get(h, '/machine/limited', 'garbage'),
          AUTH_ERROR_CODES.API_KEY_INVALID
        )
      }
      expect((await get(h, '/machine/limited', a.key)).status).toBe(200)
    })
  })
})
