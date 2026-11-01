/**
 * End-to-end logout when the store refuses a revocation write.
 *
 * Logout promises that the caller's credentials stop working. When the store refuses one of the
 * writes that keep that promise, the route must not answer success and must not clear the
 * caller's cookies, because the caller has to be able to retry: a retried logout completes, and
 * after it the access token is refused. These specs drive the real HTTP stack over a Redis whose
 * writes can be refused on demand, for both identity planes.
 */

import type { INestApplication } from '@nestjs/common'
import type Redis from 'ioredis'
import request from 'supertest'

import { BYMAX_AUTH_REDIS_CLIENT } from '../../src/server/bymax-auth.constants'
import { PasswordService } from '../../src/server/services/password.service'
import {
  bootstrapTestApp,
  createMockRedis,
  expectAuthError,
  type BootstrappedTestApp
} from './setup'

const REFUSED = 'OOM command not allowed when used memory > maxmemory'

/** Which commands the store currently refuses, by command and key. */
interface Refusal {
  command: string
  keyPart: string
}

/** A Redis whose writes matching `refusal.current` fail the way a store at its memory limit does. */
function flaky(redis: Redis, refusal: { current: Refusal | null }): Redis {
  return new Proxy(redis, {
    get(target, prop, receiver): unknown {
      const value: unknown = Reflect.get(target, prop, receiver)
      if (typeof value !== 'function') return value
      return (...args: unknown[]): unknown => {
        const active = refusal.current
        if (active !== null && String(prop) === active.command) {
          const key = String(args[0])
          if (key.includes(active.keyPart)) return Promise.reject(new Error(REFUSED))
        }
        return (value as (...a: unknown[]) => unknown).apply(target, args)
      }
    }
  })
}

/** The `name=value` pairs of the cookies a response set, ready to send back. */
function cookieHeader(res: request.Response): string {
  const raw = res.headers['set-cookie'] as unknown as string[] | undefined
  return (raw ?? []).map((line) => line.split(';')[0]).join('; ')
}

/** Whether a response clears any cookie (`Max-Age=0` or an expiry in the past). */
function clearsCookies(res: request.Response): boolean {
  const raw = (res.headers['set-cookie'] as unknown as string[] | undefined) ?? []
  return raw.some((line) => /max-age=0/i.test(line) || /expires=thu, 01 jan 1970/i.test(line))
}

describe('logout when the store refuses a revocation write (E2E)', () => {
  describe('dashboard plane, cookie delivery', () => {
    let boot: BootstrappedTestApp
    let app: INestApplication
    let store: Redis
    const refusal: { current: Refusal | null } = { current: null }
    let cookies: string

    beforeEach(async () => {
      refusal.current = null
      store = createMockRedis()
      boot = await bootstrapTestApp(
        { tokenDelivery: 'cookie' },
        {
          mutateBuilder: (builder) =>
            builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(flaky(store, refusal))
        }
      )
      app = boot.app
      const registered = await request(app.getHttpServer()).post('/register').send({
        email: 'logout-refused@example.com',
        password: 'SuperSecret123!',
        name: 'Logout User',
        tenantId: 'tenant-1'
      })
      expect(registered.status).toBe(201)
      cookies = cookieHeader(registered)
    })

    afterEach(async () => {
      await app.close()
    })

    // Scenario: the store refuses the access-token blacklist write. Expected: logout answers a 5xx,
    // clears no cookie, and the refresh session is still removed, so the failure leaves nothing
    // alive that the caller cannot also retry away. Why: a 204 with the cookies cleared would tell
    // the caller they are signed out while the access token still works until it expires.
    it('should answer a 5xx and keep the cookies when the blacklist write is refused', async () => {
      refusal.current = { command: 'set', keyPart: 'rv:' }

      const res = await request(app.getHttpServer()).post('/logout').set('Cookie', cookies)

      expect(res.status).toBeGreaterThanOrEqual(500)
      expect(clearsCookies(res)).toBe(false)
      const remaining = await store.keys('*rt:*')
      expect(remaining).toEqual([])
    })

    // Scenario: the same logout retried once the store accepts writes. Expected: 204, the cookies
    // are cleared, and the access token is now refused. Why: the client was told the logout failed
    // and kept its cookies precisely so that this retry works.
    it('should complete on retry and then refuse the access token', async () => {
      refusal.current = { command: 'set', keyPart: 'rv:' }
      const failed = await request(app.getHttpServer()).post('/logout').set('Cookie', cookies)
      expect(failed.status).toBeGreaterThanOrEqual(500)

      refusal.current = null
      const retried = await request(app.getHttpServer()).post('/logout').set('Cookie', cookies)

      expect(retried.status).toBe(204)
      expect(clearsCookies(retried)).toBe(true)
      const me = await request(app.getHttpServer()).get('/me').set('Cookie', cookies)
      expectAuthError(me, 'auth.token_invalid')
    })

    // Scenario: the store refuses the refresh-key delete instead. Expected: a 5xx and no cookie
    // cleared, while the access token is already refused (its blacklist write went through).
    it('should answer a 5xx and keep the cookies when the refresh key delete is refused', async () => {
      refusal.current = { command: 'del', keyPart: 'rt:' }

      const res = await request(app.getHttpServer()).post('/logout').set('Cookie', cookies)

      expect(res.status).toBeGreaterThanOrEqual(500)
      expect(clearsCookies(res)).toBe(false)
      const me = await request(app.getHttpServer()).get('/me').set('Cookie', cookies)
      expectAuthError(me, 'auth.token_invalid')
    })
  })

  describe('platform plane, bearer delivery', () => {
    let boot: BootstrappedTestApp
    let app: INestApplication
    let store: Redis
    const refusal: { current: Refusal | null } = { current: null }
    let accessToken: string
    let refreshToken: string

    beforeEach(async () => {
      refusal.current = null
      store = createMockRedis()
      boot = await bootstrapTestApp(
        { platform: { enabled: true } },
        {
          controllers: {
            auth: true,
            mfa: true,
            passwordReset: true,
            sessions: true,
            platform: true
          },
          mutateBuilder: (builder) =>
            builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(flaky(store, refusal))
        }
      )
      app = boot.app
      const passwordHash = await app.get(PasswordService).hash('PlatformPass123!')
      boot.platformRepo.seed({
        id: 'platform-admin-1',
        email: 'admin@platform.test',
        name: 'Platform Tester',
        passwordHash,
        role: 'SUPER_ADMIN',
        status: 'active',
        mfaEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: null
      })
      const login = await request(app.getHttpServer())
        .post('/platform/login')
        .send({ email: 'admin@platform.test', password: 'PlatformPass123!' })
      expect(login.status).toBe(200)
      const body = login.body as { accessToken: string; refreshToken: string }
      accessToken = body.accessToken
      refreshToken = body.refreshToken
    })

    afterEach(async () => {
      await app.close()
    })

    const logout = (): request.Test =>
      request(app.getHttpServer())
        .post('/platform/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ refreshToken })

    // Scenario: the store refuses the blacklist write. Expected: a 5xx, the refresh session is
    // still removed, and a retry once the store recovers completes and refuses the access token.
    it('should answer a 5xx, still remove the refresh session, and complete on retry', async () => {
      refusal.current = { command: 'set', keyPart: 'rv:' }

      const failed = await logout()

      expect(failed.status).toBeGreaterThanOrEqual(500)
      expect(await store.keys('*prt:*')).toEqual([])

      refusal.current = null
      const retried = await logout()

      expect(retried.status).toBe(204)
      const me = await request(app.getHttpServer())
        .get('/platform/me')
        .set('Authorization', `Bearer ${accessToken}`)
      expectAuthError(me, 'auth.token_invalid')
    })

    // Scenario: the store refuses the refresh-key delete. Expected: a 5xx; the access token was
    // already blacklisted, so it is refused even before the retry.
    it('should answer a 5xx when the refresh key delete is refused', async () => {
      refusal.current = { command: 'del', keyPart: 'prt:' }

      const failed = await logout()

      expect(failed.status).toBeGreaterThanOrEqual(500)
      const me = await request(app.getHttpServer())
        .get('/platform/me')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(me.status).toBe(401)
    })
  })
})
