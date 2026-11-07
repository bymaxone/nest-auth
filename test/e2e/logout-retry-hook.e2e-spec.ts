/**
 * @fileoverview Proves a logout that needed a retry still announces itself, exactly once, to the
 * account that signed out.
 *
 * A logout attempts every revocation write and answers 5xx when any failed. The refresh session
 * is deleted by the first attempt, so the retry must recover whose logout it is from the pending
 * marker, and must announce it. These cases fail a revocation write once and then drive the retry
 * over real HTTP:
 *
 *   - the retry completes the logout and fires `afterLogout` once, for the right account;
 *   - a repeat after that does not fire it again;
 *   - retries racing each other fire it once between them;
 *   - the dashboard and the platform plane behave the same way.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import type { HookContext, IAuthHooks } from '../../src/server/interfaces/auth-hooks.interface'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import { PasswordService } from '../../src/server/services/password.service'
import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

interface LogoutCall {
  userId: string
  context: HookContext
}

/**
 * A hook set that records every logout announcement and nothing else: `afterLogout` for the
 * dashboard plane and `afterPlatformLogout` for the platform plane. The context's `plane` tells
 * them apart.
 */
function recordingHooks(): { hooks: IAuthHooks; calls: LogoutCall[] } {
  const calls: LogoutCall[] = []
  const record = (userId: string, context: HookContext): void => {
    calls.push({ userId, context })
  }
  const hooks: IAuthHooks = { afterLogout: record, afterPlatformLogout: record }
  return { hooks, calls }
}

/** Makes the next write of an access-token blacklist entry reject, once. */
function failBlacklistOnce(app: INestApplication): void {
  const redis = app.get(AuthRedisService)
  const set = redis.set.bind(redis)
  let failed = false
  jest.spyOn(redis, 'set').mockImplementation(async (key: string, value: string, ttl?: number) => {
    if (key.startsWith('rv:') && !failed) {
      failed = true
      throw new Error('ECONNRESET')
    }
    return set(key, value, ttl)
  })
}

describe('a logout that needed a retry (E2E)', () => {
  let boot: BootstrappedTestApp
  let calls: LogoutCall[]

  beforeEach(async () => {
    const recorder = recordingHooks()
    calls = recorder.calls
    boot = await bootstrapTestApp(
      { tokenDelivery: 'bearer', sessions: { enabled: true }, platform: { enabled: true } },
      {
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true },
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_HOOKS).useValue(recorder.hooks) as typeof builder
      }
    )
  })

  afterEach(async () => {
    await boot.app.close()
  })

  describe('dashboard', () => {
    async function signIn(): Promise<{ accessToken: string; refreshToken: string }> {
      const res = await request(boot.app.getHttpServer()).post('/register').send({
        email: 'retry-hook@example.com',
        password: 'RetryHook123!-xyz',
        name: 'Retry Hook',
        tenantId: 'tenant-1'
      })
      expect(res.status).toBe(201)
      return res.body as { accessToken: string; refreshToken: string }
    }

    const logout = (tokens: { accessToken: string; refreshToken: string }): request.Test =>
      request(boot.app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .send({ refreshToken: tokens.refreshToken })

    // Scenario: a revocation write fails on the first attempt and the retry completes. Expected:
    // the first answer is a 5xx with no hook, the retry is 204, and the hook fires once, naming
    // the account and its tenant. Why: the retry completed the logout, and the session record that
    // would have named its owner was deleted by the first attempt.
    it('fires afterLogout once, for the right account, when the retry completes it', async () => {
      const tokens = await signIn()
      failBlacklistOnce(boot.app)

      const first = await logout(tokens)
      expect(first.status).toBeGreaterThanOrEqual(500)
      expect(calls).toHaveLength(0)

      const retry = await logout(tokens)

      expect(retry.status).toBe(204)
      expect(calls).toHaveLength(1)
      expect(calls[0]?.context).toMatchObject({ plane: 'dashboard', tenantId: 'tenant-1' })
      expect(calls[0]?.userId).toBe(calls[0]?.context.userId)
      expect(calls[0]?.userId).toBeTruthy()
    })

    // Scenario: the same logout repeated after it succeeded. Expected: still one hook. Why: a
    // double click or a retry after a lost response must not announce the logout twice.
    it('does not fire it again when the completed logout is repeated', async () => {
      const tokens = await signIn()
      failBlacklistOnce(boot.app)
      await logout(tokens)
      await logout(tokens)

      const repeat = await logout(tokens)

      expect(repeat.status).toBe(204)
      expect(calls).toHaveLength(1)
    })

    // Scenario: two retries race after a failed first attempt. Expected: one hook between them.
    it('fires it once when retries race each other', async () => {
      const tokens = await signIn()
      failBlacklistOnce(boot.app)
      await logout(tokens)

      const [a, b] = await Promise.all([logout(tokens), logout(tokens)])

      expect([a.status, b.status]).toEqual([204, 204])
      expect(calls).toHaveLength(1)
    })

    // Scenario: a logout with nothing behind it, a session that never existed and no earlier
    // attempt. Expected: 204 and no hook, since there is nobody to name.
    it('stays silent for a logout nothing had started', async () => {
      const tokens = await signIn()
      await logout(tokens)
      calls.length = 0

      const stranger = await request(boot.app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .send({ refreshToken: 'f'.repeat(64) })

      expect(stranger.status).toBe(204)
      expect(calls).toHaveLength(0)
    })

    // Scenario: an ordinary logout. Expected: one hook, as always; the retry path adds nothing.
    it('still fires afterLogout once for a logout that needed no retry', async () => {
      const tokens = await signIn()

      const res = await logout(tokens)

      expect(res.status).toBe(204)
      expect(calls).toHaveLength(1)
    })
  })

  describe('platform', () => {
    async function platformSignIn(): Promise<{ accessToken: string; refreshToken: string }> {
      const passwordHash = await boot.app.get(PasswordService).hash('PlatformRetry123!-xyz')
      boot.platformRepo.seed({
        id: 'platform-admin-retry',
        email: 'platform-retry@example.com',
        name: 'Platform Retry',
        passwordHash,
        role: 'SUPER_ADMIN',
        status: 'active',
        mfaEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: null
      })
      const res = await request(boot.app.getHttpServer())
        .post('/platform/login')
        .send({ email: 'platform-retry@example.com', password: 'PlatformRetry123!-xyz' })
      expect(res.status).toBe(200)
      return res.body as { accessToken: string; refreshToken: string }
    }

    const logout = (tokens: { accessToken: string; refreshToken: string }): request.Test =>
      request(boot.app.getHttpServer())
        .post('/platform/logout')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .send({ refreshToken: tokens.refreshToken })

    // The same three outcomes on the platform plane: a failed first attempt is silent, the
    // completing retry announces once for the administrator, and a repeat adds nothing.
    it('fires afterLogout once for the administrator, and not again on a repeat', async () => {
      const tokens = await platformSignIn()
      failBlacklistOnce(boot.app)

      const first = await logout(tokens)
      expect(first.status).toBeGreaterThanOrEqual(500)
      expect(calls).toHaveLength(0)

      const retry = await logout(tokens)
      expect(retry.status).toBe(204)
      expect(calls).toHaveLength(1)
      expect(calls[0]?.userId).toBe('platform-admin-retry')
      expect(calls[0]?.context).toMatchObject({ plane: 'platform' })

      await logout(tokens)
      expect(calls).toHaveLength(1)
    })

    it('fires it once when platform retries race each other', async () => {
      const tokens = await platformSignIn()
      failBlacklistOnce(boot.app)
      await logout(tokens)

      await Promise.all([logout(tokens), logout(tokens)])

      expect(calls).toHaveLength(1)
    })
  })
})
