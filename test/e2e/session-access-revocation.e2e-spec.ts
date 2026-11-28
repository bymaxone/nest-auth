/**
 * @fileoverview Proves that ending one session also ends the access tokens of that session, on both
 * identity planes: one row per path, each checking that the other sessions of the account still work.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import type {
  IAuthHooks,
  SessionsRevokedEvent
} from '../../src/server/interfaces/auth-hooks.interface'
import type { DashboardJwtPayload } from '../../src/server/interfaces/jwt-payload.interface'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import { AuthService } from '../../src/server/services/auth.service'
import { PasswordService } from '../../src/server/services/password.service'
import { SessionService } from '../../src/server/services/session.service'
import { WsTicketService } from '../../src/server/services/ws-ticket.service'
import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp } from './setup'

const PASSWORD = 'AccessRevoke123!-xyz'
const TENANT = 'tenant-1'
const ADMIN_ID = 'platform-admin-access'
const ADMIN_EMAIL = 'access-admin@example.com'

interface Tokens {
  accessToken: string
  refreshToken: string
}

const hashOf = (token: string): string => createHash('sha256').update(token).digest('hex')

/** Lets the detached hook run before the assertion reads what it recorded. */
const settled = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

describe('access tokens of an ended session (E2E)', () => {
  let boot: BootstrappedTestApp
  let events: SessionsRevokedEvent[]
  let sequence = 0

  async function start(sessions: Record<string, unknown> = {}): Promise<void> {
    events = []
    const hooks: IAuthHooks = {
      onSessionsRevoked: (event) => {
        events.push(event)
      }
    }
    boot = await bootstrapTestApp(
      { sessions: { enabled: true, ...sessions }, platform: { enabled: true } },
      {
        controllers: { auth: true, sessions: true, platform: true },
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_HOOKS).useValue(hooks) as typeof builder
      }
    )
  }

  afterEach(async () => {
    jest.restoreAllMocks()
    await boot.app.close()
  })

  const server = (): ReturnType<BootstrappedTestApp['app']['getHttpServer']> =>
    boot.app.getHttpServer()

  async function register(): Promise<Tokens & { userId: string; email: string }> {
    sequence += 1
    const email = `access-${sequence}@example.com`
    const res = await request(server())
      .post('/register')
      .send({ email, password: PASSWORD, name: 'Access', tenantId: TENANT })
    expect(res.status).toBe(201)
    const body = res.body as Tokens & { user: { id: string } }
    return { ...body, userId: body.user.id, email }
  }

  async function login(email: string): Promise<Tokens> {
    const res = await request(server())
      .post('/login')
      .send({ email, password: PASSWORD, tenantId: TENANT })
    expect(res.status).toBe(200)
    return res.body as Tokens
  }

  async function platformLogin(): Promise<Tokens> {
    const passwordHash = await boot.app.get(PasswordService).hash(PASSWORD)
    boot.platformRepo.seed({
      id: ADMIN_ID,
      email: ADMIN_EMAIL,
      name: 'Access Admin',
      passwordHash,
      role: 'SUPER_ADMIN',
      status: 'active',
      mfaEnabled: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLoginAt: null
    })
    const res = await request(server())
      .post('/platform/login')
      .send({ email: ADMIN_EMAIL, password: PASSWORD })
    expect(res.status).toBe(200)
    return res.body as Tokens
  }

  async function rotate(path: string, tokens: Tokens): Promise<Tokens> {
    const res = await request(server()).post(path).send({ refreshToken: tokens.refreshToken })
    expect(res.status).toBe(200)
    return res.body as Tokens
  }

  /** Closes the grace window by removing its pointers, so no row has to wait it out. */
  async function closeGraceWindow(): Promise<void> {
    for (const key of await boot.redis.keys('*rp:*')) {
      await boot.redis.del(key.replace(/^auth:/, ''), key)
    }
  }

  async function statusOf(path: string, tokens: Tokens): Promise<number> {
    const res = await request(server())
      .get(path)
      .set('Authorization', `Bearer ${tokens.accessToken}`)
    return res.status
  }

  const me = (tokens: Tokens): Promise<number> => statusOf('/me', tokens)
  const platformMe = (tokens: Tokens): Promise<number> => statusOf('/platform/me', tokens)

  async function logout(path: string, tokens: Tokens): Promise<void> {
    await request(server())
      .post(path)
      .set('Authorization', `Bearer ${tokens.accessToken}`)
      .send({ refreshToken: tokens.refreshToken })
      .expect(204)
  }

  describe('dashboard', () => {
    beforeEach(() => start())

    it('refuses an earlier access token of a session that signed out', async () => {
      const earlier = await register()
      const other = await login(earlier.email)
      const current = await rotate('/refresh', earlier)

      await logout('/logout', current)

      expect([await me(earlier), await me(current), await me(other)]).toEqual([401, 401, 200])
    })

    it('refuses the access tokens of a session revoked through the service', async () => {
      const earlier = await register()
      const other = await login(earlier.email)
      const current = await rotate('/refresh', earlier)

      await boot.app.get(SessionService).revokeSession({
        userId: earlier.userId,
        tenantId: TENANT,
        sessionHash: hashOf(current.refreshToken)
      })

      expect([await me(earlier), await me(current), await me(other)]).toEqual([401, 401, 200])
    })

    it('refuses the access tokens of a family whose refresh token was replayed', async () => {
      const earlier = await register()
      const other = await login(earlier.email)
      const current = await rotate('/refresh', earlier)
      await closeGraceWindow()
      await settled()
      events.length = 0

      await request(server())
        .post('/refresh')
        .send({ refreshToken: earlier.refreshToken })
        .expect(401)
      await settled()

      expect([await me(earlier), await me(current), await me(other)]).toEqual([401, 401, 200])
      expect(events).toEqual([
        {
          userId: earlier.userId,
          tenantId: TENANT,
          plane: 'dashboard',
          reason: 'refresh_reuse',
          sessionIds: [hashOf(current.refreshToken)]
        }
      ])
    })

    it('refuses a WebSocket ticket minted before its session was revoked', async () => {
      const account = await register()
      const tickets = boot.app.get(WsTicketService)
      const claims = Buffer.from(account.accessToken.split('.')[1] ?? '', 'base64url').toString()
      const { ticket } = await tickets.issue(JSON.parse(claims) as DashboardJwtPayload)

      await boot.app.get(SessionService).revokeSession({
        userId: account.userId,
        tenantId: TENANT,
        sessionHash: hashOf(account.refreshToken)
      })

      await expect(tickets.redeem(ticket, TENANT)).rejects.toMatchObject({
        response: { error: { code: 'auth.token_invalid' } }
      })
    })

    // The session record is gone after the first attempt, so only what that attempt kept can say
    // which session's access tokens the retry has to end.
    it('ends the access tokens on the retry of a logout whose revocation write was refused', async () => {
      const earlier = await register()
      const current = await rotate('/refresh', earlier)
      const redis = boot.app.get(AuthRedisService)
      const set = redis.set.bind(redis)
      const refused = jest.spyOn(redis, 'set').mockImplementation(async (key, value, ttl) => {
        if (key.startsWith('rvs:')) throw new Error('READONLY')
        await set(key, value, ttl)
      })

      await expect(
        boot.app.get(AuthService).logout(current.accessToken, current.refreshToken)
      ).rejects.toThrow('READONLY')
      refused.mockRestore()
      await boot.app.get(AuthService).logout(current.accessToken, current.refreshToken)

      expect(await me(earlier)).toBe(401)
    })
  })

  describe('session limit', () => {
    beforeEach(() => start({ defaultMaxSessions: 1 }))

    it('refuses the access token of an evicted session', async () => {
      const evicted = await register()

      const kept = await login(evicted.email)

      expect([await me(evicted), await me(kept)]).toEqual([401, 200])
    })
  })

  describe('platform', () => {
    beforeEach(() => start())

    it('refuses an earlier access token of a session that signed out', async () => {
      const earlier = await platformLogin()
      const other = await platformLogin()
      const current = await rotate('/platform/refresh', earlier)

      await logout('/platform/logout', current)

      expect([await platformMe(earlier), await platformMe(current)]).toEqual([401, 401])
      expect(await platformMe(other)).toBe(200)
    })

    it('refuses the access tokens of a family whose refresh token was replayed', async () => {
      const earlier = await platformLogin()
      const other = await platformLogin()
      const current = await rotate('/platform/refresh', earlier)
      await closeGraceWindow()

      await request(server())
        .post('/platform/refresh')
        .send({ refreshToken: earlier.refreshToken })
        .expect(401)

      expect([await platformMe(earlier), await platformMe(current)]).toEqual([401, 401])
      expect(await platformMe(other)).toBe(200)
    })
  })
})
