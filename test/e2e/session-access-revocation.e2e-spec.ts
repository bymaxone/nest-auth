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

  async function refreshStatus(path: string, tokens: Tokens): Promise<number> {
    const res = await request(server()).post(path).send({ refreshToken: tokens.refreshToken })
    return res.status
  }

  /** Presents one refresh token twice inside its grace window: two live sessions of one sign-in. */
  async function siblings(path: string, first: Tokens): Promise<[Tokens, Tokens]> {
    return [await rotate(path, first), await rotate(path, first)]
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

  async function deleteSession(caller: Tokens, target: Tokens): Promise<void> {
    await request(server())
      .delete(`/sessions/${hashOf(target.refreshToken)}`)
      .set('Authorization', `Bearer ${caller.accessToken}`)
      .expect(204)
  }

  /** Rewrites a session record as one written before families existed. */
  async function forgetFamily(tokens: Tokens): Promise<void> {
    const redis = boot.app.get(AuthRedisService)
    const key = `rt:${hashOf(tokens.refreshToken)}`
    const record = JSON.parse((await redis.get(key)) ?? '') as Record<string, unknown>
    delete record['familyId']
    await redis.set(key, JSON.stringify(record), 600)
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

    it('ends only the session named to DELETE /sessions/:id', async () => {
      const caller = await register()
      const earlier = await login(caller.email)
      const other = await login(caller.email)
      const target = await rotate('/refresh', earlier)

      await deleteSession(caller, target)

      expect([await me(earlier), await me(target)]).toEqual([401, 401])
      expect([await me(caller), await me(other)]).toEqual([200, 200])
    })

    // A record that names no family says nothing about which access tokens came from it.
    it('ends every access token when the record of the deleted session names no family', async () => {
      const caller = await register()
      const target = await login(caller.email)
      await forgetFamily(target)

      await deleteSession(caller, target)

      expect([await me(caller), await me(target)]).toEqual([401, 401])
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

  // Two sessions of one sign-in share a `sid`, so ending one ends both: none is left able to
  // refresh into an access token that is then refused.
  describe('two sessions of one sign-in', () => {
    beforeEach(() => start())

    const named = (): string[] => events.flatMap((event) => event.sessionIds ?? [])

    it.each([
      [
        'logout',
        async (_userId: string, target: Tokens): Promise<void> => logout('/logout', target)
      ],
      [
        'SessionService.revokeSession',
        async (userId: string, target: Tokens): Promise<void> =>
          boot.app.get(SessionService).revokeSession({
            userId,
            tenantId: TENANT,
            sessionHash: hashOf(target.refreshToken)
          })
      ]
    ])('ends both when one is ended by %s', async (_name, end) => {
      const account = await register()
      const other = await login(account.email)
      const [kept, target] = await siblings('/refresh', account)

      await end(account.userId, target)
      await settled()

      expect(await refreshStatus('/refresh', kept)).toBe(401)
      expect(await me(kept)).toBe(401)
      expect([await me(other), await refreshStatus('/refresh', other)]).toEqual([200, 200])
      expect(named()).toEqual(
        expect.arrayContaining([hashOf(kept.refreshToken), hashOf(target.refreshToken)])
      )
    })

    it('ends both when one is ended by DELETE /sessions/:id', async () => {
      const account = await register()
      const caller = await login(account.email)
      const [kept, target] = await siblings('/refresh', account)

      await deleteSession(caller, target)
      await settled()

      expect(await refreshStatus('/refresh', kept)).toBe(401)
      expect(await me(kept)).toBe(401)
      expect([await me(caller), await refreshStatus('/refresh', caller)]).toEqual([200, 200])
      expect(named()).toEqual(
        expect.arrayContaining([hashOf(kept.refreshToken), hashOf(target.refreshToken)])
      )
    })

    it('ends both on the platform plane when one signs out', async () => {
      const first = await platformLogin()
      const other = await platformLogin()
      const [kept, target] = await siblings('/platform/refresh', first)

      await logout('/platform/logout', target)
      await settled()

      expect(await refreshStatus('/platform/refresh', kept)).toBe(401)
      expect(await platformMe(kept)).toBe(401)
      expect(await refreshStatus('/platform/refresh', other)).toBe(200)
      expect(named()).toEqual(
        expect.arrayContaining([hashOf(kept.refreshToken), hashOf(target.refreshToken)])
      )
    })
  })

  describe('session limit of two', () => {
    beforeEach(() => start({ defaultMaxSessions: 2 }))

    it('ends both sessions of one sign-in when the limit pushes one out', async () => {
      const account = await register()
      const pair = await siblings('/refresh', account)

      const kept = await login(account.email)
      await settled()

      expect([
        await refreshStatus('/refresh', pair[0]),
        await refreshStatus('/refresh', pair[1])
      ]).toEqual([401, 401])
      expect([await me(pair[0]), await me(pair[1]), await me(kept)]).toEqual([401, 401, 200])
    })

    // Two over the limit: ending the oldest sign-in removes both of its sessions, which is enough.
    it('ends no more sign-ins than the limit requires', async () => {
      const account = await register()
      const other = await login(account.email)
      const pair = await siblings('/refresh', account)

      const newest = await login(account.email)
      await settled()

      expect([await me(pair[0]), await me(pair[1])]).toEqual([401, 401])
      expect([await me(other), await me(newest)]).toEqual([200, 200])
      expect(await refreshStatus('/refresh', other)).toBe(200)
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
