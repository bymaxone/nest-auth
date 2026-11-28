/**
 * @fileoverview Proves `onSessionsRevoked` is fired by every path that revokes a session, on both
 * identity planes: one row per path, each driven against the real module and an in-memory store.
 *
 * A host that keeps its own state per session (open sockets, a cache, an audit trail) can only keep
 * it correct if no revocation is silent. The rows are the whole list of paths; a new one belongs
 * here.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import { generateHotp } from '../../src/server/crypto/totp'
import type { IAuthHooks } from '../../src/server/interfaces/auth-hooks.interface'
import type { SessionsRevokedEvent } from '../../src/server/interfaces/auth-hooks.interface'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import { AuthService } from '../../src/server/services/auth.service'
import { MfaService } from '../../src/server/services/mfa.service'
import { PasswordResetService } from '../../src/server/services/password-reset.service'
import { PasswordService } from '../../src/server/services/password.service'
import { PlatformAuthService } from '../../src/server/services/platform-auth.service'
import { SessionService } from '../../src/server/services/session.service'
import { FROZEN_CLOCK_MS, bootstrapTestApp, freezeClock, restoreClock } from './setup'
import type { BootstrappedTestApp } from './setup'

const PASSWORD = 'RevokeHook123!-xyz'
const TENANT = 'tenant-1'
const ADMIN_ID = 'platform-admin-revoke'

interface Tokens {
  accessToken: string
  refreshToken: string
}

interface Account extends Tokens {
  userId: string
  email: string
}

const hashOf = (token: string): string => createHash('sha256').update(token).digest('hex')

/** Lets the detached hook run before the assertion reads what it recorded. */
const settled = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

describe('onSessionsRevoked (E2E)', () => {
  let boot: BootstrappedTestApp
  let events: SessionsRevokedEvent[]
  let hookFailure: Error | undefined
  let sequence = 0

  async function start(overrides: Parameters<typeof bootstrapTestApp>[0] = {}): Promise<void> {
    events = []
    const hooks: IAuthHooks = {
      onSessionsRevoked: (event) => {
        events.push(event)
        if (hookFailure) throw hookFailure
      }
    }
    boot = await bootstrapTestApp(
      { sessions: { enabled: true }, platform: { enabled: true }, ...overrides },
      {
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true },
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_HOOKS).useValue(hooks) as typeof builder
      }
    )
  }

  afterEach(async () => {
    hookFailure = undefined
    await boot.app.close()
  })

  const server = (): ReturnType<BootstrappedTestApp['app']['getHttpServer']> =>
    boot.app.getHttpServer()

  async function register(): Promise<Account> {
    sequence += 1
    const email = `revoke-${sequence}@example.com`
    const res = await request(server())
      .post('/register')
      .send({ email, password: PASSWORD, name: 'Revoke Hook', tenantId: TENANT })
    expect(res.status).toBe(201)
    const body = res.body as Tokens & { user: { id: string } }
    await settled()
    events.length = 0
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
      email: 'revoke-admin@example.com',
      name: 'Revoke Admin',
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
      .send({ email: 'revoke-admin@example.com', password: PASSWORD })
    expect(res.status).toBe(200)
    return res.body as Tokens
  }

  const bearer = (tokens: Tokens): [string, string] => [
    'Authorization',
    `Bearer ${tokens.accessToken}`
  ]

  /** The one event the operation produced. */
  async function onlyEvent(): Promise<SessionsRevokedEvent> {
    await settled()
    expect(events).toHaveLength(1)
    return events[0] as SessionsRevokedEvent
  }

  describe('dashboard', () => {
    beforeEach(() => start())

    it('fires on logout', async () => {
      const account = await register()
      await request(server())
        .post('/logout')
        .set(...bearer(account))
        .send({ refreshToken: account.refreshToken })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'logout',
        sessionIds: [hashOf(account.refreshToken)]
      })
    })

    it('fires on revoking one session over HTTP', async () => {
      const account = await register()
      const other = await login(account.email)
      events.length = 0

      await request(server())
        .delete(`/sessions/${hashOf(other.refreshToken)}`)
        .set(...bearer(account))
        .send({ refreshToken: account.refreshToken })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'session_revoked',
        sessionIds: [hashOf(other.refreshToken)]
      })
    })

    it('fires on a direct SessionService.revokeSession call', async () => {
      const account = await register()

      await boot.app.get(SessionService).revokeSession({
        userId: account.userId,
        tenantId: TENANT,
        sessionHash: hashOf(account.refreshToken)
      })

      expect(await onlyEvent()).toMatchObject({
        reason: 'session_revoked',
        sessionIds: [hashOf(account.refreshToken)]
      })
    })

    it('fires once on revoking every other session', async () => {
      const account = await register()
      const second = await login(account.email)
      const third = await login(account.email)
      events.length = 0

      await request(server())
        .post('/sessions/revoke-all')
        .set(...bearer(account))
        .send({ refreshToken: account.refreshToken })
        .expect(204)

      const event = await onlyEvent()
      expect(event).toMatchObject({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'other_sessions_revoked'
      })
      expect([...(event.sessionIds ?? [])].sort()).toEqual(
        [hashOf(second.refreshToken), hashOf(third.refreshToken)].sort()
      )
    })

    it('fires on AuthService.revokeAllSessions', async () => {
      const account = await register()

      await boot.app
        .get(AuthService)
        .revokeAllSessions({ userId: account.userId, tenantId: TENANT })

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'all_sessions_revoked'
      })
    })

    it('fires when a refresh finds the account gone', async () => {
      const account = await register()
      jest.spyOn(boot.repo, 'findById').mockResolvedValue(null)

      await request(server())
        .post('/refresh')
        .send({ refreshToken: account.refreshToken })
        .expect(401)

      expect(await onlyEvent()).toMatchObject({
        userId: account.userId,
        tenantId: TENANT,
        reason: 'account_unavailable'
      })
    })

    it('fires when a refresh finds the account blocked', async () => {
      const account = await register()
      const user = await boot.repo.findById({ id: account.userId, tenantId: TENANT })
      jest.spyOn(boot.repo, 'findById').mockResolvedValue({ ...user!, status: 'BANNED' })

      const res = await request(server())
        .post('/refresh')
        .send({ refreshToken: account.refreshToken })

      expect(res.status).toBe(403)
      expect(await onlyEvent()).toMatchObject({
        userId: account.userId,
        reason: 'account_unavailable'
      })
    })

    it('fires on a password change that keeps the current session', async () => {
      const account = await register()
      const other = await login(account.email)
      events.length = 0

      await request(server())
        .post('/password/change')
        .set(...bearer(account))
        .send({
          currentPassword: PASSWORD,
          newPassword: 'Changed456!-xyz',
          refreshToken: account.refreshToken
        })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'password_changed',
        sessionIds: [hashOf(other.refreshToken)]
      })
    })

    it('fires on a password change that keeps no session', async () => {
      const account = await register()

      await request(server())
        .post('/password/change')
        .set(...bearer(account))
        .send({ currentPassword: PASSWORD, newPassword: 'Changed456!-xyz' })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'password_changed'
      })
    })

    it('fires on a password reset', async () => {
      const account = await register()
      let token = ''
      boot.email.sendPasswordResetToken = async (_tenant, _to, raw): Promise<void> => {
        token = raw
      }
      await request(server())
        .post('/password/forgot-password')
        .send({ email: account.email, tenantId: TENANT })
        .expect(200)
      while (token === '') await settled()

      await request(server())
        .post('/password/reset-password')
        .send({
          email: account.email,
          tenantId: TENANT,
          token,
          newPassword: 'Changed456!-xyz'
        })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'password_reset'
      })
    })

    it('fires on a replayed refresh token', async () => {
      const account = await register()
      const rotated = await request(server())
        .post('/refresh')
        .send({ refreshToken: account.refreshToken })
        .expect(200)
      // The grace window is closed by removing its pointer, so no row has to wait it out.
      for (const key of await boot.redis.keys('*rp:*')) {
        await boot.redis.del(key.replace(/^auth:/, ''), key)
      }
      events.length = 0

      await request(server())
        .post('/refresh')
        .send({ refreshToken: account.refreshToken })
        .expect(401)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'refresh_reuse',
        sessionIds: [hashOf((rotated.body as { refreshToken: string }).refreshToken)]
      })
    })

    // The hook is the host's code: what it throws must neither fail the request nor leave the
    // session alive.
    it('keeps the revocation and the answer when the hook throws', async () => {
      const account = await register()
      hookFailure = new Error('host hook failed')

      await request(server())
        .post('/logout')
        .set(...bearer(account))
        .send({ refreshToken: account.refreshToken })
        .expect(204)

      await request(server())
        .post('/refresh')
        .send({ refreshToken: account.refreshToken })
        .expect(401)
    })

    // The sessions are already deleted when the epoch write is refused, so the event is due even
    // though the caller is told the operation failed.
    it('still fires when the sessions are deleted and the epoch write is then refused', async () => {
      const account = await register()
      jest
        .spyOn(boot.app.get(AuthRedisService), 'bumpUserTokenEpoch')
        .mockRejectedValue(new Error('READONLY'))

      await expect(
        boot.app.get(AuthService).revokeAllSessions({ userId: account.userId, tenantId: TENANT })
      ).rejects.toThrow('READONLY')

      expect(await onlyEvent()).toMatchObject({ reason: 'all_sessions_revoked' })
    })

    // The logout's first delete is refused and its metadata removal, which deletes the same key,
    // still ends the session.
    it('fires when a refused logout delete is followed by a removal that ends the session', async () => {
      const account = await register()
      const redis = boot.app.get(AuthRedisService)
      jest.spyOn(redis, 'del').mockRejectedValueOnce(new Error('READONLY'))

      await expect(
        boot.app.get(AuthService).logout(account.accessToken, account.refreshToken)
      ).rejects.toThrow('READONLY')

      expect(await onlyEvent()).toMatchObject({
        reason: 'logout',
        sessionIds: [hashOf(account.refreshToken)]
      })
      await request(server())
        .post('/refresh')
        .send({ refreshToken: account.refreshToken })
        .expect(401)
    })

    it('does not fire when the store refuses the deletion itself', async () => {
      const account = await register()
      jest
        .spyOn(boot.app.get(AuthRedisService), 'invalidateUserSessions')
        .mockRejectedValue(new Error('READONLY'))

      await expect(
        boot.app.get(AuthService).revokeAllSessions({ userId: account.userId, tenantId: TENANT })
      ).rejects.toThrow('READONLY')

      await settled()
      expect(events).toHaveLength(0)
    })
  })

  describe('session limit', () => {
    beforeEach(() => start({ sessions: { enabled: true, defaultMaxSessions: 1 } }))

    it('fires when a login evicts a session', async () => {
      const account = await register()

      await login(account.email)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'session_evicted',
        sessionIds: [hashOf(account.refreshToken)]
      })
    })
  })

  describe('MFA transitions', () => {
    beforeEach(() => {
      freezeClock()
      return start()
    })
    afterEach(() => restoreClock())

    /** The code of the TOTP window `step` away from the frozen instant. */
    const codeAt = (secret: string, step: number): string =>
      generateHotp(secret, Math.floor(FROZEN_CLOCK_MS / 1000 / 30) + step)

    it('fires when the second factor is turned on, and again when it is turned off', async () => {
      const account = await register()
      const setup = await request(server())
        .post('/mfa/setup')
        .set(...bearer(account))
        .send({ password: PASSWORD })
      const { secret } = setup.body as { secret: string }

      await request(server())
        .post('/mfa/verify-enable')
        .set(...bearer(account))
        .send({ code: codeAt(secret, 0) })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'mfa_enabled'
      })

      const challenged = await request(server())
        .post('/login')
        .send({ email: account.email, password: PASSWORD, tenantId: TENANT })
      const verified = await request(server())
        .post('/mfa/challenge')
        .send({
          mfaTempToken: (challenged.body as { mfaTempToken: string }).mfaTempToken,
          code: codeAt(secret, 1)
        })
        .expect(200)
      events.length = 0

      await request(server())
        .post('/mfa/disable')
        .set(...bearer(verified.body as Tokens))
        .send({ code: codeAt(secret, -1) })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: account.userId,
        tenantId: TENANT,
        plane: 'dashboard',
        reason: 'mfa_disabled'
      })
    })
  })

  describe('platform', () => {
    beforeEach(() => start())

    it('fires on logout', async () => {
      const tokens = await platformLogin()

      await request(server())
        .post('/platform/logout')
        .set(...bearer(tokens))
        .send({ refreshToken: tokens.refreshToken })
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: ADMIN_ID,
        plane: 'platform',
        reason: 'logout',
        sessionIds: [hashOf(tokens.refreshToken)]
      })
    })

    it('fires on the revoke-all route', async () => {
      const tokens = await platformLogin()

      await request(server())
        .delete('/platform/sessions')
        .set(...bearer(tokens))
        .expect(204)

      expect(await onlyEvent()).toEqual({
        userId: ADMIN_ID,
        plane: 'platform',
        reason: 'all_sessions_revoked'
      })
    })

    it('fires on PlatformAuthService.revokeAllPlatformSessions', async () => {
      await platformLogin()

      await boot.app.get(PlatformAuthService).revokeAllPlatformSessions(ADMIN_ID)

      expect(await onlyEvent()).toMatchObject({ reason: 'all_sessions_revoked' })
    })

    it('fires when a refresh finds the administrator gone', async () => {
      const tokens = await platformLogin()
      jest.spyOn(boot.platformRepo, 'findById').mockResolvedValue(null)

      await request(server())
        .post('/platform/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(401)

      expect(await onlyEvent()).toEqual({
        userId: ADMIN_ID,
        plane: 'platform',
        reason: 'account_unavailable'
      })
    })

    it('fires when a refresh finds the administrator blocked', async () => {
      const tokens = await platformLogin()
      const admin = await boot.platformRepo.findById(ADMIN_ID)
      jest.spyOn(boot.platformRepo, 'findById').mockResolvedValue({ ...admin!, status: 'BANNED' })

      const res = await request(server())
        .post('/platform/refresh')
        .send({ refreshToken: tokens.refreshToken })

      expect(res.status).toBe(403)
      expect(await onlyEvent()).toMatchObject({ reason: 'account_unavailable' })
    })

    it('fires on a replayed refresh token', async () => {
      const tokens = await platformLogin()
      const rotated = await request(server())
        .post('/platform/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(200)
      for (const key of await boot.redis.keys('*prp:*')) {
        await boot.redis.del(key.replace(/^auth:/, ''), key)
      }
      events.length = 0

      await request(server())
        .post('/platform/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(401)

      expect(await onlyEvent()).toEqual({
        userId: ADMIN_ID,
        plane: 'platform',
        reason: 'refresh_reuse',
        sessionIds: [hashOf((rotated.body as { refreshToken: string }).refreshToken)]
      })
    })
  })

  // A host can call any of these directly. A method that revokes without the hook, or fires it
  // twice, breaks what the hook promises; a method added to these classes has to join a list here.
  describe('exported revocation methods', () => {
    beforeEach(() => start())

    /** The methods of a class whose name says they end sessions or credentials. */
    const revoking = (type: { prototype: object }): string[] =>
      Object.getOwnPropertyNames(type.prototype)
        .filter((name) => /^(revoke|remove|logout|reset|disable|change)/.test(name))
        .sort()

    it('are the ones these rows know about', () => {
      // `removeOthers` and the `resetWith*` methods are private steps of a listed method.
      expect(revoking(SessionService)).toEqual([
        'removeOthers',
        'revokeAllExceptCurrent',
        'revokeOtherSession',
        'revokeSession'
      ])
      expect(revoking(AuthService)).toEqual([
        'logout',
        'revokeAllSessions',
        'revokeSessionMetadata'
      ])
      expect(revoking(PlatformAuthService)).toEqual(['logout', 'revokeAllPlatformSessions'])
      expect(revoking(MfaService)).toEqual(['disable', 'resetMfa'])
      expect(revoking(PasswordResetService)).toEqual([
        'changePassword',
        'resetPassword',
        'resetWithOtp',
        'resetWithToken',
        'resetWithVerifiedToken'
      ])
    })

    it.each<[string, (account: Account) => Promise<unknown>]>([
      [
        'AuthService.logout',
        (a) => boot.app.get(AuthService).logout(a.accessToken, a.refreshToken)
      ],
      [
        'AuthService.revokeAllSessions',
        (a) => boot.app.get(AuthService).revokeAllSessions({ userId: a.userId, tenantId: TENANT })
      ],
      [
        'SessionService.revokeSession',
        (a) => boot.app.get(SessionService).revokeSession(target(a))
      ],
      [
        'SessionService.revokeOtherSession',
        (a) => boot.app.get(SessionService).revokeOtherSession(target(a))
      ],
      [
        'SessionService.revokeAllExceptCurrent',
        (a) =>
          boot.app.get(SessionService).revokeAllExceptCurrent({
            userId: a.userId,
            tenantId: TENANT,
            currentSessionHash: hashOf(a.refreshToken)
          })
      ],
      ['MfaService.resetMfa', (a) => resetEnrolled(a)]
    ])('%s fires exactly once', async (_name, revoke) => {
      const account = await register()

      await revoke(account)

      await onlyEvent()
    })

    const target = (a: Account): { userId: string; tenantId: string; sessionHash: string } => ({
      userId: a.userId,
      tenantId: TENANT,
      sessionHash: hashOf(a.refreshToken)
    })

    /** Gives the account a second factor to remove, then removes it administratively. */
    async function resetEnrolled(a: Account): Promise<void> {
      await boot.repo.updateMfa({
        id: a.userId,
        tenantId: TENANT,
        data: { mfaEnabled: true, mfaSecret: 'sealed', mfaRecoveryCodes: [] }
      })
      await boot.app.get(MfaService).resetMfa(a.userId, 'dashboard', TENANT)
    }

    it.each(['logout', 'revokeAllPlatformSessions'] as const)(
      'PlatformAuthService.%s fires exactly once',
      async (method) => {
        const tokens = await platformLogin()
        const platform = boot.app.get(PlatformAuthService)

        await (method === 'logout'
          ? platform.logout(tokens.accessToken, tokens.refreshToken)
          : platform.revokeAllPlatformSessions(ADMIN_ID))

        await onlyEvent()
      }
    )
  })
})
