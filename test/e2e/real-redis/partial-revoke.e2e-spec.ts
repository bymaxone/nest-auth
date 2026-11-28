/**
 * @fileoverview A revocation a REAL Redis refuses part-way, then the same call again.
 *
 * The refusal is the server's own: the application connects as an ACL user whose write access to
 * one key family is taken away for the first call and given back for the retry. Only a real server
 * refuses a key a script declares, and a command a script runs.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import Redis from 'ioredis'
import request from 'supertest'

import { BYMAX_AUTH_REDIS_CLIENT } from '../../../src/server/bymax-auth.constants'
import { AuthRedisService } from '../../../src/server/redis/auth-redis.service'
import { MfaService } from '../../../src/server/services/mfa.service'
import { PasswordService } from '../../../src/server/services/password.service'
import { SessionService } from '../../../src/server/services/session.service'
import { bootstrapTestApp, type BootstrappedTestApp } from '../setup'

const PASSWORD = 'PartialRevoke123!-xyz'
const TENANT = 'tenant-1'
const ACL_USER = 'partial-revoke'
const ACL_PASSWORD = 'partial-revoke-secret'

/** Every key family the library writes, so one can be left read-only while the rest stay open. */
const FAMILIES = (
  'account cf dashboard ec pcf ep fam inv invidx lf lp mfa mfalock os otp pep pfam platform plp prp ' +
  'prt prvs psd psess ra rcu resend revoked rl rp rt rv rvs sd sess tu uev us wad wads wie winv ' +
  'winvidx winvrl winvset wir wm wms wmv wsp wst wsv'
).split(' ')

interface Tokens {
  accessToken: string
  refreshToken: string
}

const hashOf = (token: string): string => createHash('sha256').update(token).digest('hex')

describe('a revocation the store refuses part-way (real Redis)', () => {
  let boot: BootstrappedTestApp
  let client: Redis
  let sequence = 0

  /** Gives the application's user write access to every key family but the ones named. */
  async function refuseWrites(...families: string[]): Promise<void> {
    const namespace = boot.options.redisNamespace as string
    const keys = FAMILIES.map(
      (family) => `${families.includes(family) ? '%R' : ''}~${namespace}:${family}:*`
    )
    await boot.redis.call('ACL', 'SETUSER', ACL_USER, 'resetkeys', ...keys)
  }

  beforeEach(async () => {
    const url = new URL(process.env['BYMAX_E2E_REDIS_URL'] as string)
    const admin = new Redis(url.href)
    await admin.call(
      'ACL',
      'SETUSER',
      ACL_USER,
      'reset',
      'on',
      `>${ACL_PASSWORD}`,
      '~*',
      '&*',
      '+@all'
    )
    admin.disconnect()
    client = new Redis(url.href, { username: ACL_USER, password: ACL_PASSWORD })
    boot = await bootstrapTestApp(
      { platform: { enabled: true } },
      {
        controllers: { auth: true, sessions: true, platform: true, mfa: true },
        mutateBuilder: (builder) =>
          builder.overrideProvider(BYMAX_AUTH_REDIS_CLIENT).useValue(client)
      }
    )
    await refuseWrites()
  })

  afterEach(async () => {
    await boot.app.close()
    client.disconnect()
  })

  const server = (): ReturnType<BootstrappedTestApp['app']['getHttpServer']> =>
    boot.app.getHttpServer()

  async function register(): Promise<Tokens & { userId: string; email: string }> {
    sequence += 1
    const email = `partial-${sequence}@example.com`
    const res = await request(server())
      .post('/register')
      .send({ email, password: PASSWORD, name: 'Partial', tenantId: TENANT })
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
      id: 'platform-admin-partial',
      email: 'partial-admin@example.com',
      name: 'Partial Admin',
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
      .send({ email: 'partial-admin@example.com', password: PASSWORD })
    expect(res.status).toBe(200)
    return res.body as Tokens
  }

  async function refreshStatus(path: string, tokens: Tokens): Promise<number> {
    const res = await request(server()).post(path).send({ refreshToken: tokens.refreshToken })
    return res.status
  }

  /** Presents one refresh token twice inside its grace window: two live sessions of one sign-in. */
  async function siblings(path: string, first: Tokens): Promise<[Tokens, Tokens]> {
    const rotate = async (): Promise<Tokens> => {
      const res = await request(server()).post(path).send({ refreshToken: first.refreshToken })
      expect(res.status).toBe(200)
      return res.body as Tokens
    }
    return [await rotate(), await rotate()]
  }

  async function statusOf(path: string, tokens: Tokens): Promise<number> {
    const res = await request(server())
      .get(path)
      .set('Authorization', `Bearer ${tokens.accessToken}`)
    return res.status
  }

  async function revoke(caller: Tokens, target: Tokens): Promise<number> {
    const res = await request(server())
      .delete(`/sessions/${hashOf(target.refreshToken)}`)
      .set('Authorization', `Bearer ${caller.accessToken}`)
    return res.status
  }

  /** Rewrites a session record as one written before families existed. */
  async function forgetFamily(tokens: Tokens): Promise<void> {
    const redis = boot.app.get(AuthRedisService)
    const key = `rt:${hashOf(tokens.refreshToken)}`
    const record = JSON.parse((await redis.get(key)) ?? '') as Record<string, unknown>
    delete record['familyId']
    await redis.set(key, JSON.stringify(record), 600)
  }

  // Scenario: one of two sessions of a sign-in is revoked while the store refuses the family or the
  // access entry, and the call is repeated once it accepts writes. Expected: the first call fails and
  // the retry ends both. Why: a retry that finds the named session gone cannot reach its sibling,
  // which would keep refreshing after a revocation reported as done.
  it.each(['fam', 'rvs'])('ends the whole sign-in on the retry when %s is refused', async (key) => {
    const account = await register()
    const caller = await login(account.email)
    const [target, sibling] = await siblings('/refresh', account)

    await refuseWrites(key)
    expect(await revoke(caller, target)).toBeGreaterThanOrEqual(500)
    await refuseWrites()
    expect(await revoke(caller, target)).toBe(204)

    expect(await statusOf('/me', target)).toBe(401)
    expect(await statusOf('/me', sibling)).toBe(401)
    expect(await refreshStatus('/refresh', target)).toBe(401)
    expect(await refreshStatus('/refresh', sibling)).toBe(401)
    expect(await statusOf('/me', caller)).toBe(200)
  })

  // Scenario: one session is revoked while the server is over its memory limit. Expected: the sign-in
  // is removed all the same. Why: Redis refuses a script whose first write adds data, and runs one
  // that has already freed some, so the entry must not be what the script writes first.
  it('ends the sign-in of a revoked session when the server is out of memory', async () => {
    const account = await register()
    const [target, sibling] = await siblings('/refresh', account)
    const sessionHash = hashOf(target.refreshToken)

    await boot.redis.call('CONFIG', 'SET', 'maxmemory', '1')
    try {
      await boot.app
        .get(SessionService)
        .revokeSession({ userId: account.userId, tenantId: TENANT, sessionHash })
    } finally {
      await boot.redis.call('CONFIG', 'SET', 'maxmemory', '0')
    }

    expect(await refreshStatus('/refresh', target)).toBe(401)
    expect(await refreshStatus('/refresh', sibling)).toBe(401)
    expect(await statusOf('/me', sibling)).toBe(401)
  })

  // Scenario: a session whose record names no family is revoked while the store refuses the epoch.
  // Expected: the retry removes it and refuses its access tokens. Why: removing the session first
  // leaves the retry nothing to find, and those access tokens would then be reported as ended.
  it('advances the epoch on the retry of a session that names no family', async () => {
    const account = await register()
    const caller = await login(account.email)
    await forgetFamily(account)

    await refuseWrites('ep')
    expect(await revoke(caller, account)).toBeGreaterThanOrEqual(500)
    await refuseWrites()
    expect(await revoke(caller, account)).toBe(204)

    expect(await statusOf('/me', account)).toBe(401)
    expect(await refreshStatus('/refresh', account)).toBe(401)
  })

  // Scenario: an account names another account's session, one with a family and one without.
  // Expected: not found, and neither account loses anything. Why: the entry, the family and the epoch
  // are written only for a session the caller's own index holds.
  it.each([false, true])('writes nothing for a session of another account (%s)', async (legacy) => {
    const owner = await register()
    const stranger = await register()
    if (legacy) await forgetFamily(owner)

    expect(await revoke(stranger, owner)).toBe(404)

    expect(await statusOf('/me', owner)).toBe(200)
    expect(await statusOf('/me', stranger)).toBe(200)
    expect(await refreshStatus('/refresh', owner)).toBe(200)
  })

  /** Registers or signs in on a plane, and answers two sessions of that sign-in with its logout. */
  async function signedInTwice(path: string, refresh: string) {
    const first = path === '/logout' ? await register() : await platformLogin()
    const [mine, sibling] = await siblings(refresh, first)
    const out = async (): Promise<number> => {
      const res = await request(server())
        .post(path)
        .set('Authorization', `Bearer ${mine.accessToken}`)
        .send({ refreshToken: mine.refreshToken })
      return res.status
    }
    return { mine, sibling, out }
  }

  // Scenario: a logout the store refuses to finish, with or without room for the marker a retry
  // reads, then the same logout again once the marker is gone, as its expiry leaves it, or at once.
  // Expected: the retry ends both sessions. Why: a retry that finds neither the session nor the
  // marker has no owner and answers success with the sibling live.
  it.each([
    ['/logout', '/refresh', ['fam'], 'lp', true],
    ['/logout', '/refresh', ['fam'], 'lp', false],
    ['/logout', '/refresh', ['fam', 'lp'], 'lp', false],
    ['/platform/logout', '/platform/refresh', ['pfam'], 'plp', true],
    ['/platform/logout', '/platform/refresh', ['pfam'], 'plp', false],
    ['/platform/logout', '/platform/refresh', ['pfam', 'plp'], 'plp', false]
  ] as const)(
    '%s ends the sign-in on a retry (refused %#)',
    async (path, refresh, refused, marker, expired) => {
      const { mine, sibling, out } = await signedInTwice(path, refresh)

      await refuseWrites(...refused)
      expect(await out()).toBeGreaterThanOrEqual(500)
      await refuseWrites()
      if (expired) {
        const namespace = boot.options.redisNamespace as string
        await boot.redis.call('DEL', `${namespace}:${marker}:${hashOf(mine.refreshToken)}`)
      }
      expect(await out()).toBe(204)

      expect(await refreshStatus(refresh, mine)).toBe(401)
      expect(await refreshStatus(refresh, sibling)).toBe(401)
    }
  )

  // Scenario: a logout whose family removal is applied and whose access entry is refused, repeated.
  // Expected: the retry writes the entry, so the sibling's access token is refused. Why: the removal
  // took the session the owner was read from, and a retry with no marker answers success without it.
  it.each([
    ['/logout', '/refresh', '/me', 'rvs'],
    ['/platform/logout', '/platform/refresh', '/platform/me', 'prvs']
  ] as const)('%s writes the refused entry on a retry', async (path, refresh, me, refused) => {
    const { mine, sibling, out } = await signedInTwice(path, refresh)

    await refuseWrites(refused)
    expect(await out()).toBeGreaterThanOrEqual(500)
    await refuseWrites()
    // Until the retry, the entry is missing and only the refresh is refused.
    expect(await statusOf(me, sibling)).toBe(200)
    expect(await out()).toBe(204)

    expect(await statusOf(me, sibling)).toBe(401)
    expect(await refreshStatus(refresh, sibling)).toBe(401)
  })

  // Scenario: a logout refused both its access entry and the marker, then repeated. Expected: the
  // documented limit: the repeat answers success, refresh is refused and the sibling's access token
  // is accepted. Why: the family removal took the session, and nothing names the owner.
  it.each([
    ['/logout', '/refresh', '/me', ['rvs', 'lp']],
    ['/platform/logout', '/platform/refresh', '/platform/me', ['prvs', 'plp']]
  ] as const)('%s leaves access tokens to expire', async (path, refresh, me, refused) => {
    const { mine, sibling, out } = await signedInTwice(path, refresh)

    await refuseWrites(...refused)
    expect(await out()).toBeGreaterThanOrEqual(500)
    await refuseWrites()
    expect(await out()).toBe(204)

    expect(await statusOf(me, sibling)).toBe(200)
    expect(await refreshStatus(refresh, sibling)).toBe(401)
  })

  // Scenario: a logout answered with an error and not repeated. Expected: the presented token still
  // refreshes. Why: the session stays findable until a retry ends its sign-in.
  it.each([
    ['/logout', '/refresh', 'fam'],
    ['/platform/logout', '/platform/refresh', 'pfam']
  ] as const)('%s keeps the presented session until a retry', async (path, refresh, refused) => {
    const { mine, out } = await signedInTwice(path, refresh)

    await refuseWrites(refused)
    expect(await out()).toBeGreaterThanOrEqual(500)
    await refuseWrites()

    expect(await refreshStatus(refresh, mine)).toBe(200)
  })

  // Scenario: an MFA reset that clears the factor and then cannot end the sessions, repeated once
  // the store accepts writes. Expected: the retry ends them. Why: the retry reads an account with no
  // factor, and answering without revoking would report a reset whose sessions are still live.
  it.each(['sess', 'ep'])(
    'ends the sessions on a repeated reset when %s was refused',
    async (key) => {
      const account = await register()
      await boot.repo.updateMfa({
        id: account.userId,
        tenantId: TENANT,
        data: { mfaEnabled: true, mfaSecret: 'x', mfaRecoveryCodes: [] }
      })
      const reset = (): Promise<void> =>
        boot.app.get(MfaService).resetMfa(account.userId, 'dashboard', TENANT)

      await refuseWrites(key)
      await expect(reset()).rejects.toThrow()
      await refuseWrites()
      await reset()

      expect(await statusOf('/me', account)).toBe(401)
      expect(await refreshStatus('/refresh', account)).toBe(401)
    }
  )
})
