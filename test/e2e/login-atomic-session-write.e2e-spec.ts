/**
 * @fileoverview A session is born whole or not at all.
 *
 * A login writes the refresh record, the session index and family, the recent-authentication
 * mark and the session detail. If the later records could fail after the first had committed, the
 * caller would be told the login failed while a live session nobody holds stayed behind.
 */
import request from 'supertest'

import { BYMAX_AUTH_OPTIONS } from '../../src/server/bymax-auth.constants'
import { sessionIndexKey } from '../../src/server/constants/user-keys'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp } from './setup'

const CREDENTIALS = {
  email: 'nobody@example.com',
  password: 'SetupSecret123!',
  tenantId: 'tenant-1'
}

/** An app with sessions on and one registered account, so a login has a user to sign in. */
async function appWithAccount(sessionsEnabled = true): Promise<BootstrappedTestApp> {
  const boot = await bootstrapTestApp(
    {
      tokenDelivery: 'bearer',
      sessions: sessionsEnabled ? { enabled: true, defaultMaxSessions: 5 } : { enabled: false }
    },
    sessionsEnabled ? {} : { controllers: { auth: true, mfa: true, passwordReset: true } }
  )
  await request(boot.app.getHttpServer())
    .post('/register')
    .send({ ...CREDENTIALS, name: 'Setup User' })
  return boot
}

/** How many keys of one family the app's namespace holds, e.g. `rt`, `sd`, `ra`. */
async function count(boot: BootstrappedTestApp, family: string): Promise<number> {
  const ns = boot.app.get<{ redisNamespace: string }>(BYMAX_AUTH_OPTIONS).redisNamespace
  return (await boot.redis.keys(`${ns}:${family}:*`)).length
}

describe('a session is born whole or not at all (E2E)', () => {
  // Scenario: every ordinary write to the store rejects while one login runs (the atomic session
  // script is not an ordinary write). Expected: if the login answers an error, no refresh record
  // was left behind. Why: an error answer must not leave a live session nobody holds.
  it('leaves no live session behind when the login is answered with an error', async () => {
    const boot = await appWithAccount()
    const before = await count(boot, 'rt')
    const spy = jest
      .spyOn(boot.app.get(AuthRedisService), 'set')
      .mockRejectedValue(new Error('write failed'))

    const res = await request(boot.app.getHttpServer()).post('/login').send(CREDENTIALS)
    spy.mockRestore()
    const after = await count(boot, 'rt')
    await boot.app.close()

    if (res.status >= 400) expect(after).toBe(before)
    else expect(after).toBe(before + 1)
  })

  // Scenario: the account's session index holds a value of the wrong type, so adding the new
  // session to it fails inside the script. Expected: the login is answered with an error and no
  // refresh record was left behind. Why: Redis does not undo the writes a script made before one of
  // its commands fails, so the commands that can fail on a wrong type must run before the session
  // record exists.
  it('leaves no live session behind when the index write fails inside the script', async () => {
    const boot = await appWithAccount()
    const opts = boot.app.get<{ hmacKey: string; redisNamespace: string }>(BYMAX_AUTH_OPTIONS)
    const index = `${opts.redisNamespace}:${sessionIndexKey('dashboard', 'user-1', opts.hmacKey, 'tenant-1')}`
    await boot.redis.del(index)
    await boot.redis.set(index, 'not-a-set')
    const before = await count(boot, 'rt')

    const res = await request(boot.app.getHttpServer()).post('/login').send(CREDENTIALS)
    const after = await count(boot, 'rt')
    await boot.app.close()

    expect(res.status).toBeGreaterThanOrEqual(400)
    expect(after).toBe(before)
  })

  // Scenario: an ordinary login. Expected: the refresh record, the session detail and the
  // recent-authentication mark all exist; the first two live as long as the refresh token and the
  // mark for the five minutes it counts as recent. Why: the mark, the detail and the session commit
  // together, and a mark that lived as long as the refresh token would undo its freshness.
  it('writes the refresh record, the detail and the mark together, each with its own lifetime', async () => {
    const boot = await appWithAccount()
    const known = new Set(await boot.redis.keys('*'))

    const res = await request(boot.app.getHttpServer()).post('/login').send(CREDENTIALS)
    const born = (await boot.redis.keys('*')).filter((key) => !known.has(key))
    const ttlOf = async (family: string): Promise<number> => {
      const key = born.find((k) => k.split(':')[1] === family)
      return key === undefined ? -2 : await boot.redis.ttl(key)
    }
    const lifetimes = { rt: await ttlOf('rt'), sd: await ttlOf('sd'), ra: await ttlOf('ra') }
    await boot.app.close()

    expect(res.status).toBe(200)
    expect(lifetimes.ra).toBeGreaterThan(0)
    expect(lifetimes.ra).toBeLessThanOrEqual(300)
    expect(lifetimes.rt).toBeGreaterThan(300)
    expect(lifetimes.sd).toBeGreaterThan(300)
  })

  // Scenario: sessions are switched off. Expected: no detail record is written.
  // Why: the detail belongs to the session list, which does not exist in that configuration.
  it('writes no session detail when sessions are off', async () => {
    const boot = await appWithAccount(false)
    await request(boot.app.getHttpServer()).post('/login').send(CREDENTIALS)
    const details = await count(boot, 'sd')
    await boot.app.close()

    expect(details).toBe(0)
  })
})
