/**
 * End-to-end plane check of the platform MFA challenge.
 *
 * An MFA temp token names the identity plane it was issued for. The platform route serves the
 * platform plane only, so a dashboard token presented there must be refused before anything is
 * spent: the challenge consumes the token, burns the TOTP code, issues tokens, stores a session,
 * stamps the last login and fires the hooks, and a refusal that arrives after all of that leaves
 * an orphan session nobody holds the token for, hooks that reported a login that never answered,
 * and a user who has to start over.
 */

import * as crypto from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import type { IAuthHooks } from '../../src/server/interfaces/auth-hooks.interface'
import { bootstrapTestApp, expectAuthError } from './setup'

const PASSWORD = 'SetupSecret123!'
const EMAIL = 'plane@example.com'
const TENANT = 'tenant-1'

describe('platform MFA challenge refuses a dashboard token before spending anything (E2E)', () => {
  let app: INestApplication
  let redis: Awaited<ReturnType<typeof bootstrapTestApp>>['redis']
  let repo: Awaited<ReturnType<typeof bootstrapTestApp>>['repo']
  let secret: string
  const hookCalls: string[] = []

  beforeAll(async () => {
    const hooks: IAuthHooks = {
      afterLogin: () => {
        hookCalls.push('afterLogin')
      },
      onNewSession: () => {
        hookCalls.push('onNewSession')
      }
    }
    const boot = await bootstrapTestApp(
      { tokenDelivery: 'bearer', platform: { enabled: true } },
      {
        controllers: { auth: true, mfa: true, platform: true },
        extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }]
      }
    )
    app = boot.app
    redis = boot.redis
    repo = boot.repo

    const register = await request(app.getHttpServer())
      .post('/register')
      .send({ email: EMAIL, password: PASSWORD, name: 'Plane', tenantId: TENANT })
    const accessToken = register.body.accessToken as string
    const setup = await request(app.getHttpServer())
      .post('/mfa/setup')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: PASSWORD })
    secret = setup.body.secret as string
    await request(app.getHttpServer())
      .post('/mfa/verify-enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ code: generateTotp(secret) })
      .expect(204)
  })

  afterAll(async () => {
    await app.close()
  })

  async function sessionCount(): Promise<number> {
    return (await redis.keys('*sd:*')).length
  }

  function lastLoginOf(): number {
    const user = [...repo.users.values()].find((candidate) => candidate.email === EMAIL)
    return user?.lastLoginAt?.getTime() ?? 0
  }

  // Scenario: a user with MFA logs in at the dashboard, then the temp token and a valid code are
  // presented at the platform challenge route. Expected: the route answers PLATFORM_AUTH_REQUIRED
  // and has spent nothing: the session count, the last login and the hooks are as they were, and
  // the same token and code still complete the challenge at the dashboard route that issued it.
  it('spends no session, login stamp, hook or token on the refusal', async () => {
    const login = await request(app.getHttpServer())
      .post('/login')
      .send({ email: EMAIL, password: PASSWORD, tenantId: TENANT })
      .expect(200)
    const tempToken = login.body.mfaTempToken as string
    expect(tempToken).toEqual(expect.any(String))
    // The next window: enabling MFA already spent the current one (TOTP anti-replay).
    const code = generateTotp(secret, Date.now() + TOTP_STEP_SECONDS * 1_000)

    const sessionsBefore = await sessionCount()
    const lastLoginBefore = lastLoginOf()
    const hooksBefore = hookCalls.length

    const refused = await request(app.getHttpServer())
      .post('/platform/mfa/challenge')
      .send({ mfaTempToken: tempToken, code })

    expectAuthError(refused, 'auth.platform_auth_required')
    // Measured now, before the redeem below issues a session of its own.
    const spent = {
      newSessions: (await sessionCount()) - sessionsBefore,
      lastLoginStamped: lastLoginOf() !== lastLoginBefore,
      hookCalls: hookCalls.length - hooksBefore
    }
    const redeemed = await request(app.getHttpServer())
      .post('/mfa/challenge')
      .send({ mfaTempToken: tempToken, code })

    // One object, so a failure shows everything the refusal spent rather than the first thing.
    expect({ ...spent, redeemStatus: redeemed.status }).toEqual({
      newSessions: 0,
      lastLoginStamped: false,
      hookCalls: 0,
      redeemStatus: 200
    })
  })

  // Scenario: wrong codes are submitted with a dashboard token at the platform route, more often
  // than the lockout threshold. Expected: every one is refused for its plane, none counts as a
  // failed attempt, and the dashboard challenge with the right code still succeeds. Why: the
  // refusal must not touch the brute-force counter, or anyone holding a dashboard token could
  // lock its owner out through the other plane's route.
  it('does not count refused attempts toward the brute-force counter', async () => {
    const login = await request(app.getHttpServer())
      .post('/login')
      .send({ email: EMAIL, password: PASSWORD, tenantId: TENANT })
      .expect(200)
    const tempToken = login.body.mfaTempToken as string

    for (let attempt = 1; attempt <= 8; attempt += 1) {
      const refused = await request(app.getHttpServer())
        .post('/platform/mfa/challenge')
        .send({ mfaTempToken: tempToken, code: '000000' })
      expectAuthError(refused, 'auth.platform_auth_required')
    }

    // The previous window: the other scenario used the next one, enabling used the current one.
    const redeemed = await request(app.getHttpServer())
      .post('/mfa/challenge')
      .send({
        mfaTempToken: tempToken,
        code: generateTotp(secret, Date.now() - TOTP_STEP_SECONDS * 1_000)
      })
    expect(redeemed.status).toBe(200)
  })
})

// ---------------------------------------------------------------------------
// TOTP helper (RFC 6238), self-contained like the other MFA specs
// ---------------------------------------------------------------------------

const TOTP_STEP_SECONDS = 30
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function generateTotp(base32Secret: string, time: number = Date.now()): string {
  const key = base32Decode(base32Secret)
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(Math.floor(time / 1000 / TOTP_STEP_SECONDS)))
  const hmac = crypto.createHmac('sha1', key).update(buf).digest()
  const offset = (hmac[hmac.length - 1] as number) & 0x0f
  const code =
    (((hmac[offset] as number) & 0x7f) << 24) |
    (((hmac[offset + 1] as number) & 0xff) << 16) |
    (((hmac[offset + 2] as number) & 0xff) << 8) |
    ((hmac[offset + 3] as number) & 0xff)
  return (code % 10 ** 6).toString().padStart(6, '0')
}

function base32Decode(input: string): Buffer {
  const bytes: number[] = []
  let bits = 0
  let value = 0
  for (const c of input.replace(/=+$/, '').toUpperCase()) {
    const idx = BASE32_ALPHABET.indexOf(c)
    if (idx < 0) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}
