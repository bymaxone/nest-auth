/**
 * @fileoverview `POST …/mfa/setup` with no body answers exactly as it does for `{}`.
 *
 * `password` is optional on purpose: an account provisioned through OAuth has no local password
 * and needs none, so an absent body and an empty object are the same request and must get the
 * same answer.
 */
import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { PasswordService } from '../../src/server/services/password.service'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp } from './setup'

const PLATFORM_EMAIL = 'admin@platform.test'
const PLATFORM_PASSWORD = 'PlatformPass123!'

interface Answer {
  status: number
  body: Record<string, unknown>
}

/** What a route answered for the given body; `undefined` sends no body at all. */
async function answer(
  app: INestApplication,
  path: string,
  token: string,
  body: object | undefined
): Promise<Answer> {
  const req = request(app.getHttpServer()).post(path).set('Authorization', `Bearer ${token}`)
  const res = body === undefined ? await req : await req.send(body)
  return { status: res.status, body: res.body as Record<string, unknown> }
}

/** A dashboard user with a password, or an OAuth-only one when `oauthOnly` is set. */
async function dashboardUser(
  oauthOnly: boolean
): Promise<{ boot: BootstrappedTestApp; token: string }> {
  const boot = await bootstrapTestApp({ tokenDelivery: 'bearer' })
  const reg = await request(boot.app.getHttpServer()).post('/register').send({
    email: 'nobody@example.com',
    password: 'SetupSecret123!',
    name: 'Setup User',
    tenantId: 'tenant-1'
  })
  const { user, accessToken } = reg.body as { user: { id: string }; accessToken: string }
  if (oauthOnly) {
    const stored = boot.repo.users.get(user.id)
    if (stored === undefined) throw new Error('registered user missing from the repository')
    boot.repo.users.set(user.id, { ...stored, passwordHash: null })
  }
  return { boot, token: accessToken }
}

async function platformAdmin(): Promise<{ boot: BootstrappedTestApp; token: string }> {
  const boot = await bootstrapTestApp(
    { platform: { enabled: true } },
    { controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true } }
  )
  const passwordHash = await boot.app.get(PasswordService).hash(PLATFORM_PASSWORD)
  boot.platformRepo.seed({
    id: 'platform-admin-1',
    email: PLATFORM_EMAIL,
    name: 'Platform Tester',
    passwordHash,
    role: 'SUPER_ADMIN',
    status: 'active',
    mfaEnabled: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    lastLoginAt: null
  })
  const login = await request(boot.app.getHttpServer())
    .post('/platform/login')
    .send({ email: PLATFORM_EMAIL, password: PLATFORM_PASSWORD })
  return { boot, token: (login.body as { accessToken: string }).accessToken }
}

describe('POST …/mfa/setup without a body (E2E)', () => {
  // Scenario: a dashboard account with a local password, once with no body and once with `{}`.
  // Expected: the same status and the same error body (a password is required and none was sent).
  // Why: an absent body and an empty object are the same request.
  it('answers a password account without a body as it answers {}', async () => {
    const bare = await dashboardUser(false)
    const empty = await dashboardUser(false)

    const withoutBody = await answer(bare.boot.app, '/mfa/setup', bare.token, undefined)
    const withEmpty = await answer(empty.boot.app, '/mfa/setup', empty.token, {})

    await bare.boot.app.close()
    await empty.boot.app.close()
    expect(withEmpty.status).toBe(401)
    expect(withoutBody).toEqual(withEmpty)
  })

  // Scenario: an OAuth-only dashboard account (no local password), no body versus `{}`. Expected:
  // both succeed and carry the same fields. Why: this account needs no password, so refusing a
  // bodyless call would leave it unable to enable MFA from a client that sends none.
  it('lets an OAuth-only account set up MFA without a body, as with {}', async () => {
    const bare = await dashboardUser(true)
    const empty = await dashboardUser(true)

    const withoutBody = await answer(bare.boot.app, '/mfa/setup', bare.token, undefined)
    const withEmpty = await answer(empty.boot.app, '/mfa/setup', empty.token, {})

    await bare.boot.app.close()
    await empty.boot.app.close()
    expect(withEmpty.status).toBe(201)
    expect(withoutBody.status).toBe(201)
    expect(Object.keys(withoutBody.body).sort()).toEqual(Object.keys(withEmpty.body).sort())
  })

  // Scenario: the platform surface, a password account, no body versus `{}`. Expected: the same
  // status and body as for the dashboard route. Why: the platform handler reads `dto.password`
  // the same way, so it needs the same guarantee.
  it('answers a platform admin without a body as it answers {}', async () => {
    const bare = await platformAdmin()
    const empty = await platformAdmin()

    const withoutBody = await answer(bare.boot.app, '/platform/mfa/setup', bare.token, undefined)
    const withEmpty = await answer(empty.boot.app, '/platform/mfa/setup', empty.token, {})

    await bare.boot.app.close()
    await empty.boot.app.close()
    expect(withEmpty.status).toBe(401)
    expect(withoutBody).toEqual(withEmpty)
  })
})
