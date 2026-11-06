/**
 * End-to-end handling of a refresh token that is present but malformed.
 *
 * Every route that reads the refresh token from the request body reads it through one place, and
 * what that place does with a value that is not a token decides what the client is told. A value
 * that is not a string, is empty, or exceeds the contract's opaque-token bound is not a missing
 * token: treating it as one would answer 401 on refresh, 204 on logout while the refresh session
 * stayed alive, and 404 on revoke-all. These specs drive the real HTTP stack for the dashboard
 * and platform routes and assert the answer and the side effect, because a 204 that leaves a
 * session alive is the failure this exists to prevent.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp, expectAuthError, type BootstrappedTestApp } from './setup'

/** The longest refresh token the wire contract admits. */
const MAX_LENGTH = 2048

/** Values a client can send that are present but not a usable token. */
const MALFORMED: [label: string, value: unknown][] = [
  ['an empty string', ''],
  ['a number', 123],
  ['an object', { a: 1 }],
  ['an array', ['x']],
  ['a string over the bound', 'a'.repeat(MAX_LENGTH + 1)]
]

/** Values that mean "no token": omitted, or JSON null. */
const NO_TOKEN: [label: string, body: Record<string, unknown>][] = [
  ['omitted', {}],
  ['null', { refreshToken: null }]
]

interface Session {
  authorization: string
  refreshToken: string
}

describe('a present but malformed refreshToken (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let sequence = 0

  beforeAll(async () => {
    boot = await bootstrapTestApp(
      { tokenDelivery: 'bearer', platform: { enabled: true } },
      {
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true }
      }
    )
    app = boot.app
  })

  afterAll(async () => {
    await app.close()
  })

  /** A new account with a live session, so a side effect is attributable to one request. */
  async function signUp(): Promise<Session> {
    sequence += 1
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({
        email: `malformed${sequence}@example.com`,
        password: 'SuperSecret123!',
        name: 'Malformed User',
        tenantId: 'tenant-1'
      })
    const body = res.body as { accessToken: string; refreshToken: string }
    return { authorization: `Bearer ${body.accessToken}`, refreshToken: body.refreshToken }
  }

  /** How many refresh sessions the store holds, to see that a request revoked none. */
  async function liveSessions(): Promise<number> {
    return (await boot.redis.keys('*rt:*')).length
  }

  function expectNamesTheField(res: request.Response): void {
    expectAuthError(res, 'auth.validation')
    const details = (res.body as { error: { details: { field: string }[] } }).error.details
    expect(details.map((d) => d.field)).toEqual(['refreshToken'])
  }

  describe.each(MALFORMED)('when the token is %s', (_label, value) => {
    // Scenario: refresh with a malformed token. Expected: 400 validation naming the field, not
    // the 401 a missing or unknown token earns, so the client learns its request was wrong.
    it('answers refresh with 400 validation', async () => {
      const res = await request(app.getHttpServer()).post('/refresh').send({ refreshToken: value })

      expectNamesTheField(res)
    })

    // Scenario: logout of a real session, carrying its access token, with a malformed refresh
    // token. Expected: 400, and NOTHING happened: the access token works and the refresh
    // session is in place. Why: a 204 here would tell the client it is signed out while the
    // refresh token it holds keeps working.
    it('answers logout with 400 and changes nothing', async () => {
      const session = await signUp()
      const before = await liveSessions()

      const res = await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', session.authorization)
        .send({ refreshToken: value })

      expectNamesTheField(res)
      expect(await liveSessions()).toBe(before)
      const me = await request(app.getHttpServer())
        .get('/me')
        .set('Authorization', session.authorization)
      expect(me.status).toBe(200)
    })

    // Scenario: revoke-all with a malformed current-session token. Expected: 400 and no session
    // revoked, in place of a misleading "session not found".
    it('answers revoke-all with 400 and revokes nothing', async () => {
      const session = await signUp()
      const before = await liveSessions()

      const res = await request(app.getHttpServer())
        .post('/sessions/revoke-all')
        .set('Authorization', session.authorization)
        .send({ refreshToken: value })

      expectNamesTheField(res)
      expect(await liveSessions()).toBe(before)
    })

    // Scenario: the platform plane reads its token from the body in every delivery mode.
    // Expected: the same 400 on both of its routes.
    it('answers the platform refresh and logout with 400 validation', async () => {
      const refresh = await request(app.getHttpServer())
        .post('/platform/refresh')
        .send({ refreshToken: value })
      const logout = await request(app.getHttpServer())
        .post('/platform/logout')
        .send({ refreshToken: value })

      expectNamesTheField(refresh)
      expectNamesTheField(logout)
    })
  })

  describe.each(NO_TOKEN)('when the token is %s', (_label, body) => {
    // Scenario: no token at all. Expected: unchanged. Refresh refuses with 401, logout is the
    // best-effort 204, and revoke-all cannot tell which session is current, so 404.
    it('keeps the answers for a missing token', async () => {
      const refresh = await request(app.getHttpServer()).post('/refresh').send(body)
      const session = await signUp()
      const logout = await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', session.authorization)
        .send(body)
      const other = await signUp()
      const revokeAll = await request(app.getHttpServer())
        .post('/sessions/revoke-all')
        .set('Authorization', other.authorization)
        .send(body)

      expectAuthError(refresh, 'auth.refresh_token_invalid')
      expect(logout.status).toBe(204)
      expectAuthError(revokeAll, 'auth.session_not_found')
    })
  })

  // Scenario: a token of exactly the longest admitted length. Expected: it is a well-formed
  // value, so it reaches the service and is refused there as an unknown token (401), not 400.
  it('treats a token of exactly the bound as well formed', async () => {
    const res = await request(app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: 'a'.repeat(MAX_LENGTH) })

    expectAuthError(res, 'auth.refresh_token_invalid')
  })

  // Scenario: a body that is a JSON array. Expected: it carries no `refreshToken`, so it is a
  // missing token and not a malformed one.
  it('treats an array body as a missing token', async () => {
    const res = await request(app.getHttpServer())
      .post('/refresh')
      .set('Content-Type', 'application/json')
      .send('[1]')

    expectAuthError(res, 'auth.refresh_token_invalid')
  })

  // Scenario: a real token on logout. Expected: it revokes the session, so the validation does
  // not touch the working path.
  it('signs out a real session', async () => {
    const session = await signUp()
    const before = await liveSessions()

    const res = await request(app.getHttpServer())
      .post('/logout')
      .set('Authorization', session.authorization)
      .send({ refreshToken: session.refreshToken })

    expect(res.status).toBe(204)
    expect(await liveSessions()).toBe(before - 1)
  })
})

describe('a junk body refreshToken in cookie delivery (E2E)', () => {
  let app: INestApplication
  let cookies: string

  beforeAll(async () => {
    const boot = await bootstrapTestApp({ tokenDelivery: 'cookie' })
    app = boot.app
    const registered = await request(app.getHttpServer()).post('/register').send({
      email: 'cookie-mode@example.com',
      password: 'SuperSecret123!',
      name: 'Cookie User',
      tenantId: 'tenant-1'
    })
    // The login cookies are `Secure`, which supertest does not send over plain http, so they are
    // forwarded by hand.
    cookies = (registered.headers['set-cookie'] as unknown as string[])
      .map((line) => line.split(';')[0])
      .join('; ')
  })

  afterAll(async () => {
    await app.close()
  })

  // Scenario: the delivery mode reads the refresh token from the cookie, so the body field is not
  // read at all. Expected: a junk value there changes no answer. Refresh rotates the session, and
  // no 400 appears for a field the mode does not use.
  it.each(MALFORMED)('ignores %s in the body and refreshes from the cookie', async (_l, value) => {
    const res = await request(app.getHttpServer())
      .post('/refresh')
      .set('Cookie', cookies)
      .send({ refreshToken: value })

    expect(res.status).toBe(200)
    cookies = (res.headers['set-cookie'] as unknown as string[])
      .map((line) => line.split(';')[0])
      .join('; ')
  })
})
