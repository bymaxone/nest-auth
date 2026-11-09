/**
 * End-to-end bound on a refresh token carried by cookie.
 *
 * A refresh token is opaque and its length is bounded by the wire contract: a body value over the
 * bound is refused with a 400 before any lookup, and the cookie is held to the same bound, since no
 * token this library mints is longer and an oversize value can only be junk or an attack. These
 * specs drive the real HTTP stack in cookie delivery, and in `both`, where the cookie is read first.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp, expectAuthError, type BootstrappedTestApp } from './setup'

/** The longest refresh token the wire contract admits. */
const MAX_LENGTH = 2048

describe.each(['cookie', 'both'] as const)('a refresh cookie, in %s delivery (E2E)', (delivery) => {
  let boot: BootstrappedTestApp
  let app: INestApplication

  beforeAll(async () => {
    boot = await bootstrapTestApp({ tokenDelivery: delivery })
    app = boot.app
  })

  afterAll(async () => {
    await app.close()
  })

  /** A new account's cookies, as the `Cookie` header a browser would send. */
  async function signUp(email: string): Promise<{ header: string; accessCookie: string }> {
    const res = await request(app.getHttpServer()).post('/register').send({
      email,
      password: 'SuperSecret123!',
      name: 'Cookie User',
      tenantId: 'tenant-1'
    })
    const set = (res.headers['set-cookie'] as unknown as string[]).map((line) => line.split(';')[0])
    const access = set.find((pair) => pair?.startsWith('access_token=')) ?? ''
    return { header: set.join('; '), accessCookie: access }
  }

  async function liveSessions(): Promise<number> {
    return (await boot.redis.keys('*rt:*')).length
  }

  // Scenario: refresh with a cookie over the bound. Expected: 400 validation naming the field, not
  // the 401 an unknown token earns, and no session touched. Why: the value cannot be a token this
  // library minted, so it is refused before the store is asked about it.
  it('answers refresh with 400 validation for a cookie over the bound', async () => {
    const session = await signUp(`cookie-refresh-${delivery}@example.com`)
    const before = await liveSessions()

    const res = await request(app.getHttpServer())
      .post('/refresh')
      .set('Cookie', `refresh_token=${'a'.repeat(MAX_LENGTH + 1)}`)

    expectAuthError(res, 'auth.validation')
    const details = (res.body as { error: { details: { field: string }[] } }).error.details
    expect(details.map((d) => d.field)).toEqual(['refreshToken'])
    expect(await liveSessions()).toBe(before)
    expect(session.header).not.toBe('')
  })

  // Scenario: logout from a browser whose refresh cookie is over the bound, while a real session
  // exists elsewhere. Expected: 204 and both auth cookies cleared, as for any unusable token, and
  // the real session is untouched. Why: the junk cookie shadows the real one, and logout is the
  // way out of that state, so it must neither refuse nor revoke a session it cannot name.
  it('answers logout with 204 and clears the cookies for a cookie over the bound', async () => {
    await signUp(`cookie-logout-${delivery}@example.com`)
    const before = await liveSessions()

    const res = await request(app.getHttpServer())
      .post('/logout')
      .set('Cookie', `refresh_token=${'a'.repeat(MAX_LENGTH + 1)}`)

    expect(res.status).toBe(204)
    const cleared = (res.headers['set-cookie'] as unknown as string[]).filter(
      (line) => /max-age=0/i.test(line) || /expires=thu, 01 jan 1970/i.test(line)
    )
    expect(cleared.map((line) => line.split('=')[0]).sort()).toEqual(
      expect.arrayContaining(['access_token', 'refresh_token'])
    )
    expect(await liveSessions()).toBe(before)
  })

  // Scenario: a cookie of exactly the bound. Expected: it is a well-formed but unknown token, so
  // refresh answers 401 and not 400. Why: the bound is inclusive.
  it('treats a cookie of exactly the bound as a token, not as a malformed value', async () => {
    const res = await request(app.getHttpServer())
      .post('/refresh')
      .set('Cookie', `refresh_token=${'a'.repeat(MAX_LENGTH)}`)

    expect(res.status).toBe(401)
  })
})
