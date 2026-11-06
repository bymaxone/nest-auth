/**
 * End-to-end check that "all except the current session" needs a current session.
 *
 * Revoking every session but the caller's, and changing a password while ending the other
 * sessions, both take the caller's refresh token to say which session to keep. A token that is
 * well formed but names no live session of the caller keeps nothing, so the same operation
 * would revoke every session the account has, the caller's own included, and answer success. These
 * specs drive the real HTTP stack and assert the refusal AND the side effect: a stale token is
 * answered 404 before anything is changed, and for a password change that includes the password.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { PasswordService } from '../../src/server/services/password.service'
import { bootstrapTestApp, expectAuthError, type BootstrappedTestApp } from './setup'

const PASSWORD = 'SuperSecret123!'
const NEW_PASSWORD = 'AnotherSecret456!'
const TENANT = 'tenant-1'

/** A well-formed refresh token that names no session. */
const STALE_TOKEN = 'f'.repeat(64)

interface Session {
  authorization: string
  refreshToken: string
}

describe('"all except the current session" requires a live current session (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let sequence = 0

  beforeEach(async () => {
    boot = await bootstrapTestApp({ tokenDelivery: 'bearer' })
    app = boot.app
  })

  afterEach(async () => {
    await app.close()
  })

  /** A new account with its first session. */
  async function signUp(): Promise<{ email: string; first: Session }> {
    sequence += 1
    const email = `live${sequence}@example.com`
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({ email, password: PASSWORD, name: 'Live User', tenantId: TENANT })
    return { email, first: toSession(res) }
  }

  function toSession(res: request.Response): Session {
    const body = res.body as { accessToken: string; refreshToken: string }
    return { authorization: `Bearer ${body.accessToken}`, refreshToken: body.refreshToken }
  }

  async function signIn(email: string, password = PASSWORD): Promise<request.Response> {
    return request(app.getHttpServer()).post('/login').send({ email, password, tenantId: TENANT })
  }

  /** Whether a refresh token can be rotated, i.e. its session is alive. */
  async function refreshWorks(refreshToken: string): Promise<boolean> {
    const res = await request(app.getHttpServer()).post('/refresh').send({ refreshToken })
    return res.status === 200
  }

  describe('POST /sessions/revoke-all', () => {
    // Scenario: a token that is well formed but names no session. Expected: 404, and the caller's
    // own session and any other are untouched. Why: "except current" with no current session
    // would revoke everything, the caller's session included, and answer 204.
    it('refuses a token that names no live session and revokes nothing', async () => {
      const { email, first } = await signUp()
      const second = toSession(await signIn(email))

      const res = await request(app.getHttpServer())
        .post('/sessions/revoke-all')
        .set('Authorization', first.authorization)
        .send({ refreshToken: STALE_TOKEN })

      expectAuthError(res, 'auth.session_not_found')
      expect(await refreshWorks(first.refreshToken)).toBe(true)
      expect(await refreshWorks(second.refreshToken)).toBe(true)
    })

    // Scenario: the caller's real token. Expected: every OTHER session is revoked and the caller's
    // own survives, so the check does not touch the working path.
    it('revokes the other sessions and keeps the current one', async () => {
      const { email, first } = await signUp()
      const second = toSession(await signIn(email))

      const res = await request(app.getHttpServer())
        .post('/sessions/revoke-all')
        .set('Authorization', first.authorization)
        .send({ refreshToken: first.refreshToken })

      expect(res.status).toBe(204)
      expect(await refreshWorks(second.refreshToken)).toBe(false)
      expect(await refreshWorks(first.refreshToken)).toBe(true)
    })
  })

  describe('POST /password/change', () => {
    const change = (session: Session, body: object): request.Test =>
      request(app.getHttpServer())
        .post('/password/change')
        .set('Authorization', session.authorization)
        .send({ currentPassword: PASSWORD, newPassword: NEW_PASSWORD, ...body })

    // Scenario: the right password with a token that names no live session. Expected: 404 and the
    // password is UNCHANGED, the old one signs in and the new one does not, and no session is
    // revoked. Why: otherwise a stale token would change the password and then end the caller's own
    // session along with every other.
    it('refuses a stale token before the password changes', async () => {
      const { email, first } = await signUp()
      const second = toSession(await signIn(email))

      const res = await change(first, { refreshToken: STALE_TOKEN })

      expectAuthError(res, 'auth.session_not_found')
      expect((await signIn(email, PASSWORD)).status).toBe(200)
      expect((await signIn(email, NEW_PASSWORD)).status).toBe(401)
      expect(await refreshWorks(first.refreshToken)).toBe(true)
      expect(await refreshWorks(second.refreshToken)).toBe(true)
    })

    // Scenario: a wrong current password together with a stale token. Expected: 401, the answer to
    // the credential, so the session check is not reachable without the password and tells a
    // caller who does not hold it nothing about their token.
    it('answers a wrong current password before it looks at the token', async () => {
      const { first } = await signUp()

      const res = await change(first, {
        currentPassword: 'WrongPassword789!',
        refreshToken: STALE_TOKEN
      })

      expectAuthError(res, 'auth.invalid_credentials')
    })

    // Scenario: the right password and the caller's real token. Expected: the password changes, the
    // other sessions end, and the caller's own survives.
    it('changes the password and keeps only the current session', async () => {
      const { email, first } = await signUp()
      const second = toSession(await signIn(email))

      const res = await change(first, { refreshToken: first.refreshToken })

      expect(res.status).toBe(204)
      expect((await signIn(email, NEW_PASSWORD)).status).toBe(200)
      expect(await refreshWorks(second.refreshToken)).toBe(false)
      expect(await refreshWorks(first.refreshToken)).toBe(true)
    })

    // Scenario: the caller's session rotates while the new password is being hashed, so it is live
    // at the check and gone at the sweep. Expected: the change completes, the password is the new
    // one, and EVERY session ends, the rotated one included, since there is no current session left
    // to keep. Why: the password is already written, so the cleanup must not be aborted by the
    // session it was told to spare; a 404 here would leave the old sessions alive on a changed
    // password.
    it('ends every session when the caller session rotates during the change', async () => {
      const { email, first } = await signUp()
      const second = toSession(await signIn(email))
      const passwords = app.get(PasswordService)
      const hash = passwords.hash.bind(passwords)
      let rotated: Session | undefined
      jest.spyOn(passwords, 'hash').mockImplementationOnce(async (plain: string) => {
        const res = await request(app.getHttpServer())
          .post('/refresh')
          .send({ refreshToken: first.refreshToken })
        rotated = toSession(res)
        return hash(plain)
      })

      const res = await change(first, { refreshToken: first.refreshToken })

      expect(res.status).toBe(204)
      expect((await signIn(email, NEW_PASSWORD)).status).toBe(200)
      expect(await refreshWorks(second.refreshToken)).toBe(false)
      expect(rotated).toBeDefined()
      expect(await refreshWorks((rotated as Session).refreshToken)).toBe(false)
    })

    // Scenario: no token at all. Expected: unchanged. The password changes and every session ends,
    // since there is no current session to keep.
    it('ends every session when no token is sent', async () => {
      const { email, first } = await signUp()

      const res = await change(first, {})

      expect(res.status).toBe(204)
      expect((await signIn(email, NEW_PASSWORD)).status).toBe(200)
      expect(await refreshWorks(first.refreshToken)).toBe(false)
    })
  })
})
