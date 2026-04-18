/**
 * End-to-end FIFO session eviction.
 *
 * Verifies that when a user exceeds `sessions.defaultMaxSessions` the oldest
 * session is automatically evicted (FIFO). Bootstraps the module with a limit
 * of 5, performs 6 distinct device logins, and asserts that:
 *   1. Exactly 5 sessions remain after the 6th login.
 *   2. The 6th (most recent) login is marked `isCurrent: true` when listing.
 *   3. The 1st login's refresh token is rejected with 401 because its session
 *      was evicted from the `sess:{userId}` Redis SET.
 *
 * Every step runs through the real HTTP layer via supertest — no service
 * internals are stubbed, the eviction must happen end-to-end.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Constants — six distinct device User-Agent strings
// ---------------------------------------------------------------------------

/** Mac desktop User-Agent — used for the FIRST login (the one that gets evicted). */
const UA_MAC = 'Mozilla/5.0 (Macintosh; Mac OS X)'

/** Linux desktop User-Agent — second login. */
const UA_LINUX = 'Mozilla/5.0 (X11; Linux x86_64)'

/** Windows desktop User-Agent — third login. */
const UA_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0)'

/** Android mobile User-Agent — fourth login. */
const UA_ANDROID = 'Mozilla/5.0 (Linux; Android 14)'

/** iPad tablet User-Agent — fifth login. */
const UA_IPAD = 'Mozilla/5.0 (iPad; iPadOS)'

/** iPhone mobile User-Agent — SIXTH login (the new "current" session). */
const UA_IPHONE = 'Mozilla/5.0 (iPhone iOS)'

/** Configured concurrent session limit for this suite. */
const MAX_PER_USER = 5

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('session FIFO eviction (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Scenario — six-device login → automatic eviction → list → blocked refresh
  //
  // Every step depends on the previous one (register → 6 logins → list →
  // attempt refresh with the evicted token). All shared state is mutated in
  // `beforeAll` and across the chained `it()` blocks below — the shared
  // variables are reused intentionally.
  // ---------------------------------------------------------------------------

  describe('FIFO eviction when defaultMaxSessions is exceeded', () => {
    let app: INestApplication

    // Tokens for each of the six device logins, in chronological order.
    // The first pair belongs to the session that MUST be evicted; the sixth
    // pair acts as the caller's current session for every subsequent step.
    let firstAccessToken: string
    let firstRefreshToken: string
    let sixthAccessToken: string
    let sixthRefreshToken: string

    // Shared state IS shared across the it() blocks below — each test
    // verifies one slice of the chained scenario set up in beforeAll.
    beforeAll(async () => {
      // Override default sessions group to enforce a hard limit of 5
      // concurrent sessions per user. The sessions group is spread (not
      // deep-merged) by bootstrapTestApp, so we re-include `enabled: true`.
      const bootstrap = await bootstrapTestApp({
        tokenDelivery: 'bearer',
        sessions: { enabled: true, defaultMaxSessions: MAX_PER_USER }
      })
      app = bootstrap.app

      // Register the user once. With emailVerification.required: false (the
      // bootstrapTestApp default) registration immediately yields tokens AND
      // creates an active session for the registration request. To keep the
      // "six sessions from six devices" invariant clean, we immediately
      // logout the registration session so only the dedicated device logins
      // contribute to the active session set.
      const register = await request(app.getHttpServer()).post('/register').send({
        email: 'eviction@example.com',
        password: 'EvictionSecret123!',
        name: 'Eviction Test User',
        tenantId: 'tenant-1'
      })
      const registerAccessToken = register.body.accessToken as string
      const registerRefreshToken = register.body.refreshToken as string
      await request(app.getHttpServer())
        .post('/logout')
        .set('Authorization', `Bearer ${registerAccessToken}`)
        .send({ refreshToken: registerRefreshToken })

      // Helper — perform a login with a specific User-Agent and return the
      // resulting token pair. Each login MUST carry a unique User-Agent so
      // each session is identifiable in the listSessions output.
      const login = async (
        userAgent: string
      ): Promise<{ accessToken: string; refreshToken: string }> => {
        const res = await request(app.getHttpServer())
          .post('/login')
          .set('User-Agent', userAgent)
          .send({
            email: 'eviction@example.com',
            password: 'EvictionSecret123!',
            tenantId: 'tenant-1'
          })
        return {
          accessToken: res.body.accessToken as string,
          refreshToken: res.body.refreshToken as string
        }
      }

      // Login #1 — Mac. This is the OLDEST session and the one expected
      // to be evicted by the 6th login.
      const first = await login(UA_MAC)
      firstAccessToken = first.accessToken
      firstRefreshToken = first.refreshToken

      // Logins #2–#5 — fill up the 5-session quota.
      await login(UA_LINUX)
      await login(UA_WINDOWS)
      await login(UA_ANDROID)
      await login(UA_IPAD)

      // Login #6 — iPhone. With 5 sessions already active, this login MUST
      // trigger FIFO eviction of the Mac (oldest) session before recording
      // itself. After this call returns, the user has exactly 5 sessions
      // again — Linux, Windows, Android, iPad, and iPhone.
      const sixth = await login(UA_IPHONE)
      sixthAccessToken = sixth.accessToken
      sixthRefreshToken = sixth.refreshToken
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that all six logins produced distinct refresh tokens so each session is identifiable.
    it('should produce distinct token pairs across all six device logins', () => {
      // Arrange — all token pairs were captured in beforeAll. We only kept
      // the first and sixth as named state; the middle four are anonymous
      // because no assertion in this suite needs them individually.

      // Act — no further action; assertions run on captured state.

      // Assert — both retained pairs must be present and the first/sixth
      // pairs must differ from each other to prove distinct sessions.
      expect(firstAccessToken).toEqual(expect.any(String))
      expect(firstRefreshToken).toEqual(expect.any(String))
      expect(sixthAccessToken).toEqual(expect.any(String))
      expect(sixthRefreshToken).toEqual(expect.any(String))
      expect(firstRefreshToken).not.toBe(sixthRefreshToken)
      expect(firstAccessToken).not.toBe(sixthAccessToken)
    })

    // Verifies that GET /sessions returns exactly 5 sessions after the 6th login triggered FIFO eviction.
    it('should list exactly five sessions and mark the sixth login as current', async () => {
      // Arrange — six logins were performed in beforeAll. The first (Mac)
      // session is expected to have been evicted automatically; the sixth
      // (iPhone) login's tokens act as the caller's current session.

      // Act — call GET /sessions with the sixth bearer token AND forward
      // the sixth refresh token in the body so the server can mark the
      // caller's session as `isCurrent: true` (bearer mode reads refresh
      // tokens from the request body).
      const res = await request(app.getHttpServer())
        .get('/sessions')
        .set('Authorization', `Bearer ${sixthAccessToken}`)
        .send({ refreshToken: sixthRefreshToken })

      // Assert
      expect(res.status).toBe(200)
      expect(Array.isArray(res.body)).toBe(true)
      const sessions = res.body as Array<{
        id: string
        sessionHash: string
        device: string
        isCurrent: boolean
      }>

      // FIFO eviction must have removed exactly one session (the Mac one)
      // so the active set is back down to the configured limit.
      expect(sessions).toHaveLength(MAX_PER_USER)

      // Exactly one session must be flagged current — the iPhone (sixth)
      // login. parseUserAgent maps the UA_IPHONE string to "... on iOS".
      const currentSessions = sessions.filter((s) => s.isCurrent)
      expect(currentSessions).toHaveLength(1)
      expect(currentSessions[0]?.device).toMatch(/iOS/)
    })

    // Verifies that POST /refresh with the evicted first session's refresh token returns 401.
    it('should reject refresh attempts using the evicted first session token with 401', async () => {
      // Arrange — the first (Mac) session was evicted by the 6th login in
      // beforeAll, so its `rt:{hash}` member is gone from `sess:{userId}`
      // and its `rt:{hash}` Redis key was deleted.

      // Act — attempt to refresh using the evicted token. Bearer mode reads
      // the refresh token from the request body.
      const res = await request(app.getHttpServer())
        .post('/refresh')
        .set('User-Agent', UA_MAC)
        .send({ refreshToken: firstRefreshToken })

      // Assert — refresh must fail with 401 because the session was evicted.
      // No new tokens may be returned in the response body.
      expect(res.status).toBe(401)
      expect(res.body?.accessToken).toBeUndefined()
      expect(res.body?.refreshToken).toBeUndefined()
    })
  })
})
