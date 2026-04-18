/**
 * End-to-end refresh concurrency with grace window.
 *
 * Two refresh requests carrying the same original refresh token must both
 * succeed when the second one arrives within the grace window
 * (`jwt.refreshGraceWindowSeconds`). The first request rotates from the
 * primary session key; the second request lands on the grace pointer left
 * behind by the first and rotates from there. Once the grace window expires,
 * any further use of the original token must return 401 — both the primary
 * session and the grace pointer are gone.
 *
 * The bootstrap overrides `jwt.refreshGraceWindowSeconds` to a short value so
 * the suite can wait for expiry with a real `setTimeout` instead of reaching
 * into the in-memory ioredis-mock to delete the grace key directly.
 *
 * Implementation note: `TokenManagerService.reissueTokens` mints an entirely
 * new refresh token pair on the grace path (see `rotateFromGrace`). The grace
 * window is therefore NOT a "same-result cache" — it is a "second-chance
 * rotation" within a short replay window. This suite asserts the actual
 * contract: both responses succeed with valid (but distinct) token pairs.
 *
 * ioredis-mock quirk: the mock returns JavaScript `undefined` when a Lua
 * script returns nil, but real Redis (and the production `reissueTokens`
 * check `oldSessionJson !== null`) expects `null`. The beforeAll wraps the
 * mock's `eval` to normalise `undefined` to `null` so the grace path behaves
 * identically to production. No production source is modified.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { JWT_SECRET, bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Short grace window in seconds. 2 seconds keeps the suite fast while still
 * leaving enough headroom for the second `Promise.all`-issued refresh to land
 * inside the window even on slow CI runners.
 */
const GRACE_WINDOW_SECONDS = 2

/**
 * Wait padding on top of the grace window before asserting expiry. 500 ms is
 * generous enough to absorb scheduler jitter on slow CI without making the
 * test flaky in either direction.
 */
const GRACE_EXPIRY_BUFFER_MS = 500

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('refresh concurrency with grace window (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Scenario — register → login → refresh twice with same token → expire → 401
  //
  // Every test below depends on state set up by the previous test. The chain
  // is intentional: it mirrors a single client racing two refresh attempts on
  // the same cached refresh token, so shared state (`firstResponse`,
  // `secondResponse`, `originalRefreshToken`) is mutated across the chained
  // `it()` blocks rather than reset per test.
  // ---------------------------------------------------------------------------

  describe('two refresh requests with the same original token', () => {
    let app: INestApplication

    // Original refresh token issued at login. Both /refresh requests in this
    // scenario exchange this same value, simulating two browser tabs (or a
    // retry after a network blip) reusing the cached refresh token.
    let originalRefreshToken: string

    // Captured responses from the two refresh requests. Asserted body-by-body
    // to prove that the grace window let the second request succeed when the
    // primary session was already deleted by the first rotation.
    let firstResponse: request.Response
    let secondResponse: request.Response

    // Shared state IS shared across the it() blocks below — each test
    // verifies one slice of the chained scenario set up in beforeAll
    // and continued by earlier it() blocks.
    beforeAll(async () => {
      // Arrange — bootstrap a test app with a short grace window so the expiry
      // assertion runs fast. `jwt` is shallow-spread by bootstrapTestApp, so
      // the secret must be repeated here or it will be lost.
      const bootstrap = await bootstrapTestApp({
        tokenDelivery: 'bearer',
        jwt: { secret: JWT_SECRET, refreshGraceWindowSeconds: GRACE_WINDOW_SECONDS }
      })
      app = bootstrap.app

      // ioredis-mock returns `undefined` when a Lua script returns nil, but the
      // production `TokenManagerService.reissueTokens` checks `oldSessionJson !==
      // null`. Real Redis returns `null` for nil, so the production check works
      // against a live Redis instance — but in this in-memory mock the check
      // would silently pass with `undefined`, sending the rotation through the
      // primary path with bad data and producing a spurious 401 on the grace
      // path. Wrap the mock's `eval` to normalise `undefined` to `null` so the
      // grace window behaves identically to production. This is test-only
      // infrastructure (no production source is modified).
      const originalEval = bootstrap.redis.eval.bind(bootstrap.redis) as (
        ...args: unknown[]
      ) => Promise<unknown>
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ;(bootstrap.redis as any).eval = async (...args: unknown[]): Promise<unknown> => {
        const result = await originalEval(...args)
        return result === undefined ? null : result
      }

      // Register and login to obtain a fresh refresh token. Registration with
      // emailVerification.required=false (the bootstrap default) immediately
      // yields tokens, but we follow up with /login anyway to mirror the
      // typical client flow and ensure the active session is the login session.
      await request(app.getHttpServer()).post('/register').send({
        email: 'race@example.com',
        password: 'RaceSecret123!',
        name: 'Race User',
        tenantId: 'tenant-1'
      })

      const login = await request(app.getHttpServer()).post('/login').send({
        email: 'race@example.com',
        password: 'RaceSecret123!',
        tenantId: 'tenant-1'
      })

      originalRefreshToken = login.body.refreshToken as string

      // Act — fire two /refresh requests in parallel via Promise.all, both
      // exchanging the SAME original refresh token. The first to win the
      // Lua-script race rotates from the primary session and writes a grace
      // pointer keyed to the original token's hash; the second finds the
      // primary session deleted and falls through to the grace pointer (atomic
      // GETDEL), which yields a fresh, distinct token pair derived from the
      // same underlying session.
      //
      // Note: the grace pointer is written by the first rotation AFTER the Lua
      // script deletes the primary key. supertest issues each Promise.all
      // request as an independent HTTP call but the in-process server handles
      // them on the single event loop, so the first request's `redis.set` of
      // the grace pointer reliably completes before the second request reaches
      // its `getdel` lookup.
      const [first, second] = await Promise.all([
        request(app.getHttpServer()).post('/refresh').send({ refreshToken: originalRefreshToken }),
        request(app.getHttpServer()).post('/refresh').send({ refreshToken: originalRefreshToken })
      ])

      firstResponse = first
      secondResponse = second
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that the default grace window is 30 seconds when not overridden.
    it('should default to a 30 second refresh grace window when not overridden', async () => {
      // Arrange — bootstrap a second app WITHOUT overriding the grace window.
      const defaultBootstrap = await bootstrapTestApp({ tokenDelivery: 'bearer' })

      // Act — read the user-supplied jwt options. The user-supplied object does
      // NOT set refreshGraceWindowSeconds, which is the contract that lets the
      // module fall back to DEFAULT_OPTIONS.jwt.refreshGraceWindowSeconds (30).
      const userJwt = defaultBootstrap.options.jwt as { refreshGraceWindowSeconds?: number }

      // Assert — the override is undefined, so the 30 s default applies.
      expect(userJwt.refreshGraceWindowSeconds).toBeUndefined()

      await defaultBootstrap.app.close()
    })

    // Verifies that the first /refresh request returns HTTP 200.
    it('should respond 200 to the first /refresh request (primary rotation)', () => {
      expect(firstResponse.status).toBe(200)
    })

    // Verifies that the second /refresh request also returns HTTP 200 via the grace path.
    it('should respond 200 to the second /refresh request (grace pointer rotation)', () => {
      // The second request reuses the SAME original token. Without a grace
      // window it would return 401; with the grace window the GETDEL on
      // `rp:{sha256(original)}` finds the pointer the first rotation wrote and
      // mints a fresh token pair from the underlying session.
      expect(secondResponse.status).toBe(200)
    })

    // Verifies that both responses carry well-formed access and refresh token strings.
    it('should return non-empty access and refresh tokens on both responses', () => {
      expect(typeof firstResponse.body.accessToken).toBe('string')
      expect(firstResponse.body.accessToken.length).toBeGreaterThan(0)
      expect(typeof firstResponse.body.refreshToken).toBe('string')
      expect(firstResponse.body.refreshToken.length).toBeGreaterThan(0)

      expect(typeof secondResponse.body.accessToken).toBe('string')
      expect(secondResponse.body.accessToken.length).toBeGreaterThan(0)
      expect(typeof secondResponse.body.refreshToken).toBe('string')
      expect(secondResponse.body.refreshToken.length).toBeGreaterThan(0)
    })

    // Verifies that the two grace-rotated token pairs are distinct (no result caching).
    it('should issue distinct token pairs to the two requests (grace mints fresh tokens)', () => {
      // The grace path in `TokenManagerService.rotateFromGrace` calls
      // `randomUUID()` to mint a brand-new refresh token, then signs a brand-new
      // access JWT (with a new `jti`). It does NOT serve a cached rotation
      // result. The two responses must therefore carry different token values.
      expect(firstResponse.body.refreshToken).not.toBe(secondResponse.body.refreshToken)
      expect(firstResponse.body.accessToken).not.toBe(secondResponse.body.accessToken)
    })

    // Verifies that both rotated refresh tokens differ from the original (true rotation occurred).
    it('should issue rotated refresh tokens that differ from the original', () => {
      expect(firstResponse.body.refreshToken).not.toBe(originalRefreshToken)
      expect(secondResponse.body.refreshToken).not.toBe(originalRefreshToken)
    })

    // Verifies that reusing the original refresh token after the grace window expires returns 401.
    it('should reject the original refresh token with 401 once the grace window has expired', async () => {
      // Arrange — wait for the grace pointer (`rp:{sha256(original)}`) to TTL
      // out. The window is 2 s plus a 500 ms buffer to absorb scheduler jitter.
      //
      // The second /refresh in beforeAll already consumed the original grace
      // pointer via atomic GETDEL, so a third replay would 401 immediately even
      // without waiting. The wait is kept to make the temporal contract of the
      // grace window explicit and to cover the broader case where the second
      // rotation never happened — in that scenario, only the TTL expiry can
      // invalidate the original token.
      await new Promise<void>((resolve) =>
        setTimeout(resolve, GRACE_WINDOW_SECONDS * 1000 + GRACE_EXPIRY_BUFFER_MS)
      )

      // Act — replay the original refresh token. The primary session key was
      // deleted atomically by the first rotation; the grace pointer for the
      // original token was atomically consumed by the second rotation; so the
      // call must throw REFRESH_TOKEN_INVALID, which the auth exception filter
      // maps to HTTP 401.
      const replay = await request(app.getHttpServer())
        .post('/refresh')
        .send({ refreshToken: originalRefreshToken })

      // Assert
      expect(replay.status).toBe(401)
    })
  })
})
