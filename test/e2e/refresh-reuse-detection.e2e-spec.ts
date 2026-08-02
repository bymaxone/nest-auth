/**
 * End-to-end refresh-token reuse detection (RFC 6819 / OWASP rotation with automatic reuse
 * detection).
 *
 * Rotation alone does not stop a stolen refresh token: the thief simply rotates it and rides
 * the lineage forward. What stops it is noticing that a token which was already consumed comes
 * back — once its grace window has closed, that replay can only mean two holders. The reaction
 * is to revoke the whole **family**: every live descendant of that one login dies, so whichever
 * side is the thief is locked out and the victim must re-authenticate.
 *
 * The revocation is deliberately scoped to the lineage, not to the account: a theft on one
 * device must not log the user out of every other device they own.
 *
 * These specs drive the real HTTP surface against the in-memory Redis, so they exercise the
 * rotation script, the family bookkeeping, and the revocation transaction together.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { JWT_SECRET, bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Short grace window so a replay can be pushed past it without a slow test. */
const GRACE_WINDOW_SECONDS = 1

/** Padding on top of the grace window before replaying, to absorb scheduler jitter. */
const GRACE_EXPIRY_BUFFER_MS = 400

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('refresh-token reuse detection (E2E)', () => {
  let app: INestApplication

  /**
   * Registers and logs in a user, returning their first refresh token. Each scenario uses its
   * own account so one revocation cannot bleed into another.
   */
  async function login(email: string): Promise<string> {
    await request(app.getHttpServer())
      .post('/register')
      .send({ email, password: 'ReuseSecret123!', name: 'Reuse User', tenantId: 'tenant-1' })
    const response = await request(app.getHttpServer())
      .post('/login')
      .send({ email, password: 'ReuseSecret123!', tenantId: 'tenant-1' })
    return response.body.refreshToken as string
  }

  /** Exchanges a refresh token and returns the response. */
  async function refresh(token: string): Promise<request.Response> {
    return request(app.getHttpServer()).post('/refresh').send({ refreshToken: token })
  }

  /** Waits out the grace window so a replay is judged as a reuse rather than recovered. */
  async function waitOutGraceWindow(): Promise<void> {
    await new Promise<void>((resolve) =>
      setTimeout(resolve, GRACE_WINDOW_SECONDS * 1000 + GRACE_EXPIRY_BUFFER_MS)
    )
  }

  beforeAll(async () => {
    const bootstrap = await bootstrapTestApp({
      tokenDelivery: 'bearer',
      jwt: { secret: JWT_SECRET, refreshGraceWindowSeconds: GRACE_WINDOW_SECONDS }
    })
    app = bootstrap.app

    // ioredis-mock returns `undefined` where real Redis returns nil/null. The rotation script
    // reports "this token was never issued" as nil, so without this the outcome would not be
    // recognised. Test-only infrastructure; no production source is modified.
    const originalEval = bootstrap.redis.eval.bind(bootstrap.redis) as (
      ...args: unknown[]
    ) => Promise<unknown>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(bootstrap.redis as any).eval = async (...args: unknown[]): Promise<unknown> => {
      const result = await originalEval(...args)
      return result === undefined ? null : result
    }
  })

  afterAll(async () => {
    await app.close()
  })

  // Verifies the theft signal itself: a token that was legitimately issued, rotated away, and
  // replayed after its grace window closed is rejected — it is not silently accepted, and it is
  // not resurrected by the grace path.
  it('rejects a consumed refresh token replayed after its grace window closes', async () => {
    const original = await login('reuse-basic@example.com')
    expect((await refresh(original)).status).toBe(200)

    await waitOutGraceWindow()

    expect((await refresh(original)).status).toBe(401)
  })

  // Verifies the reaction: the replay does not merely fail, it takes the whole lineage with it.
  // The descendant token the thief (or the victim) is holding stops working immediately, which
  // is what forces re-authentication instead of letting the parallel session live on.
  it('revokes the whole lineage when a consumed token is replayed', async () => {
    const original = await login('reuse-family@example.com')
    const rotated = await refresh(original)
    const descendant = rotated.body.refreshToken as string

    await waitOutGraceWindow()
    // The replay is the theft signal; the request itself still fails.
    expect((await refresh(original)).status).toBe(401)

    // The live descendant of that login is gone with it.
    expect((await refresh(descendant)).status).toBe(401)
  })

  // Verifies the blast radius: a theft on one device must not log the user out everywhere. The
  // second login opens its own family, so it survives the first family's revocation — this is
  // the behaviour that replaced "revoke every session this user has".
  it('leaves the user other logins alone when one lineage is revoked', async () => {
    const first = await login('reuse-scope@example.com')
    const secondLogin = await request(app.getHttpServer())
      .post('/login')
      .send({ email: 'reuse-scope@example.com', password: 'ReuseSecret123!', tenantId: 'tenant-1' })
    const second = secondLogin.body.refreshToken as string

    // Burn the first lineage: rotate it, let the window close, then replay.
    const firstRotated = await refresh(first)
    await waitOutGraceWindow()
    expect((await refresh(first)).status).toBe(401)
    expect((await refresh(firstRotated.body.refreshToken as string)).status).toBe(401)

    // The other login is untouched and still rotates.
    expect((await refresh(second)).status).toBe(200)
  })

  // SECURITY REGRESSION GUARD. Reuse detection revokes the family's live sessions, but a grace
  // pointer planted by an EARLIER rotation of that same lineage can still be inside its window
  // when the reuse fires — detection only proves the REPLAYED token's own pointer expired, which
  // says nothing about a younger sibling's. Recovering from that pointer would mint a fresh
  // session carrying the revoked family id and hand back the lineage the revocation just killed.
  it('does not let a live grace pointer resurrect a revoked lineage', async () => {
    const t1 = await login('reuse-resurrect@example.com')

    // t1 -> t2 immediately, so t1's grace pointer starts ageing first.
    const t2 = (await refresh(t1)).body.refreshToken as string
    // Let t1's pointer expire, then rotate t2 -> t3 so t2's pointer is freshly planted and live.
    await waitOutGraceWindow()
    const rotatedT2 = await refresh(t2)
    expect(rotatedT2.status).toBe(200)

    // Replaying t1 now is a reuse: its own pointer is gone, but t2's is not.
    expect((await refresh(t1)).status).toBe(401)

    // t2 is a consumed token whose grace pointer is still live — it must NOT recover a session
    // from the lineage that was just revoked.
    expect((await refresh(t2)).status).toBe(401)
  })

  // Verifies the grace window stays single-shot: it exists to cover the one retry where the old
  // token was consumed but the client never received the new one. Letting it serve every request
  // inside the window would let one captured token mint a session over and over.
  it('serves the grace window only once per rotation', async () => {
    const original = await login('reuse-single-shot@example.com')
    expect((await refresh(original)).status).toBe(200)

    // First replay lands inside the window and is recovered.
    expect((await refresh(original)).status).toBe(200)
    // The pointer is consumed, so the next one inside the same window is not.
    expect((await refresh(original)).status).toBe(401)
  })
})
