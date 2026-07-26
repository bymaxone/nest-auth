/**
 * End-to-end per-IP rate limiting.
 *
 * The library has always shipped `AUTH_THROTTLE_CONFIGS`, but as recommendations: the numbers
 * only took effect if the host wired `ThrottlerModule` and registered its guard. A deployment
 * that did not — and nothing told it — ran every auth route with no per-IP limit at all.
 *
 * These specs drive the real HTTP surface with the limiter on and assert the two things that
 * matter: the limit actually trips without any host wiring, and it refuses with the library's
 * own error envelope rather than a third-party throttler's shape.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { JWT_SECRET, bootstrapTestApp } from './setup'

describe('per-IP rate limiting (E2E)', () => {
  let app: INestApplication

  beforeAll(async () => {
    const bootstrap = await bootstrapTestApp({
      tokenDelivery: 'bearer',
      jwt: { secret: JWT_SECRET },
      rateLimit: { enabled: true }
    })
    app = bootstrap.app
  })

  afterAll(async () => {
    await app.close()
  })

  /** One login attempt with wrong credentials — the request still counts against the limit. */
  async function attemptLogin(email: string): Promise<request.Response> {
    return request(app.getHttpServer())
      .post('/login')
      .send({ email, password: 'WrongPassword123!', tenantId: 'tenant-1' })
  }

  // `login` is 5 requests per minute. The sixth from the same address must be refused, with no
  // ThrottlerModule anywhere in the test app — that is the whole point of moving the limit into
  // the library.
  it('refuses the sixth login attempt from one address inside the window', async () => {
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const allowed = await attemptLogin('limited@example.com')
      expect(allowed.status).not.toBe(429)
    }

    const refused = await attemptLogin('limited@example.com')

    expect(refused.status).toBe(429)
    expect(refused.body).toMatchObject({
      error: { code: 'auth.too_many_requests' }
    })
    // The window length, so a client knows when to come back.
    expect(refused.headers['retry-after']).toBe('60')
  })

  // Budgets are per route: exhausting login must not lock the caller out of a password reset,
  // which is exactly what someone who just failed to log in is likely to do next.
  it('keeps each route budget separate', async () => {
    for (let attempt = 1; attempt <= 6; attempt += 1) {
      await attemptLogin('separate@example.com')
    }
    expect((await attemptLogin('separate@example.com')).status).toBe(429)

    const reset = await request(app.getHttpServer())
      .post('/password/forgot-password')
      .send({ email: 'separate@example.com', tenantId: 'tenant-1' })

    expect(reset.status).not.toBe(429)
  })
})
