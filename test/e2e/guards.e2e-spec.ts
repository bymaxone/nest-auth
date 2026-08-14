/**
 * @fileoverview Drives the guard branches no E2E reached — the refusals, not the admissions.
 *
 * E2E-only coverage of `src/server/guards` was **30.4% of branches**. What the existing suite
 * exercises is guards *admitting* a valid caller, because that is what every happy-path flow does
 * on its way somewhere else. The refusals — an unverifiable token, a cross-site POST, a JWT whose
 * account no longer exists — were proven only by unit tests handing each guard an
 * `ExecutionContext` no middleware would build. That proves the code runs; it does not prove the
 * guard is reachable, or that the refusal survives the pipeline it actually sits in.
 *
 * These are the branches that decide whether a request is authorised, so "runs" is not the
 * property that matters about them.
 */

import { randomBytes } from 'node:crypto'

import { JwtService } from '@nestjs/jwt'
import request from 'supertest'

import { BYMAX_AUTH_USER_REPOSITORY } from '../../src/server/bymax-auth.constants'
import { bootstrapTestApp, createMockUserRepository, expectAuthError } from './setup'
import type { BootstrappedTestApp, MockUserRepository } from './setup'

/**
 * A well-formed JWT this deployment did not sign, minted under a key generated per run.
 *
 * It used to be a literal with a stub signature, and that was weaker on both counts. A string
 * that is not really signed is rejected by the parser as much as by the verifier, so it could
 * not tell "the signature check works" from "this is not a JWT" — which is what the case beside
 * it already covers. And a JWT-shaped literal next to the word `Bearer` is exactly what GitHub's
 * secret scanner matches: the value carried nothing, but an alert nobody can distinguish from a
 * real leak at a glance is how an alert stream stops being read.
 */
const FOREIGN_JWT = new JwtService({}).sign(
  { sub: 'user-1', tenantId: 'tenant-1', type: 'dashboard' },
  { secret: randomBytes(32).toString('hex'), expiresIn: '5m' }
)

describe('JwtAuthGuard refusals (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    // `platform.enabled` because the platform cases below drive `/platform/me`. Without it the
    // route is not mounted and the request 404s — which, with `AuthExceptionFilter` registered,
    // comes back as `auth.internal` rather than as a 404 shape. That is how the first draft of
    // this suite failed: a missing route and a rejected credential are both "an error with an
    // auth code", and only asserting the exact code told them apart.
    boot = await bootstrapTestApp(
      { platform: { enabled: true } },
      {
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true }
      }
    )
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies every unusable credential collapses onto ONE code, over real HTTP.
  //
  // The catalogue's rule is that a caller must not be able to tell a malformed token from a
  // well-formed one this deployment did not sign, from none at all — `auth.token_expired` and
  // `auth.token_revoked` exist for logs and are deliberately never served. Asserting the three
  // together is the point: each alone would pass against a guard that answered them differently.
  it.each([
    { why: 'no credential at all', header: undefined },
    { why: 'a syntactically invalid token', header: 'Bearer not-a-jwt' },
    { why: 'a well-formed token this deployment did not sign', header: `Bearer ${FOREIGN_JWT}` }
  ])('refuses $why with auth.token_invalid', async ({ header }) => {
    const req = request(boot.app.getHttpServer()).get('/me')
    if (header !== undefined) void req.set('Authorization', header)

    expectAuthError(await req, 'auth.token_invalid')
  })

  // Verifies the same three on a PLATFORM route, which reads its credential from a different
  // place: `extractPlatformAccessToken` always takes the Authorization header regardless of
  // `tokenDelivery`. A cookie-mode deployment therefore refuses a platform caller who sends only
  // cookies, and that difference is invisible from the dashboard routes.
  it.each([
    { why: 'no credential at all', header: undefined },
    { why: 'a syntactically invalid token', header: 'Bearer not-a-jwt' },
    { why: 'a foreign-signed token', header: `Bearer ${FOREIGN_JWT}` }
  ])('refuses $why on a platform route with auth.token_invalid', async ({ header }) => {
    const req = request(boot.app.getHttpServer()).get('/platform/me')
    if (header !== undefined) void req.set('Authorization', header)

    expectAuthError(await req, 'auth.token_invalid')
  })
})

describe('UserStatusGuard — the account behind a live token (E2E)', () => {
  // Verifies a token stays unusable once its account is gone.
  //
  // A JWT is valid for its whole lifetime and carries no link to the record it was minted from,
  // so an account deleted a second after sign-in leaves a credential that verifies perfectly.
  // The guard is the only thing standing between that token and the routes that act. Driven over
  // HTTP against `/ws-ticket`, which composes `JwtAuthGuard` + `UserStatusGuard` — and which had
  // no E2E of its own before this.
  it('refuses a token whose account was deleted after it was issued', async () => {
    const boot = await bootstrapTestApp()

    try {
      const registered = await request(boot.app.getHttpServer()).post('/register').send({
        email: 'deleted-after@example.com',
        password: 'ProbePass123!-xyz',
        name: 'Gone Soon',
        tenantId: 'tenant-1'
      })
      expect(registered.status).toBe(201)
      const { accessToken } = registered.body as { accessToken: string }

      // The ticket is issued while the account exists — the control that makes the refusal below
      // about the deletion rather than about the route being broken.
      const before = await request(boot.app.getHttpServer())
        .post('/ws-ticket')
        .set('Authorization', `Bearer ${accessToken}`)
      expect(before.status).toBe(200)
      // The TTL is asserted as the VALUE the shared contract fixes, not as `any(Number)`.
      // `wire-contract.json` describes the ticket as "64 lowercase hex characters (32 CSPRNG
      // bytes), single-use, 30 s lifetime", and `expect.any(Number)` passes on every regression
      // that could reach it — a ticket that lived an hour, or zero seconds, would both be green.
      // That is the exact defect this suite exists to stop, arriving in the suite itself.
      expect(before.body).toEqual({
        ticket: expect.stringMatching(/^[0-9a-f]{64}$/),
        expiresIn: 30
      })

      const repo = boot.repo as MockUserRepository
      repo.users.clear()
      await boot.redis.flushall()

      expectAuthError(
        await request(boot.app.getHttpServer())
          .post('/ws-ticket')
          .set('Authorization', `Bearer ${accessToken}`),
        'auth.token_invalid'
      )
    } finally {
      await boot.app.close()
    }
  })
})

describe('TrustedOriginGuard refusals (E2E)', () => {
  // Verifies the CSRF refusals a browser actually triggers.
  //
  // This guard is the library's cross-site defence and **every one of its refusal branches was
  // unproven over HTTP** — only its admissions were, because every other E2E is same-origin by
  // construction. A guard whose refusals are untested is a guard whose admissions are the only
  // thing measured.
  //
  // Both headers are driven because the guard decides on either: `Origin` against the configured
  // list, and `Sec-Fetch-Site` on browsers that send it. The same-site and none cases assert the
  // guard does not refuse traffic it must allow — a defence that refuses everything is not a
  // passing test.
  it.each([
    {
      why: 'an Origin not on the list',
      headers: { origin: 'https://evil.example' },
      allowed: false
    },
    {
      why: 'a cross-site Sec-Fetch-Site with no Origin',
      headers: { 'sec-fetch-site': 'cross-site' },
      allowed: false
    },
    {
      why: 'an Origin on the list',
      headers: { origin: 'https://app.example.com' },
      allowed: true
    },
    {
      why: 'a same-origin Sec-Fetch-Site',
      headers: { 'sec-fetch-site': 'same-origin' },
      allowed: true
    }
  ])('$why → refused: $allowed', async ({ headers, allowed }) => {
    const boot = await bootstrapTestApp({
      cookies: { trustedOrigins: ['https://app.example.com'] }
    })

    try {
      const req = request(boot.app.getHttpServer()).post('/login')
      for (const [name, value] of Object.entries(headers)) void req.set(name, value)

      const res = await req.send({
        email: 'nobody@example.com',
        password: 'ProbePass123!-xyz',
        tenantId: 'tenant-1'
      })

      if (allowed) {
        // Past the guard. The credentials are wrong on purpose — reaching the credential check at
        // all is the property, and asserting the auth failure rather than a 2xx keeps this from
        // passing on a deployment that stopped checking passwords.
        expectAuthError(res, 'auth.invalid_credentials')
      } else {
        expectAuthError(res, 'auth.untrusted_origin')
      }
    } finally {
      await boot.app.close()
    }
  })
})

describe('AuthRateLimitGuard — which address it keys on (E2E)', () => {
  // Verifies `clientIpSource: 'trusted-proxy'` keys the limiter on the forwarded address rather
  // than on the socket peer.
  //
  // The branch matters because getting it backwards is silent and severe in both directions:
  // keying on the socket peer behind a proxy limits every user as one, and trusting a forwarded
  // header without a proxy lets any caller reset their own bucket by changing it. Two requests
  // from *different* forwarded addresses must not share a bucket — which is what distinguishes
  // the branches, since a single request cannot.
  it('separates buckets by the forwarded address under trusted-proxy', async () => {
    const boot = await bootstrapTestApp({
      rateLimit: { enabled: true, clientIpSource: 'trusted-proxy' }
    })
    boot.app.getHttpAdapter().getInstance().set('trust proxy', true)

    try {
      // A DIFFERENT e-mail per address, which the first draft got wrong and the run caught: the
      // brute-force lockout is keyed by `hmac(tenantId + ':' + email)`, so reusing one identity
      // locked the ACCOUNT and answered 429 from that control — the same status this case is
      // about, produced by a different mechanism. Distinct identities leave the per-IP bucket as
      // the only thing that can produce it.
      const attempt = (forwarded: string, email: string) =>
        request(boot.app.getHttpServer())
          .post('/login')
          .set('X-Forwarded-For', forwarded)
          .send({ email, password: 'ProbePass123!-xyz', tenantId: 'tenant-1' })

      // Exhaust one address, then show a different one is unaffected.
      let exhausted = false
      for (let i = 0; i < 12 && !exhausted; i++) {
        const res = await attempt('203.0.113.9', `first-${String(i)}@example.com`)
        exhausted = res.status === 429
      }
      expect(exhausted).toBe(true)

      const other = await attempt('198.51.100.7', 'second@example.com')
      expect(other.status).not.toBe(429)
      expectAuthError(other, 'auth.invalid_credentials')
    } finally {
      await boot.app.close()
    }
  })
})
