/**
 * End-to-end coverage for negative paths that were not exercised by the
 * existing suite. Bundled into one file because each scenario only needs a
 * handful of lines — splitting them into individual specs would add boilerplate
 * without making the audit story clearer.
 *
 * Scenarios:
 *   1. `/invitations/accept` with an unknown token → INVALID_INVITATION_TOKEN.
 *   2. `/invitations/accept` replay with a consumed token → INVALID_INVITATION_TOKEN.
 *   3. `DELETE /sessions/:id` for a session that does not belong to the caller →
 *      SESSION_NOT_FOUND (auth-bypass-class guarantee).
 *   4. `DELETE /sessions/all` with no refresh token / cookie → SESSION_NOT_FOUND.
 *   5. `/password/reset-password` with an unknown token → PASSWORD_RESET_TOKEN_INVALID.
 *   6. `/password/verify-otp` with the wrong code → OTP_INVALID.
 *   7. `/oauth/:provider` with an unknown provider → OAUTH_FAILED.
 *   8. `/oauth/:provider` with an empty `tenantId` → 400 from the DTO pipe.
 */

import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import type { IAuthHooks, OAuthLoginResult } from '../../src/server/interfaces/auth-hooks.interface'
import { OAUTH_PLUGINS } from '../../src/server/oauth/oauth.constants'
import { bootstrapTestApp } from './setup'
import type { BootstrappedTestApp, MockUserRepository } from './setup'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Registers a fresh dashboard user and returns the bearer access token plus
 * the refresh token. Used by scenarios that need an authenticated caller.
 */
async function registerAndLogin(
  boot: BootstrappedTestApp,
  email: string
): Promise<{ accessToken: string; refreshToken: string }> {
  const reg = await request(boot.app.getHttpServer())
    .post('/register')
    .send({ email, password: 'NegPath123!-xyz', name: 'Neg Path User', tenantId: 'tenant-1' })
  expect(reg.status).toBe(201)
  return reg.body as { accessToken: string; refreshToken: string }
}

// ---------------------------------------------------------------------------
// Invitations — INVALID_INVITATION_TOKEN
// ---------------------------------------------------------------------------

describe('/invitations/accept negative paths (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp(
      { invitations: { enabled: true, tokenTtlSeconds: 60 } },
      {
        controllers: {
          auth: true,
          mfa: true,
          passwordReset: true,
          sessions: true,
          invitations: true
        }
      }
    )
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies that submitting a token Tagged Out of nowhere returns the
  // standard INVALID_INVITATION_TOKEN code.
  it('should reject /invitations/accept with INVALID_INVITATION_TOKEN for an unknown token', async () => {
    const res = await request(boot.app.getHttpServer())
      .post('/invitations/accept')
      .send({
        token: 'a'.repeat(64),
        password: 'NewAccPass1!-xyz',
        name: 'Recipient Name'
      })

    expect(res.status).toBeGreaterThanOrEqual(400)
    expect(res.status).toBeLessThan(500)
    const body = res.body as { error?: { code?: string } }
    expect(body.error?.code).toBe('auth.invalid_invitation_token')
  })

  // Verifies that a token can only be accepted ONCE. The second attempt with
  // the same token must surface INVALID_INVITATION_TOKEN — single-use is the
  // central anti-replay guarantee.
  it('should reject /invitations/accept replay with INVALID_INVITATION_TOKEN', async () => {
    // Create an inviter (ADMIN) to issue the invitation.
    const inviter = await registerAndLogin(boot, `inviter-${Date.now().toString()}@example.com`)
    // Promote the inviter to ADMIN via direct repo mutation (the lib does not
    // ship a "set role" endpoint — RBAC is enforced from the persisted role).
    const repo = boot.repo as MockUserRepository
    for (const u of repo.users.values()) {
      if (u.email === `inviter-${Date.now().toString()}@example.com`) {
        repo.users.set(u.id, { ...u, role: 'ADMIN' })
      }
    }
    // ADMIN inviter — fish them out by passing a stable email.
    const stableEmail = `replay-inviter-${Math.random().toString(36).slice(2)}@example.com`
    const _ = await registerAndLogin(boot, stableEmail)
    let inviterId: string | undefined
    for (const u of repo.users.values()) {
      if (u.email === stableEmail) {
        repo.users.set(u.id, { ...u, role: 'ADMIN' })
        inviterId = u.id
      }
    }
    void inviter
    void _
    if (!inviterId) throw new Error('inviter not seeded')

    // Re-login the promoted inviter so the JWT carries role: ADMIN.
    const inviterLogin = await request(boot.app.getHttpServer())
      .post('/login')
      .send({ email: stableEmail, password: 'NegPath123!-xyz', tenantId: 'tenant-1' })
    expect(inviterLogin.status).toBe(200)
    const inviterAccess = (inviterLogin.body as { accessToken: string }).accessToken

    // Issue the invitation.
    const inviteeEmail = `replay-invitee-${Math.random().toString(36).slice(2)}@example.com`
    const create = await request(boot.app.getHttpServer())
      .post('/invitations')
      .set('Authorization', `Bearer ${inviterAccess}`)
      .send({ email: inviteeEmail, role: 'MEMBER' })
    expect(create.status).toBe(204)

    // Hash-only storage means the raw token cannot be recovered from Redis.
    // Spy on `sendInvitation` so the next invocation hands us the raw token,
    // then create a fresh invitation just to capture it.
    let capturedToken: string | undefined
    const provider = boot.email
    const originalSend = provider.sendInvitation.bind(provider)
    provider.sendInvitation = (async (toEmail, data) => {
      capturedToken = data.inviteToken
      return originalSend(toEmail, data)
    }) as typeof provider.sendInvitation
    void inviteeEmail

    const inviteeEmail2 = `replay-invitee-b-${Math.random().toString(36).slice(2)}@example.com`
    await request(boot.app.getHttpServer())
      .post('/invitations')
      .set('Authorization', `Bearer ${inviterAccess}`)
      .send({ email: inviteeEmail2, role: 'MEMBER' })

    expect(capturedToken).toBeTruthy()

    // First accept — succeeds.
    const accept1 = await request(boot.app.getHttpServer()).post('/invitations/accept').send({
      token: capturedToken,
      password: 'AcceptPass1!-xyz',
      name: 'Invitee'
    })
    expect(accept1.status).toBe(201)

    // Second accept with the same token — must be rejected (single-use).
    const accept2 = await request(boot.app.getHttpServer()).post('/invitations/accept').send({
      token: capturedToken,
      password: 'AcceptPass2!-xyz',
      name: 'Replay'
    })
    expect(accept2.status).toBeGreaterThanOrEqual(400)
    expect(accept2.status).toBeLessThan(500)
    expect((accept2.body as { error?: { code?: string } }).error?.code).toBe(
      'auth.invalid_invitation_token'
    )
  })
})

// ---------------------------------------------------------------------------
// Sessions — ownership + missing refresh
// ---------------------------------------------------------------------------

describe('sessions negative paths (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp()
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies that user A cannot revoke a session belonging to user B.
  // The library's contract is to surface SESSION_NOT_FOUND rather than 403 so
  // attackers cannot enumerate session IDs by error-code diffing.
  it('should return SESSION_NOT_FOUND when revoking a session owned by another user', async () => {
    const userA = await registerAndLogin(
      boot,
      `owner-a-${Math.random().toString(36).slice(2)}@example.com`
    )
    const userB = await registerAndLogin(
      boot,
      `owner-b-${Math.random().toString(36).slice(2)}@example.com`
    )

    // List user B's sessions to grab the active session id.
    const list = await request(boot.app.getHttpServer())
      .get('/sessions')
      .set('Authorization', `Bearer ${userB.accessToken}`)
    expect(list.status).toBe(200)
    const sessions = list.body as Array<{ id: string }>
    expect(sessions.length).toBeGreaterThan(0)
    const targetId = sessions[0]!.id

    // User A tries to revoke user B's session.
    const res = await request(boot.app.getHttpServer())
      .delete(`/sessions/${targetId}`)
      .set('Authorization', `Bearer ${userA.accessToken}`)

    expect(res.status).toBeGreaterThanOrEqual(400)
    expect(res.status).toBeLessThan(500)
    const body = res.body as { error?: { code?: string } }
    expect(body.error?.code).toBe('auth.session_not_found')
  })

  // Verifies that DELETE /sessions/all without a refresh token in the request
  // is rejected with SESSION_NOT_FOUND — the controller cannot determine which
  // session to keep alive without the token.
  it('should reject DELETE /sessions/all with SESSION_NOT_FOUND when no refresh token is present', async () => {
    const user = await registerAndLogin(
      boot,
      `noref-${Math.random().toString(36).slice(2)}@example.com`
    )

    // Bearer-mode call without a refresh-token body is the failure scenario
    // the controller specifically guards against.
    const res = await request(boot.app.getHttpServer())
      .delete('/sessions/all')
      .set('Authorization', `Bearer ${user.accessToken}`)
    // intentionally no body

    expect(res.status).toBeGreaterThanOrEqual(400)
    expect(res.status).toBeLessThan(500)
    const body = res.body as { error?: { code?: string } }
    expect(body.error?.code).toBe('auth.session_not_found')
  })
})

// ---------------------------------------------------------------------------
// Password reset — token + OTP invalid paths
// ---------------------------------------------------------------------------

describe('password reset negative paths (E2E)', () => {
  // Verifies that submitting an unknown reset token returns the standard
  // PASSWORD_RESET_TOKEN_INVALID code. Anti-enumeration guarantee.
  it('should reject /password/reset-password with PASSWORD_RESET_TOKEN_INVALID for an unknown token', async () => {
    const boot = await bootstrapTestApp({
      passwordReset: { method: 'token' }
    })
    try {
      const res = await request(boot.app.getHttpServer())
        .post('/password/reset-password')
        .send({
          email: 'ghost@example.com',
          token: 'a'.repeat(64),
          newPassword: 'NewPass123!-xyz',
          tenantId: 'tenant-1'
        })

      expect(res.status).toBeGreaterThanOrEqual(400)
      expect(res.status).toBeLessThan(500)
      const body = res.body as { error?: { code?: string } }
      expect(body.error?.code).toBe('auth.password_reset_token_invalid')
    } finally {
      await boot.app.close()
    }
  })

  // Verifies that submitting a wrong OTP at /password/verify-otp returns
  // OTP_INVALID (not OTP_MAX_ATTEMPTS on the first wrong attempt).
  it('should reject /password/verify-otp with OTP_INVALID for the wrong code', async () => {
    const boot = await bootstrapTestApp({
      passwordReset: { method: 'otp', otpLength: 6, otpTtlSeconds: 300 }
    })
    try {
      // Register and request OTP.
      const email = `reset-otp-${Math.random().toString(36).slice(2)}@example.com`
      await registerAndLogin(boot, email)
      await request(boot.app.getHttpServer())
        .post('/password/forgot-password')
        .send({ email, tenantId: 'tenant-1' })

      const res = await request(boot.app.getHttpServer())
        .post('/password/verify-otp')
        .send({ email, otp: '000000', tenantId: 'tenant-1' })

      expect(res.status).toBeGreaterThanOrEqual(400)
      expect(res.status).toBeLessThan(500)
      const body = res.body as { error?: { code?: string } }
      // OTP_INVALID on first wrong attempt — OTP_MAX_ATTEMPTS only appears
      // after exceeding the lib's attempt budget.
      expect(body.error?.code).toBe('auth.otp_invalid')
    } finally {
      await boot.app.close()
    }
  })
})

// ---------------------------------------------------------------------------
// OAuth — unknown provider + missing tenantId
// ---------------------------------------------------------------------------

describe('OAuth negative paths (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    // Mount the OAuth controller with a single plugin so the controller
    // exists; the unknown-provider test then hits a path the plugin does not
    // claim. Authentication hooks are no-op (action: 'reject') because the
    // unknown-provider path short-circuits before calling them.
    const noopHooks: IAuthHooks = {
      async onOAuthLogin(): Promise<OAuthLoginResult> {
        return { action: 'reject', reason: 'not-needed' }
      }
    }
    const mockGooglePlugin = {
      name: 'google',
      authorizeUrl: () => 'https://example.com/oauth/google?state=x',
      exchangeCode: async () => ({ access_token: 't', token_type: 'Bearer' }),
      fetchProfile: async () => ({
        provider: 'google',
        providerId: 'x',
        email: 'x@example.com',
        name: 'X'
      })
    }
    boot = await bootstrapTestApp(
      {
        oauth: {
          google: {
            clientId: 'test-id',
            clientSecret: 'test-secret',
            callbackUrl: 'http://localhost:4000/oauth/google/callback'
          }
        }
      },
      {
        controllers: {
          auth: true,
          mfa: true,
          passwordReset: true,
          sessions: true,
          oauth: true
        },
        extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: noopHooks }],
        mutateBuilder: (builder) =>
          builder.overrideProvider(OAUTH_PLUGINS).useValue([mockGooglePlugin]) as typeof builder
      }
    )
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies that requesting an OAuth flow for a provider that is not
  // registered surfaces OAUTH_FAILED — the catch-all OAuth error code the
  // lib uses to avoid leaking which providers are configured.
  it('should return OAUTH_FAILED for /oauth/:unknown', async () => {
    const res = await request(boot.app.getHttpServer())
      .get('/oauth/unknownprov')
      .query({ tenantId: 'tenant-1' })

    expect(res.status).toBeGreaterThanOrEqual(400)
    expect(res.status).toBeLessThan(500)
    const body = res.body as { error?: { code?: string } }
    expect(body.error?.code).toBe('auth.oauth_failed')
  })

  // Verifies that omitting `tenantId` from /oauth/:provider is rejected by
  // the DTO pipe with a 400 — protects against accidentally initiating OAuth
  // without a tenant scope.
  it('should reject /oauth/google with 400 when tenantId is missing', async () => {
    const res = await request(boot.app.getHttpServer()).get('/oauth/google')

    expect(res.status).toBe(400)
  })
})
