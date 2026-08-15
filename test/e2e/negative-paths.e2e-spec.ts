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
 *   4. `POST /sessions/revoke-all` with no refresh token / cookie → SESSION_NOT_FOUND.
 *   5. `/password/reset-password` with an unknown token → PASSWORD_RESET_TOKEN_INVALID.
 *   6. `/password/verify-otp` with the wrong code → OTP_INVALID.
 *   7. `/oauth/:provider` with an unknown provider → OAUTH_FAILED.
 *   8. `/oauth/:provider` with an empty `tenantId` → 400 from the DTO pipe.
 */

import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import type { IAuthHooks, OAuthLoginResult } from '../../src/server/interfaces/auth-hooks.interface'
import { OAUTH_PLUGINS } from '../../src/server/oauth/oauth.constants'
import { bootstrapTestApp, expectAuthError } from './setup'
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
// The two @Public token routes, reached with no token at all
// ---------------------------------------------------------------------------

describe('logout and refresh with no credential (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp()
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Both handlers read their credential through `extractAccessToken(req) ?? ''` /
  // `extractRefreshToken(req) ?? ''`, and the `?? ''` arm — the request that carries neither a
  // header nor a cookie — had never been driven over HTTP. It is the ordinary shape of both
  // routes in the wild: a browser whose cookies expired, a client that lost its token, a bot.
  //
  // The two answer DIFFERENTLY on purpose, and that is the pair worth asserting together.

  // Logout is idempotent: signing out with nothing to sign out of is success, not an error.
  // Answering 401 here would leave a client that lost its tokens unable to complete a logout it
  // has already, in every sense that matters, completed — and would tell an unauthenticated
  // caller whether a credential was recognised.
  it('answers a logout with no credential 204, and clears nothing it was not sent', async () => {
    const res = await request(boot.app.getHttpServer()).post('/logout').send({})

    expect(res.status).toBe(204)
    expect(res.body).toEqual({})
  })

  // Refresh is the opposite: with no refresh token there is nothing to rotate, and the answer is
  // the same refusal a wrong token gets. Identical on purpose — a caller must not learn from the
  // response whether the token they sent was recognised, only that they have no session.
  // The platform twins of the two above, on a surface that reads its credential from a
  // different place: `extractPlatformAccessToken` / `extractPlatformRefreshToken` always take
  // the header and the body, never a cookie, whatever `tokenDelivery` says. So "no credential"
  // is a different code path here, and it had the same untested `?? ''` arm.
  it('answers a platform logout with no credential 204 and a platform refresh 401', async () => {
    const platform = await bootstrapTestApp(
      { platform: { enabled: true } },
      {
        controllers: { auth: true, mfa: true, passwordReset: true, sessions: true, platform: true }
      }
    )

    try {
      const logout = await request(platform.app.getHttpServer()).post('/platform/logout').send({})
      expect(logout.status).toBe(204)

      const refresh = await request(platform.app.getHttpServer()).post('/platform/refresh').send({})
      expectAuthError(refresh, 'auth.refresh_token_invalid')
    } finally {
      await platform.app.close()
    }
  })

  it('answers a refresh with no credential exactly as it answers a wrong one', async () => {
    const missing = await request(boot.app.getHttpServer()).post('/refresh').send({})
    const wrong = await request(boot.app.getHttpServer())
      .post('/refresh')
      .send({ refreshToken: 'a'.repeat(64) })

    expectAuthError(missing, 'auth.refresh_token_invalid')
    expect(missing.body).toEqual(wrong.body)
    expect(missing.status).toBe(wrong.status)
  })
})

// ---------------------------------------------------------------------------
// A host that never mounted a cookie parser
// ---------------------------------------------------------------------------

describe('cookie readers on a host with no cookie parser (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp({}, { withoutCookieParser: true })
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // `cookie-parser` is the consumer's to mount — this library takes no dependency on it and a
  // bearer-only deployment has no reason to add one. Every cookie reader here therefore has to
  // survive `req.cookies` being **undefined**, and until now nothing proved it: the harness
  // mounts a shim for every other suite, so the branch was reachable only through a unit test
  // handing the reader an object Express would not have built.
  //
  // The failure it guards against is not subtle and is not confined to cookies: a reader that
  // assumed the object exists throws a TypeError, which the exception filter turns into a 500 on
  // a route the caller drove with a perfectly good bearer token.
  it('refuses the MFA challenge instead of failing on the missing cookie jar', async () => {
    const res = await request(boot.app.getHttpServer())
      .post('/mfa/challenge')
      .set('Cookie', 'mfa_temp_token=whatever')
      .send({ code: '123456' })

    // The header was sent and there is no parser to read it, so the request arrives with no
    // token from either source — which is the controller's own refusal, not an error.
    expectAuthError(res, 'auth.mfa_temp_token_invalid')
  })

  // The same property on the credential path: a bearer login works normally on a host with no
  // cookie parser. Without this the case above would also pass on an application that refused
  // everything.
  it('still signs a user in over bearer', async () => {
    const registered = await request(boot.app.getHttpServer()).post('/register').send({
      email: 'no-cookie-parser@example.com',
      password: 'NoCookieParser123!-xyz',
      name: 'No Parser',
      tenantId: 'tenant-1'
    })

    expect(registered.status).toBe(201)

    const me = await request(boot.app.getHttpServer())
      .get('/me')
      .set('Authorization', `Bearer ${(registered.body as { accessToken: string }).accessToken}`)

    expect(me.status).toBe(200)
  })
})

// ---------------------------------------------------------------------------
// Harness fidelity — the controller's own pipe must reach the wire
// ---------------------------------------------------------------------------

describe('the published validation contract reaches the wire (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp()
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies an undeclared property is REFUSED, not stripped — which is what
  // `createAuthValidationPipe`'s `forbidNonWhitelisted: true` publishes.
  //
  // This guards the harness against itself. Installing any global pipe with `whitelist: true`
  // strips unknown properties before the controller-scoped pipe can refuse them, so the suite
  // exercises a request production never sees. That is not hypothetical: it hid a real defect —
  // `POST /password/change` refused the `refreshToken` its own handler reads, because
  // `ChangePasswordDto` did not declare it and the stripping pipe removed the field before the
  // refusal could happen. Every E2E passed over it, and a consumer running no global pipe met the
  // 400 in production.
  //
  // Asserted as BEHAVIOUR rather than as the absence of `useGlobalPipes` in this file. A source
  // check would be defeated by moving the registration; this one fails whatever re-introduces the
  // stripping, including a dependency that registers a pipe of its own.
  it('refuses an undeclared property instead of stripping it', async () => {
    const res = await request(boot.app.getHttpServer())
      .post('/register')
      .send({
        email: `whitelist-probe-${Math.random().toString(36).slice(2)}@example.com`,
        password: 'ProbePass123!-xyz',
        name: 'Whitelist Probe',
        tenantId: 'tenant-1',
        undeclaredProperty: 'x'
      })

    expectAuthError(res, 'auth.validation')
    expect((res.body as { error: { details: { field: string }[] } }).error.details).toContainEqual(
      expect.objectContaining({ field: 'undeclaredProperty' })
    )
  })
})

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

    expectAuthError(res, 'auth.invalid_invitation_token')
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
    provider.sendInvitation = (async (tenantId, toEmail, data) => {
      capturedToken = data.inviteToken
      return originalSend(tenantId, toEmail, data)
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
    expectAuthError(accept2, 'auth.invalid_invitation_token')
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

    expectAuthError(res, 'auth.session_not_found')
  })

  // Verifies that POST /sessions/revoke-all without a refresh token in the request
  // is rejected with SESSION_NOT_FOUND — the controller cannot determine which
  // session to keep alive without the token.
  //
  // The route is asserted as its own verb for a reason: while it was `DELETE /sessions/all`,
  // this test kept passing after the handler moved, because `DELETE /sessions/:id` matched
  // `all` as an id and answered the same code. A test that cannot tell the endpoint it means
  // from the one next to it is not testing the endpoint.
  it('should reject POST /sessions/revoke-all with SESSION_NOT_FOUND when no refresh token is present', async () => {
    const user = await registerAndLogin(
      boot,
      `noref-${Math.random().toString(36).slice(2)}@example.com`
    )

    // Bearer-mode call without a refresh-token body is the failure scenario
    // the controller specifically guards against.
    const res = await request(boot.app.getHttpServer())
      .post('/sessions/revoke-all')
      .set('Authorization', `Bearer ${user.accessToken}`)
    // intentionally no body

    expectAuthError(res, 'auth.session_not_found')
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

      expectAuthError(res, 'auth.password_reset_token_invalid')
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

      // OTP_INVALID on first wrong attempt — OTP_MAX_ATTEMPTS only appears
      // after exceeding the lib's attempt budget.
      expectAuthError(res, 'auth.otp_invalid')
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

    expectAuthError(res, 'auth.oauth_failed')
  })

  // Verifies that omitting `tenantId` from /oauth/:provider is rejected by the DTO pipe — so an
  // OAuth flow cannot start without a tenant scope.
  //
  // Asserts the envelope, not just the status. `status === 400` was satisfied by the framework's
  // own `{ statusCode, message, error }` shape just as well as by the library's, which is how the
  // global pipe in `setup.ts` shadowed `createAuthValidationPipe` unnoticed: this was the only
  // E2E touching a DTO failure, and it could not see which pipe answered.
  it('should reject /oauth/google with auth.validation when tenantId is missing', async () => {
    const res = await request(boot.app.getHttpServer()).get('/oauth/google')

    expectAuthError(res, 'auth.validation')
    expect((res.body as { error: { details: { field: string }[] } }).error.details).toContainEqual(
      expect.objectContaining({ field: 'tenantId' })
    )
  })
})

// ---------------------------------------------------------------------------
// tenantId under a configured resolver — refused, not discarded
// ---------------------------------------------------------------------------

describe('body tenantId under a configured resolver (E2E)', () => {
  let boot: BootstrappedTestApp

  beforeAll(async () => {
    boot = await bootstrapTestApp({ tenantIdResolver: () => 'from-resolver' })
  })

  afterAll(async () => {
    await boot.app.close()
  })

  // Verifies the refusal over real HTTP, on the flow a security audit of a derived backend
  // reported. It used to answer 201 with the account created under the resolved tenant while the
  // caller believed it had chosen `attacker-chosen-tenant` — the caller's belief and the server's
  // state diverging on the tenancy boundary the resolver exists to defend, with nothing in the
  // response saying so.
  it('refuses a register whose body names a tenant', async () => {
    const res = await request(boot.app.getHttpServer())
      .post('/register')
      .send({
        email: `tenant-probe-${Math.random().toString(36).slice(2)}@example.com`,
        password: 'ProbePass123!-xyz',
        name: 'Tenant Probe',
        tenantId: 'attacker-chosen-tenant'
      })

    expectAuthError(res, 'auth.validation')
    expect((res.body as { error: { details: { field: string }[] } }).error.details).toEqual([
      { field: 'tenantId', message: expect.stringContaining('must not be sent') }
    ])
  })

  // Verifies the same body without the field still registers, so the refusal is about the
  // caller naming a tenant rather than about the endpoint being unusable under a resolver.
  it('accepts the same register once the body stops naming a tenant', async () => {
    const res = await request(boot.app.getHttpServer())
      .post('/register')
      .send({
        email: `tenant-ok-${Math.random().toString(36).slice(2)}@example.com`,
        password: 'ProbePass123!-xyz',
        name: 'Tenant Probe'
      })

    expect(res.status).toBe(201)
  })
})
