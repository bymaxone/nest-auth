/**
 * End-to-end invitation flow.
 *
 * Exercises the real HTTP routes registered by `InvitationController` through a
 * fully-bootstrapped NestJS application in bearer-token mode. The scenario
 * walks through the full invitation lifecycle:
 *
 *   1. An admin user is provisioned and logs in.
 *   2. POST /invitations creates a pending invitation for a new email.
 *   3. The raw token is extracted from the captured invitation email.
 *   4. POST /invitations/accept creates the new account and issues tokens.
 *   5. The invitee can immediately log in with the chosen password.
 *
 * The shared in-memory email mock in `setup.ts` discards the raw token because
 * production code never logs it. This suite installs a thin per-test override
 * on `sendInvitation` that embeds the real value into the captured `html` body,
 * mirroring what a real provider (Resend, SendGrid, …) would render — the same
 * technique used by `password-reset-flow.e2e-spec.ts`.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import type { InviteData } from '../../src/server/interfaces/email-provider.interface'
import type { CapturedEmail, MockEmailProvider, MockUserRepository } from './setup'
import { bootstrapTestApp } from './setup'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Patches a {@link MockEmailProvider} so that invitation sends embed the raw
 * token into the captured `html` body, the way a real provider would render
 * its template. Returning the same `sentEmails` reference allows callers to
 * keep a stable handle on the captures across the chain steps.
 */
function instrumentInvitationEmails(email: MockEmailProvider): CapturedEmail[] {
  // Reassign the method directly — the same `email` instance is held by the
  // NestJS DI container via `useValue`, so the service will call our override.
  ;(email as { sendInvitation: MockEmailProvider['sendInvitation'] }).sendInvitation = async (
    to: string,
    data: InviteData
  ): Promise<void> => {
    const html =
      `<p>${data.inviterName} invited you to ${data.tenantName}: ` +
      `<a href="https://app.example.com/accept-invite?token=${data.inviteToken}">Accept</a></p>`
    email.sentEmails.push({ to, subject: 'Invitation', html })
  }

  return email.sentEmails
}

/**
 * Polls the captured emails array until at least one entry matching `predicate`
 * exists, returning that entry. Required because the service may complete the
 * HTTP response before the email is appended to the array.
 *
 * @throws Error when no matching email arrives within `timeoutMs`.
 */
async function waitForEmail(
  sentEmails: CapturedEmail[],
  predicate: (email: CapturedEmail) => boolean,
  timeoutMs = 1_000
): Promise<CapturedEmail> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const found = sentEmails.find(predicate)
    if (found) return found
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
  throw new Error(`Timed out waiting for email after ${timeoutMs}ms`)
}

/**
 * Promotes the most recently created user with the given email to `admin` by
 * mutating the in-memory mock repo directly. The mock exposes its underlying
 * `Map` so tests can adjust persisted state without round-tripping through the
 * (intentionally minimal) `IUserRepository` surface.
 */
function promoteToAdmin(repo: MockUserRepository, email: string): void {
  for (const user of repo.users.values()) {
    if (user.email === email) {
      repo.users.set(user.id, { ...user, role: 'ADMIN' })
      return
    }
  }
  throw new Error(`No user with email ${email} found in the mock repo`)
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('invitations flow (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Scenario — admin invites → invitee accepts → invitee logs in
  //
  // The chain (register admin → promote → login → invite → extract token →
  // accept → assert stored user → login as invitee) runs in a single
  // `beforeAll` and the assertions are split across focused `it()` blocks. The
  // shared variables below mutate step-by-step inside that hook.
  // ---------------------------------------------------------------------------

  describe('admin invites a new member', () => {
    let app: INestApplication
    let repo: MockUserRepository
    let inviteStatus: number
    let acceptStatus: number
    let acceptBody: Record<string, unknown>
    let extractedToken: string
    let inviteeLoginStatus: number
    let inviteeLoginBody: Record<string, unknown>

    // Shared state mutates step-by-step inside this beforeAll. Each `it()` below
    // verifies one slice of that chain.
    beforeAll(async () => {
      const bootstrap = await bootstrapTestApp(
        {
          invitations: { enabled: true, tokenTtlSeconds: 3_600 }
        },
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
      const { app: _app, repo: _repo, email } = bootstrap
      app = _app
      repo = _repo
      const sentEmails = instrumentInvitationEmails(email)

      // Step 1 — register the future admin user. The default role assigned by
      // the mock repo on `create()` is 'MEMBER'; we promote in-memory to ADMIN
      // immediately afterwards so the JWT issued at login carries role: 'ADMIN'.
      await request(app.getHttpServer()).post('/register').send({
        email: 'admin@example.com',
        password: 'AdminSecret123!',
        name: 'Admin User',
        tenantId: 'tenant-1'
      })
      promoteToAdmin(repo, 'admin@example.com')

      // Step 2 — login as the admin to obtain a fresh access token whose JWT
      // payload reflects role: 'ADMIN' (login re-reads the user from the repo).
      const adminLogin = await request(app.getHttpServer()).post('/login').send({
        email: 'admin@example.com',
        password: 'AdminSecret123!',
        tenantId: 'tenant-1'
      })
      const adminAccessToken = adminLogin.body.accessToken as string

      // Step 3 — POST /invitations with the admin bearer token. Returns 204
      // No Content per the controller's @HttpCode(NO_CONTENT) decorator.
      const invite = await request(app.getHttpServer())
        .post('/invitations')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send({ email: 'invitee@example.com', role: 'MEMBER' })
      inviteStatus = invite.status

      // Step 4 — extract the raw invitation token from the captured email.
      // `generateSecureToken(32)` always emits exactly 64 hex chars, so a
      // single regex over the embedded URL suffices.
      const inviteEmail = await waitForEmail(
        sentEmails,
        (e) => e.to === 'invitee@example.com' && e.subject === 'Invitation'
      )
      const match = /[?&]token=([a-f0-9]+)/i.exec(inviteEmail.html)
      extractedToken = match ? (match[1] as string) : ''

      // Step 5 — POST /invitations/accept consumes the token and creates the
      // invitee account. Returns 201 Created with a full token pair.
      const accept = await request(app.getHttpServer())
        .post('/invitations/accept')
        .send({ token: extractedToken, name: 'Invitee', password: 'StrongPass123!' })
      acceptStatus = accept.status
      acceptBody = accept.body as Record<string, unknown>

      // Step 6 — login as the freshly-created invitee to confirm the password
      // hash was persisted correctly and the account is immediately usable.
      const inviteeLogin = await request(app.getHttpServer()).post('/login').send({
        email: 'invitee@example.com',
        password: 'StrongPass123!',
        tenantId: 'tenant-1'
      })
      inviteeLoginStatus = inviteeLogin.status
      inviteeLoginBody = inviteeLogin.body as Record<string, unknown>
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that POST /invitations with a valid admin bearer token returns 204 No Content.
    it('should accept the invitation request and return 204', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — InvitationController.invite is annotated with
      // @HttpCode(NO_CONTENT). A successful invite has no response body.
      expect(inviteStatus).toBe(204)
    })

    // Verifies that the captured invitation email embeds a 64-character hex token.
    it('should embed a 64-character hex token in the invitation email URL', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — `generateSecureToken(32)` always produces exactly 64 hex chars.
      expect(extractedToken).toMatch(/^[a-f0-9]{64}$/)
    })

    // Verifies that POST /invitations/accept returns 201 with a fresh token pair and the new user.
    it('should create the invitee account and return 201 with tokens', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — InvitationController.accept is annotated with
      // @HttpCode(CREATED). The body contains the standard AuthResult shape.
      expect(acceptStatus).toBe(201)
      expect(acceptBody['accessToken']).toEqual(expect.any(String))
      expect(acceptBody['refreshToken']).toEqual(expect.any(String))
      expect(acceptBody['user']).toEqual(
        expect.objectContaining({ email: 'invitee@example.com', name: 'Invitee' })
      )
    })

    // Verifies that the persisted invitee record was created with emailVerified: true and role MEMBER.
    it('should persist the invitee with emailVerified: true and role MEMBER', () => {
      // Arrange — performed in beforeAll.

      // Act — locate the persisted record by email in the mock repo's Map.
      const stored = Array.from(repo.users.values()).find((u) => u.email === 'invitee@example.com')

      // Assert — the invitation flow implies email ownership (no separate
      // verification step) and the role echoes the value supplied to /invitations.
      expect(stored).toBeDefined()
      expect(stored?.emailVerified).toBe(true)
      expect(stored?.role).toBe('MEMBER')
      expect(stored?.tenantId).toBe('tenant-1')
    })

    // Verifies that POST /login as the invitee succeeds with the chosen password.
    it('should allow the invitee to log in with the chosen password', () => {
      // Arrange — performed in beforeAll.

      // Act — performed in beforeAll.

      // Assert — the password hash was persisted correctly during /accept and
      // the credential check at /login matches it.
      expect(inviteeLoginStatus).toBe(200)
      expect(inviteeLoginBody['accessToken']).toEqual(expect.any(String))
      expect(inviteeLoginBody['refreshToken']).toEqual(expect.any(String))
      expect(inviteeLoginBody['user']).toEqual(
        expect.objectContaining({ email: 'invitee@example.com' })
      )
    })
  })

  describe('non-admin cannot create invitations', () => {
    // Verifies that a MEMBER-role user receives 403 Forbidden when calling POST /invitations.
    it('should return 403 when a non-admin tries to create an invitation', async () => {
      // Arrange — bootstrap a fresh app, register a regular MEMBER user (no
      // promotion to ADMIN), then login to obtain a bearer token whose JWT
      // payload reflects role: 'MEMBER'.
      const { app } = await bootstrapTestApp(
        {
          invitations: { enabled: true, tokenTtlSeconds: 3_600 }
        },
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
      try {
        await request(app.getHttpServer()).post('/register').send({
          email: 'member@example.com',
          password: 'MemberSecret123!',
          name: 'Member User',
          tenantId: 'tenant-1'
        })
        const memberLogin = await request(app.getHttpServer()).post('/login').send({
          email: 'member@example.com',
          password: 'MemberSecret123!',
          tenantId: 'tenant-1'
        })
        const memberAccessToken = memberLogin.body.accessToken as string

        // Act — POST /invitations with a MEMBER bearer token, attempting to
        // issue the higher ADMIN role. InvitationService.invite enforces that
        // the inviter must hold a role >= the requested role via hasRole().
        const invite = await request(app.getHttpServer())
          .post('/invitations')
          .set('Authorization', `Bearer ${memberAccessToken}`)
          .send({ email: 'someone@example.com', role: 'ADMIN' })

        // Assert — the service throws ForbiddenException (INSUFFICIENT_ROLE),
        // which Nest serializes as 403 Forbidden. No invitation is persisted
        // and no email is sent.
        expect(invite.status).toBe(403)
      } finally {
        await app.close()
      }
    })
  })
})
