/**
 * End-to-end OAuth 2.0 Authorization Code flow.
 *
 * Exercises the real HTTP routes registered by `OAuthController` through a
 * fully-bootstrapped NestJS application. The Google provider plugin is replaced
 * with an in-memory mock via `OAUTH_PLUGINS` provider override so the suite
 * never touches accounts.google.com or oauth2.googleapis.com — every assertion
 * runs against the actual library wiring (CSRF state lifecycle, hook invocation,
 * token issuance) without a network dependency.
 *
 * The scenarios mirror the production flow:
 *   1. GET /oauth/google initiates the flow and produces a 302 redirect that
 *      embeds the CSRF `state` query parameter.
 *   2. GET /oauth/google/callback with a fresh state and a hook returning
 *      `{ action: 'create' }` provisions a new user via `createWithOAuth` and
 *      returns bearer tokens.
 *   3. A second callback for the same providerId, with the hook returning
 *      `{ action: 'link', userId }`, links the OAuth identity to an existing
 *      user and issues tokens for that user.
 *   4. A callback with an unknown state value triggers `OAUTH_FAILED` and a
 *      401 response.
 *   5. (1.0.7) An MFA-enabled user routed through OAuth must complete the
 *      MFA challenge before a session is issued — exercises both the cookie+
 *      JSON branch (no mfaRedirectUrl) and the cookie+302 branch.
 *   6. (1.0.7) An OAuth error redirects to `errorRedirectUrl` with `?error=`
 *      when configured, and otherwise propagates as a JSON exception.
 */

import * as crypto from 'node:crypto'

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import { encrypt } from '../../src/server/crypto/aes-gcm'
import type {
  HookContext,
  IAuthHooks,
  OAuthLoginResult
} from '../../src/server/interfaces/auth-hooks.interface'
import type {
  OAuthProfile,
  OAuthProviderPlugin
} from '../../src/server/interfaces/oauth-provider.interface'
import type { SafeAuthUser } from '../../src/server/interfaces/user-repository.interface'
import { OAUTH_PLUGINS } from '../../src/server/oauth/oauth.constants'
import type { MockUserRepository } from './setup'
import { bootstrapTestApp, MFA_ENCRYPTION_KEY } from './setup'

// ---------------------------------------------------------------------------
// Mock Google plugin
// ---------------------------------------------------------------------------

/** Stable provider id used by the mock plugin across every callback. */
const MOCK_PROVIDER_ID = 'google_user_123'

/** Stable email returned by the mock plugin's profile fetch. */
const MOCK_EMAIL = 'oauth@example.com'

/**
 * Deterministic test profile returned by `fetchProfile`.
 *
 * Defining it as a top-level constant keeps the mock plugin pure — every call
 * resolves with exactly the same payload, mirroring how a real provider would
 * answer for the same authenticated user.
 */
const MOCK_PROFILE: OAuthProfile = {
  provider: 'google',
  providerId: MOCK_PROVIDER_ID,
  email: MOCK_EMAIL,
  name: 'OAuth User',
  // The provider asserts it verified this address. A plugin that cannot assert it must send
  // `false`, and the account is created unverified — the whole reason the field is required.
  emailVerified: true
}

/**
 * Builds a fresh mock {@link OAuthProviderPlugin} that conforms to the actual
 * production plugin contract.
 *
 * The mock ignores the `code` argument entirely — the production code path
 * (state lookup, hook invocation, repo access, token issuance) is exercised
 * end-to-end against the real services without needing to talk to Google.
 *
 * Each call returns a new instance with fresh `jest.fn()` spies so suites can
 * assert call counts independently.
 */
function createMockGooglePlugin(): OAuthProviderPlugin {
  return {
    name: 'google',
    authorizeUrl: jest.fn(
      (state: string, _codeChallenge?: string): string =>
        `https://example.com/oauth/google?state=${state}`
    ),
    exchangeCode: jest.fn(
      async (
        _code: string,
        _codeVerifier?: string
      ): Promise<{ access_token: string; token_type: string }> => ({
        access_token: 'mock_access_token',
        token_type: 'Bearer'
      })
    ),
    fetchProfile: jest.fn(async (_accessToken: string): Promise<OAuthProfile> => MOCK_PROFILE)
  }
}

// ---------------------------------------------------------------------------
// Hook helpers
// ---------------------------------------------------------------------------

/**
 * Mutable container for the `onOAuthLogin` return value.
 *
 * Each scenario sets `current` to the `OAuthLoginResult` it wants returned for
 * the next callback. The hooks instance registered with NestJS dereferences
 * `current` at call time, so per-scenario tweaks take effect without a fresh
 * module compilation.
 */
interface HookController {
  current: OAuthLoginResult | null
  /** Records the (profile, existingUser) tuple seen by the hook for assertions. */
  lastCall: {
    profile: OAuthProfile
    existingUser: SafeAuthUser | null
  } | null
}

/**
 * Builds an {@link IAuthHooks} implementation backed by the {@link HookController}.
 *
 * Only `onOAuthLogin` is implemented — the other hooks are intentionally absent
 * because the OAuth flow exercises only that single lifecycle point.
 */
function createControlledHooks(controller: HookController): IAuthHooks {
  return {
    async onOAuthLogin(
      profile: OAuthProfile,
      existingUser: SafeAuthUser | null,
      _context: HookContext
    ): Promise<OAuthLoginResult> {
      controller.lastCall = { profile, existingUser }
      if (!controller.current) {
        // Treat missing setup as a deliberate reject so misconfigured tests fail loudly.
        return { action: 'reject', reason: 'no hook result configured' }
      }
      return controller.current
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extracts the `state` query parameter from a `Location` header value.
 *
 * The mock plugin formats its authorize URL as
 * `https://example.com/oauth/google?state=<value>`, so a single `URL` parse
 * is enough; falls back to a regex for resilience if the format ever changes.
 */
function extractStateFromLocation(location: string | undefined): string {
  if (!location) throw new Error('Location header missing on OAuth initiation response')
  // Use the WHATWG URL parser — robust against trailing slashes, repeated params, etc.
  const parsed = new URL(location)
  const state = parsed.searchParams.get('state')
  if (!state) throw new Error(`No state query param in Location header: ${location}`)
  return state
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('oauth flow (E2E)', () => {
  // ---------------------------------------------------------------------------
  // Scenario — full OAuth lifecycle (initiate → create → link → invalid state)
  //
  // The scenarios are chained: the user created in scenario 2 is linked again
  // in scenario 3, mirroring how a single Google account moves through the
  // create-then-link path in production. A single bootstrap is shared so the
  // in-memory repo and Redis state persist across the chain.
  // ---------------------------------------------------------------------------

  describe('full lifecycle', () => {
    let app: INestApplication
    let repo: MockUserRepository
    let hookController: HookController
    let plugin: OAuthProviderPlugin

    // First-callback state captured during scenario 1 and consumed by scenario 2.
    let initiateState: string

    // User id provisioned by scenario 2 — used by scenario 3 to drive the
    // `link` action through the same providerId.
    let createdUserId: string

    beforeAll(async () => {
      hookController = { current: null, lastCall: null }
      const hooks = createControlledHooks(hookController)
      plugin = createMockGooglePlugin()

      const bootstrap = await bootstrapTestApp(
        {
          oauth: {
            google: {
              clientId: 'test-client-id',
              clientSecret: 'test-client-secret',
              callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
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
          extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }],
          mutateBuilder: (builder) =>
            builder.overrideProvider(OAUTH_PLUGINS).useValue([plugin]) as typeof builder
        }
      )
      app = bootstrap.app
      repo = bootstrap.repo
    })

    afterAll(async () => {
      await app.close()
    })

    // Verifies that GET /oauth/google issues a 302 redirect carrying a non-empty `state` query parameter.
    it('should redirect with a non-empty state on initiation', async () => {
      // Arrange — no per-test setup; the mock plugin's authorizeUrl is deterministic.

      // Act
      const res = await request(app.getHttpServer()).get('/oauth/google').query({
        tenantId: 'tenant-1'
      })

      // Assert
      expect(res.status).toBe(302)
      const location = res.headers['location'] as string | undefined
      const state = extractStateFromLocation(location)
      expect(state.length).toBeGreaterThan(0)
      // The library generates a 32-byte hex nonce — 64 lowercase hex chars.
      expect(state).toMatch(/^[0-9a-f]{64}$/)
      expect(plugin.authorizeUrl).toHaveBeenCalledWith(state, expect.any(String))

      // Capture for scenario 2.
      initiateState = state
    })

    // Verifies that the callback with a valid state and a `create` hook provisions a user and returns bearer tokens.
    it('should create a user and issue tokens when the hook returns action: create', async () => {
      // Arrange — wire the hook to request a fresh user account on this callback.
      hookController.current = { action: 'create' }

      // Act
      const res = await request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'fake_code', state: initiateState })

      // Assert — bearer-mode response carries access + refresh tokens and a user object.
      expect(res.status).toBe(200)
      expect(res.body).toEqual(
        expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          user: expect.objectContaining({
            email: MOCK_EMAIL,
            tenantId: 'tenant-1',
            oauthProvider: 'google',
            oauthProviderId: MOCK_PROVIDER_ID
          })
        })
      )
      // Credentials must NOT leak into the serialised response payload.
      expect(res.body.user).not.toHaveProperty('passwordHash')
      expect(res.body.user).not.toHaveProperty('mfaSecret')

      // The hook saw a null existingUser because no record matched the providerId yet.
      expect(hookController.lastCall?.existingUser).toBeNull()
      expect(hookController.lastCall?.profile.providerId).toBe(MOCK_PROVIDER_ID)

      // The mock repo persists the new user under the OAuth fields.
      const persisted = await repo.findByOAuthId('google', MOCK_PROVIDER_ID, 'tenant-1')
      expect(persisted).not.toBeNull()
      expect(persisted?.email).toBe(MOCK_EMAIL)
      expect(persisted?.passwordHash).toBeNull()
      createdUserId = persisted!.id
    })

    // Verifies that a second callback with the same providerId and a `link` hook returns tokens for the existing user.
    it('should link the existing user and issue tokens when the hook returns action: link', async () => {
      // Arrange — request a fresh state for the second flow (the previous one was
      // single-use and has already been consumed).
      const initiate = await request(app.getHttpServer()).get('/oauth/google').query({
        tenantId: 'tenant-1'
      })
      const freshState = extractStateFromLocation(
        initiate.headers['location'] as string | undefined
      )
      expect(freshState).not.toBe(initiateState)

      // Wire the hook for the link path.
      hookController.current = { action: 'link', userId: createdUserId } as OAuthLoginResult & {
        userId: string
      }

      // Act
      const res = await request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'fake_code2', state: freshState })

      // Assert — the existing user is returned, identified by the same id from scenario 2.
      expect(res.status).toBe(200)
      expect(res.body).toEqual(
        expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          user: expect.objectContaining({
            id: createdUserId,
            email: MOCK_EMAIL,
            oauthProvider: 'google',
            oauthProviderId: MOCK_PROVIDER_ID
          })
        })
      )

      // The hook's existingUser argument must reflect the user persisted in scenario 2.
      expect(hookController.lastCall?.existingUser?.id).toBe(createdUserId)

      // No new user was created — the repo still holds exactly one OAuth identity for this profile.
      let matchCount = 0
      for (const u of repo.users.values()) {
        if (u.oauthProvider === 'google' && u.oauthProviderId === MOCK_PROVIDER_ID) {
          matchCount += 1
        }
      }
      expect(matchCount).toBe(1)
    })

    // Verifies that the callback returns 401 with the OAUTH_FAILED code when the state value is unknown.
    it('should reject the callback with 401 OAUTH_FAILED when the state is invalid', async () => {
      // Arrange — set up the hook just to prove it never gets invoked (state validation
      // runs before any plugin or hook code path).
      hookController.current = { action: 'create' }
      hookController.lastCall = null

      // Act — supply a structurally valid (length-wise) but unknown state value.
      const res = await request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'foo', state: 'a'.repeat(64) })

      // Assert — AuthException(OAUTH_FAILED) maps to HTTP 401 via AuthExceptionFilter.
      // The filter envelopes the AuthException payload under an `error` field, so
      // assert against `body.error.code` rather than the bare top-level `code`.
      expect(res.status).toBe(401)
      expect(res.body).toEqual(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'auth.oauth_failed'
          })
        })
      )

      // The hook must not have been called — state validation gates everything else.
      expect(hookController.lastCall).toBeNull()
    })

    // Verifies that Google's standard OIDC + Account-chooser query parameters
    // (iss, scope, authuser, prompt, hd) do not cause the controller-level
    // ValidationPipe(forbidNonWhitelisted: true) to reject the callback.
    // Real-world callback URLs from accounts.google.com include these params;
    // the DTO accepts them as @IsOptional and the service ignores them.
    it('should accept the callback when Google adds iss / scope / authuser / prompt / hd', async () => {
      // Arrange — fresh state plus a hook that returns a brand-new user. The
      // hook is the only path that depends on tenantId, so we use the same
      // tenant the previous scenarios used.
      const initiate = await request(app.getHttpServer()).get('/oauth/google').query({
        tenantId: 'tenant-1'
      })
      const freshState = extractStateFromLocation(
        initiate.headers['location'] as string | undefined
      )
      hookController.current = { action: 'create' }
      hookController.lastCall = null
      // A distinct address and provider id: the scenarios above already created an account for
      // MOCK_EMAIL, and a `create` onto an address that is already taken is now a 409 by
      // design. This scenario is about query-param tolerance, so it needs a free address.
      ;(plugin.fetchProfile as jest.Mock).mockResolvedValueOnce({
        ...MOCK_PROFILE,
        email: 'extras@example.com',
        providerId: 'google-extras-1'
      })

      // Act — append every Google-specific query parameter the lib must
      // tolerate, exactly as accounts.google.com sends them on a successful
      // consent. The route used to 400 with "property iss should not exist".
      const res = await request(app.getHttpServer()).get('/oauth/google/callback').query({
        code: 'fake_code_with_extras',
        state: freshState,
        iss: 'https://accounts.google.com',
        scope: 'openid email profile',
        authuser: '0',
        prompt: 'consent',
        hd: 'example.com'
      })

      // Assert — the request must complete the same way it does without the
      // extra params: a 200 with bearer tokens and the user object. The
      // extras must NOT leak into the response (the lib only reads code/state).
      expect(res.status).toBe(200)
      expect(res.body).toEqual(
        expect.objectContaining({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
          user: expect.objectContaining({
            email: 'extras@example.com',
            oauthProvider: 'google'
          })
        })
      )

      // Hook ran, confirming the extra params reached the controller without
      // triggering forbidNonWhitelisted on the way in.
      expect(hookController.lastCall).not.toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario — oauth.successRedirectUrl (browser OAuth flow)
  //
  // Verifies the 1.0.4 redirect option. With successRedirectUrl set, the
  // callback responds with a 302 to the configured URL (carrying cookies in
  // the same response) instead of returning the JSON payload that API
  // consumers expect. The auth cookies must still be set so the destination
  // page is authenticated on the follow-up navigation.
  // ---------------------------------------------------------------------------

  describe('with successRedirectUrl configured', () => {
    let app: INestApplication
    let plugin: OAuthProviderPlugin
    let hookController: HookController

    beforeAll(async () => {
      hookController = { current: null, lastCall: null }
      const hooks = createControlledHooks(hookController)
      plugin = createMockGooglePlugin()

      const bootstrap = await bootstrapTestApp(
        {
          // Cookie mode is required by the resolveOptions validator when
          // successRedirectUrl is set — bearer-only delivery would discard
          // the access token in the 302 response body.
          tokenDelivery: 'cookie',
          oauth: {
            successRedirectUrl: '/dashboard',
            google: {
              clientId: 'redir-test-client-id',
              clientSecret: 'redir-test-client-secret',
              callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
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
          extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }],
          mutateBuilder: (builder) =>
            builder.overrideProvider(OAUTH_PLUGINS).useValue([plugin]) as typeof builder
        }
      )
      app = bootstrap.app
    })

    afterAll(async () => {
      await app.close()
    })

    /**
     * Verifies the browser path. The supertest agent does NOT follow redirects
     * by default, so the assertion can pin both the status (302) and the
     * `Location` header to the configured URL. The response body must be empty
     * — Nest's passthrough mode returns no JSON when the handler returns
     * `undefined`, which is exactly what the redirect branch does.
     */
    it('should respond 302 to successRedirectUrl after a successful callback', async () => {
      hookController.current = { action: 'create' }

      const initiate = await request(app.getHttpServer()).get('/oauth/google').query({
        tenantId: 'tenant-1'
      })
      const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

      const res = await request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'redir_code', state })

      expect(res.status).toBe(302)
      expect(res.headers['location']).toBe('/dashboard')
      // No JSON payload accompanies the redirect — the browser will not see
      // the access token in a body it discards anyway.
      expect(res.body).toEqual({})
    })

    /**
     * Verifies that auth cookies are still issued on the 302 response. The
     * cookie-mode delivery sets `Set-Cookie` headers before the redirect runs,
     * so a single response carries both the 302 AND the credentials the
     * destination page needs.
     */
    it('should still set auth cookies on the 302 response', async () => {
      hookController.current = { action: 'create' }
      // Its own address, for the same reason as the query-param scenario: this describes
      // cookie delivery on a redirect, not a second account for an address already taken.
      ;(plugin.fetchProfile as jest.Mock).mockResolvedValueOnce({
        ...MOCK_PROFILE,
        email: 'redirect-cookies@example.com',
        providerId: 'google-redirect-1'
      })

      const initiate = await request(app.getHttpServer()).get('/oauth/google').query({
        tenantId: 'tenant-1'
      })
      const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

      const res = await request(app.getHttpServer())
        .get('/oauth/google/callback')
        .query({ code: 'redir_cookie_code', state })

      expect(res.status).toBe(302)
      const setCookie = res.headers['set-cookie']
      // The lib's TokenDeliveryService writes the access + refresh cookies on
      // the same response that carries the redirect headers. Both cookies must
      // be present so the destination page can authenticate on the next request.
      expect(Array.isArray(setCookie) ? setCookie.join('\n') : (setCookie ?? '')).toMatch(
        /access_token=/
      )
      expect(Array.isArray(setCookie) ? setCookie.join('\n') : (setCookie ?? '')).toMatch(
        /refresh_token=/
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario — OAuth + MFA (1.0.7)
  //
  // When the resolved user has MFA enabled, the OAuth callback must NOT issue
  // session tokens directly — that would leave the user with `mfaVerified: false`
  // and the MfaRequiredGuard would lock them out on every subsequent request.
  // Instead, the callback plants a short-lived HttpOnly `mfa_temp_token` cookie
  // path-scoped to `/auth/mfa` and either redirects to `mfaRedirectUrl` or
  // returns the temp token as JSON. The user completes `POST /auth/mfa/challenge`
  // (which now also reads the token from the cookie) to obtain real session
  // tokens.
  // ---------------------------------------------------------------------------

  describe('with MFA-enabled user (1.0.7)', () => {
    /** Helper to seed an MFA-enabled user into the in-memory repo. */
    function seedMfaUser(
      repo: MockUserRepository,
      params: { tenantId: string; email: string; providerId: string; mfaSecret: string }
    ): string {
      const id = `user-mfa-${params.providerId}`
      repo.users.set(id, {
        id,
        email: params.email,
        name: 'MFA User',
        passwordHash: null,
        role: 'MEMBER',
        status: 'active',
        tenantId: params.tenantId,
        emailVerified: true,
        mfaEnabled: true,
        mfaSecret: params.mfaSecret,
        mfaRecoveryCodes: [],
        oauthProvider: 'google',
        oauthProviderId: params.providerId,
        lastLoginAt: null,
        createdAt: new Date()
      })
      return id
    }

    describe('without mfaRedirectUrl', () => {
      let app: INestApplication
      let plugin: OAuthProviderPlugin
      let hookController: HookController
      let repo: MockUserRepository

      beforeAll(async () => {
        hookController = { current: null, lastCall: null }
        const hooks = createControlledHooks(hookController)
        plugin = createMockGooglePlugin()
        // Override the mock plugin to return a distinct providerId so this
        // suite does not collide with the lifecycle suite's seeded user.
        ;(plugin.fetchProfile as jest.Mock).mockResolvedValue({
          ...MOCK_PROFILE,
          providerId: 'mfa-provider-id'
        })

        const bootstrap = await bootstrapTestApp(
          {
            tokenDelivery: 'bearer',
            oauth: {
              google: {
                clientId: 'mfa-test-client',
                clientSecret: 'mfa-test-secret',
                callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
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
            extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }],
            mutateBuilder: (builder) =>
              builder.overrideProvider(OAUTH_PLUGINS).useValue([plugin]) as typeof builder
          }
        )
        app = bootstrap.app
        repo = bootstrap.repo
      })

      afterAll(async () => {
        await app.close()
      })

      /**
       * Verifies the JSON path: when no `mfaRedirectUrl` is configured the
       * callback returns `{ mfaRequired: true, mfaTempToken }` and plants the
       * `mfa_temp_token` cookie path-scoped to the MFA challenge route.
       * Session tokens MUST NOT be issued — `MfaRequiredGuard` would otherwise
       * lock the user out on subsequent requests.
       */
      it('should plant mfa_temp_token cookie and return JSON mfaRequired payload', async () => {
        const secret = generateBase32Secret()
        seedMfaUser(repo, {
          tenantId: 'tenant-1',
          email: 'oauth-mfa@example.com',
          providerId: 'mfa-provider-id',
          mfaSecret: encryptForMfa(secret)
        })
        hookController.current = {
          action: 'link',
          userId: 'user-mfa-mfa-provider-id'
        } as OAuthLoginResult & { userId: string }

        const initiate = await request(app.getHttpServer())
          .get('/oauth/google')
          .query({ tenantId: 'tenant-1' })
        const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

        const res = await request(app.getHttpServer())
          .get('/oauth/google/callback')
          .query({ code: 'mfa_code_1', state })

        expect(res.status).toBe(200)
        expect(res.body).toEqual({
          mfaRequired: true,
          mfaTempToken: expect.any(String)
        })
        // Tokens must NOT be issued on the MFA branch.
        expect(res.body.accessToken).toBeUndefined()
        expect(res.body.refreshToken).toBeUndefined()

        // mfa_temp_token cookie was planted, path-scoped to /auth/mfa.
        const setCookieHeader = res.headers['set-cookie']
        const cookieString = Array.isArray(setCookieHeader)
          ? setCookieHeader.join('\n')
          : (setCookieHeader ?? '')
        expect(cookieString).toMatch(/mfa_temp_token=/)
        expect(cookieString).toMatch(/Path=\/auth\/mfa/)
        expect(cookieString).toMatch(/HttpOnly/i)
      })

      /**
       * Verifies the cookie-driven MFA challenge: the cookie planted by the
       * callback is forwarded back on `POST /auth/mfa/challenge`, the body
       * carries ONLY the TOTP code, and the lib returns full session tokens.
       */
      it('should complete the MFA challenge using the cookie-only flow', async () => {
        const secret = generateBase32Secret()
        seedMfaUser(repo, {
          tenantId: 'tenant-1',
          email: 'cookie-flow@example.com',
          providerId: 'cookie-flow-provider-id',
          mfaSecret: encryptForMfa(secret)
        })
        ;(plugin.fetchProfile as jest.Mock).mockResolvedValueOnce({
          ...MOCK_PROFILE,
          providerId: 'cookie-flow-provider-id',
          email: 'cookie-flow@example.com'
        })
        hookController.current = {
          action: 'link',
          userId: 'user-mfa-cookie-flow-provider-id'
        } as OAuthLoginResult & { userId: string }

        const initiate = await request(app.getHttpServer())
          .get('/oauth/google')
          .query({ tenantId: 'tenant-1' })
        const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

        const callback = await request(app.getHttpServer())
          .get('/oauth/google/callback')
          .query({ code: 'mfa_code_2', state })

        // Build the cookie header the way the browser would.
        const setCookieHeader = callback.headers['set-cookie']
        const cookies = Array.isArray(setCookieHeader)
          ? setCookieHeader
          : setCookieHeader
            ? [setCookieHeader]
            : []
        const mfaCookieHeader = cookies
          .map((entry) => entry.split(';')[0])
          .find((kv) => kv?.startsWith('mfa_temp_token='))
        expect(mfaCookieHeader).toBeDefined()

        // Generate a valid TOTP for the seeded secret.
        const totp = generateTotp(secret)

        // Submit ONLY the code in the body — the cookie carries the temp token.
        const challenge = await request(app.getHttpServer())
          .post('/mfa/challenge')
          .set('Cookie', mfaCookieHeader!)
          .send({ code: totp })

        expect(challenge.status).toBe(200)
        expect(challenge.body).toEqual(
          expect.objectContaining({
            accessToken: expect.any(String),
            refreshToken: expect.any(String),
            user: expect.objectContaining({ email: 'cookie-flow@example.com' })
          })
        )

        // The cookie was cleared on the response.
        const clearCookieHeader = challenge.headers['set-cookie']
        const clearedCookies = Array.isArray(clearCookieHeader)
          ? clearCookieHeader.join('\n')
          : (clearCookieHeader ?? '')
        // clearCookie sets Expires=Thu, 01 Jan 1970 OR Max-Age=0 depending on the
        // Express version — accept either.
        expect(clearedCookies).toMatch(/mfa_temp_token=;/)
      })

      it('should accept a retry with the correct code after a wrong code (v1.0.8 regression)', async () => {
        /*
         * Scenario: prior to v1.0.8 the JWT was consumed by `verifyMfaTempToken`
         * BEFORE the TOTP was validated, so a single mistyped digit killed the
         * token in Redis and every subsequent attempt surfaced as
         * `MFA_TEMP_TOKEN_INVALID` ("MFA session expired"). This test mints a
         * fresh OAuth-driven temp token, submits a deliberately wrong code,
         * asserts the failure is `MFA_INVALID_CODE` (not token-invalid), then
         * submits the correct code under the SAME cookie and asserts the
         * challenge succeeds — proving the JWT is still alive for retry.
         * Protects the split verify/consume contract added in v1.0.8.
         */
        const secret = generateBase32Secret()
        seedMfaUser(repo, {
          tenantId: 'tenant-1',
          email: 'retry-flow@example.com',
          providerId: 'retry-flow-provider-id',
          mfaSecret: encryptForMfa(secret)
        })
        ;(plugin.fetchProfile as jest.Mock).mockResolvedValueOnce({
          ...MOCK_PROFILE,
          providerId: 'retry-flow-provider-id',
          email: 'retry-flow@example.com'
        })
        hookController.current = {
          action: 'link',
          userId: 'user-mfa-retry-flow-provider-id'
        } as OAuthLoginResult & { userId: string }

        const initiate = await request(app.getHttpServer())
          .get('/oauth/google')
          .query({ tenantId: 'tenant-1' })
        const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

        const callback = await request(app.getHttpServer())
          .get('/oauth/google/callback')
          .query({ code: 'mfa_code_retry', state })

        const setCookieHeader = callback.headers['set-cookie']
        const cookies = Array.isArray(setCookieHeader)
          ? setCookieHeader
          : setCookieHeader
            ? [setCookieHeader]
            : []
        const mfaCookieHeader = cookies
          .map((entry) => entry.split(';')[0])
          .find((kv) => kv?.startsWith('mfa_temp_token='))
        expect(mfaCookieHeader).toBeDefined()

        // ── Attempt #1 — deliberately wrong code. The lib must surface
        // `MFA_INVALID_CODE` and KEEP the cookie alive so retry works.
        const firstAttempt = await request(app.getHttpServer())
          .post('/mfa/challenge')
          .set('Cookie', mfaCookieHeader!)
          .send({ code: '000000' })

        expect(firstAttempt.status).toBe(401)
        expect(firstAttempt.body).toEqual(
          expect.objectContaining({
            error: expect.objectContaining({ code: 'auth.mfa_invalid_code' })
          })
        )
        const firstSetCookie = firstAttempt.headers['set-cookie']
        // The cookie must NOT be cleared on MFA_INVALID_CODE — retry depends on it.
        const firstClearHeaders = Array.isArray(firstSetCookie)
          ? firstSetCookie.join('\n')
          : (firstSetCookie ?? '')
        expect(firstClearHeaders).not.toMatch(/mfa_temp_token=;/)

        // ── Attempt #2 — correct TOTP under the SAME cookie. The lib must
        // accept it because the JWT is still alive in Redis.
        const totp = generateTotp(secret)
        const secondAttempt = await request(app.getHttpServer())
          .post('/mfa/challenge')
          .set('Cookie', mfaCookieHeader!)
          .send({ code: totp })

        expect(secondAttempt.status).toBe(200)
        expect(secondAttempt.body).toEqual(
          expect.objectContaining({
            accessToken: expect.any(String),
            refreshToken: expect.any(String),
            user: expect.objectContaining({ email: 'retry-flow@example.com' })
          })
        )

        // The cookie IS cleared on success — the JWT has been consumed.
        const secondSetCookie = secondAttempt.headers['set-cookie']
        const secondClearHeaders = Array.isArray(secondSetCookie)
          ? secondSetCookie.join('\n')
          : (secondSetCookie ?? '')
        expect(secondClearHeaders).toMatch(/mfa_temp_token=;/)
      })
    })

    describe('with mfaRedirectUrl', () => {
      let app: INestApplication
      let plugin: OAuthProviderPlugin
      let hookController: HookController
      let repo: MockUserRepository

      beforeAll(async () => {
        hookController = { current: null, lastCall: null }
        const hooks = createControlledHooks(hookController)
        plugin = createMockGooglePlugin()
        ;(plugin.fetchProfile as jest.Mock).mockResolvedValue({
          ...MOCK_PROFILE,
          providerId: 'mfa-redir-id',
          email: 'mfa-redir@example.com'
        })

        const bootstrap = await bootstrapTestApp(
          {
            tokenDelivery: 'bearer',
            oauth: {
              mfaRedirectUrl: '/auth/mfa-challenge',
              google: {
                clientId: 'mfa-redir-client',
                clientSecret: 'mfa-redir-secret',
                callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
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
            extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }],
            mutateBuilder: (builder) =>
              builder.overrideProvider(OAUTH_PLUGINS).useValue([plugin]) as typeof builder
          }
        )
        app = bootstrap.app
        repo = bootstrap.repo
      })

      afterAll(async () => {
        await app.close()
      })

      /**
       * Verifies the browser path: with `mfaRedirectUrl` configured, the
       * callback issues a 302 with the cookie still planted on the response.
       */
      it('should respond 302 to mfaRedirectUrl with mfa_temp_token cookie set', async () => {
        const secret = generateBase32Secret()
        seedMfaUser(repo, {
          tenantId: 'tenant-1',
          email: 'mfa-redir@example.com',
          providerId: 'mfa-redir-id',
          mfaSecret: encryptForMfa(secret)
        })
        hookController.current = {
          action: 'link',
          userId: 'user-mfa-mfa-redir-id'
        } as OAuthLoginResult & { userId: string }

        const initiate = await request(app.getHttpServer())
          .get('/oauth/google')
          .query({ tenantId: 'tenant-1' })
        const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

        const res = await request(app.getHttpServer())
          .get('/oauth/google/callback')
          .query({ code: 'mfa_redir_code', state })

        expect(res.status).toBe(302)
        expect(res.headers['location']).toBe('/auth/mfa-challenge')
        // No JSON body alongside the redirect.
        expect(res.body).toEqual({})

        const setCookieHeader = res.headers['set-cookie']
        const cookieString = Array.isArray(setCookieHeader)
          ? setCookieHeader.join('\n')
          : (setCookieHeader ?? '')
        expect(cookieString).toMatch(/mfa_temp_token=/)
        expect(cookieString).toMatch(/Path=\/auth\/mfa/)
      })
    })
  })

  // ---------------------------------------------------------------------------
  // Scenario — OAuth error redirect (1.0.7)
  //
  // Symmetric polish for the success/MFA redirect paths: when the callback
  // fails with an `AuthException` (state invalid, plugin error, hook reject)
  // and `oauth.errorRedirectUrl` is configured, the lib redirects to that URL
  // with `?error=<code>` instead of propagating the JSON exception.
  // ---------------------------------------------------------------------------

  describe('error redirect (1.0.7)', () => {
    describe('with errorRedirectUrl configured', () => {
      let app: INestApplication
      let plugin: OAuthProviderPlugin
      let hookController: HookController

      beforeAll(async () => {
        hookController = { current: null, lastCall: null }
        const hooks = createControlledHooks(hookController)
        plugin = createMockGooglePlugin()

        const bootstrap = await bootstrapTestApp(
          {
            tokenDelivery: 'bearer',
            oauth: {
              errorRedirectUrl: '/auth/error',
              google: {
                clientId: 'err-test-client',
                clientSecret: 'err-test-secret',
                callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
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
            extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }],
            mutateBuilder: (builder) =>
              builder.overrideProvider(OAUTH_PLUGINS).useValue([plugin]) as typeof builder
          }
        )
        app = bootstrap.app
      })

      afterAll(async () => {
        await app.close()
      })

      /**
       * Verifies the redirect path: a hook that rejects the OAuth flow with
       * `{ action: 'reject' }` raises `OAUTH_FAILED` inside the service. The
       * controller catches that AuthException and 302s to the configured
       * URL with `?error=oauth_failed` appended.
       */
      it('should redirect to errorRedirectUrl with ?error=oauth_failed when the hook rejects', async () => {
        hookController.current = { action: 'reject', reason: 'no go' }

        const initiate = await request(app.getHttpServer())
          .get('/oauth/google')
          .query({ tenantId: 'tenant-1' })
        const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

        const res = await request(app.getHttpServer())
          .get('/oauth/google/callback')
          .query({ code: 'fail_code', state })

        expect(res.status).toBe(302)
        expect(res.headers['location']).toBe('/auth/error?error=oauth_failed')
        // No JSON body — only the redirect headers.
        expect(res.body).toEqual({})
      })
    })

    describe('without errorRedirectUrl', () => {
      let app: INestApplication
      let plugin: OAuthProviderPlugin
      let hookController: HookController

      beforeAll(async () => {
        hookController = { current: null, lastCall: null }
        const hooks = createControlledHooks(hookController)
        plugin = createMockGooglePlugin()

        const bootstrap = await bootstrapTestApp(
          {
            tokenDelivery: 'bearer',
            oauth: {
              google: {
                clientId: 'err-throw-client',
                clientSecret: 'err-throw-secret',
                callbackUrl: 'https://app.example.com/auth/oauth/google/callback'
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
            extraModuleProviders: [{ provide: BYMAX_AUTH_HOOKS, useValue: hooks }],
            mutateBuilder: (builder) =>
              builder.overrideProvider(OAUTH_PLUGINS).useValue([plugin]) as typeof builder
          }
        )
        app = bootstrap.app
      })

      afterAll(async () => {
        await app.close()
      })

      /**
       * Verifies the legacy contract is preserved: with no `errorRedirectUrl`
       * the AuthException propagates to NestJS's exception filter as a JSON
       * 401 — same behaviour as every previous library version.
       */
      it('should respond with the standard JSON 401 OAUTH_FAILED when no errorRedirectUrl is configured', async () => {
        hookController.current = { action: 'reject', reason: 'no go' }

        const initiate = await request(app.getHttpServer())
          .get('/oauth/google')
          .query({ tenantId: 'tenant-1' })
        const state = extractStateFromLocation(initiate.headers['location'] as string | undefined)

        const res = await request(app.getHttpServer())
          .get('/oauth/google/callback')
          .query({ code: 'fail_code', state })

        expect(res.status).toBe(401)
        expect(res.body).toEqual(
          expect.objectContaining({
            error: expect.objectContaining({ code: 'auth.oauth_failed' })
          })
        )
      })
    })
  })
})

// ---------------------------------------------------------------------------
// TOTP helper — RFC 6238 / RFC 4226 implementation using node:crypto only.
//
// Mirrors `test/e2e/mfa-flow.e2e-spec.ts` so the OAuth + MFA scenarios can
// produce real TOTP codes without coupling to lib internals.
// ---------------------------------------------------------------------------

/** TOTP time step in seconds (RFC 6238 §5.2). */
const TOTP_STEP_SECONDS = 30

/** Number of digits in a TOTP code (RFC 4226 §5.3). */
const TOTP_DIGITS = 6

/** Base32 alphabet per RFC 4648 §6 (uppercase A–Z and digits 2–7). */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Encrypts a Base32 TOTP secret with the lib's AES-256-GCM helper so it
 * can be written into the in-memory user repo in the same shape the lib
 * persists on real `userRepo.updateMfa` calls.
 *
 * Uses statically imported `encrypt` + `MFA_ENCRYPTION_KEY` (top of file)
 * so the suite stays consistent with the rest of the codebase's
 * ESM-import convention — no runtime `require()` and no eslint-disable.
 */
function encryptForMfa(base32Secret: string): string {
  return encrypt(base32Secret, MFA_ENCRYPTION_KEY)
}

/**
 * Generates a fresh Base32-encoded TOTP secret. Lives in this file so the
 * OAuth + MFA suite does not depend on lib internals beyond `aes-gcm.ts`.
 */
function generateBase32Secret(): string {
  const bytes = crypto.randomBytes(20)
  let result = ''
  let bits = 0
  let value = 0
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f]
      bits -= 5
    }
  }
  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f]
  }
  return result
}

/**
 * Generates a 6-digit TOTP code for the given Base32 secret at the given time.
 *
 * Mirrors `src/server/crypto/totp.ts` so the test stays decoupled from library
 * internals. Uses HMAC-SHA1 + 30s step + 6-digit code.
 */
function generateTotp(base32Secret: string, time: number = Date.now()): string {
  const key = base32Decode(base32Secret)
  const counter = Math.floor(time / 1000 / TOTP_STEP_SECONDS)

  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))

  const hmac = crypto.createHmac('sha1', key).update(buf).digest()

  const offset = (hmac[hmac.length - 1] as number) & 0x0f
  const code =
    (((hmac[offset] as number) & 0x7f) << 24) |
    (((hmac[offset + 1] as number) & 0xff) << 16) |
    (((hmac[offset + 2] as number) & 0xff) << 8) |
    ((hmac[offset + 3] as number) & 0xff)

  return (code % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, '0')
}

/** Decodes a Base32 string per RFC 4648 §6 into raw bytes. */
function base32Decode(input: string): Buffer {
  const cleaned = input.replace(/=+$/, '').toUpperCase()
  const bytes: number[] = []
  let bits = 0
  let value = 0

  for (const c of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(c)
    if (idx < 0) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }

  return Buffer.from(bytes)
}
