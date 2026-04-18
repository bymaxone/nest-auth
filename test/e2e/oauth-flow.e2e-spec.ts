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
 * The four scenarios mirror the production flow:
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
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
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
import { bootstrapTestApp } from './setup'

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
  name: 'OAuth User'
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
  })
})
