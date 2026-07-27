/**
 * OAuthService — unit tests
 *
 * Verifies the two-step OAuth 2.0 Authorization Code flow:
 *  1. initiateOAuth() — CSRF state generation, Redis storage, and provider redirect.
 *  2. handleCallback() — state validation, code exchange, profile fetch, hook dispatch,
 *     account creation/linking, token issuance, and session tracking.
 *
 * Mocking strategy: every collaborator (Redis, user repo, hooks, token manager, session
 * service, OAuth plugin) is a plain jest mock object. The real sha256 function is used
 * to verify Redis key format — this is intentional and avoids key-format regression.
 * Logger.prototype.error is spied on to avoid noise and verify observability paths.
 *
 * All tests use jest.resetAllMocks() in beforeEach so mock call history never bleeds
 * between tests.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { Response } from 'express'

import { OAUTH_PLUGINS } from './oauth.constants'
import { OAuthService } from './oauth.service'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { maskEmail } from '../utils/mask-email'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { TokenManagerService } from '../services/token-manager.service'

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const AUTH_USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  passwordHash: 'scrypt:salt:hash',
  mfaSecret: 'encrypted-secret',
  mfaRecoveryCodes: ['code1', 'code2'],
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const SAFE_USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const OAUTH_PROFILE = {
  provider: 'google',
  providerId: 'g-123',
  email: 'user@example.com',
  emailVerified: true,
  name: 'Test User'
}

const AUTH_RESULT = {
  user: SAFE_USER,
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh-uuid'
}

// Stored state payload JSON that would be stored in Redis.
const STORED_STATE = JSON.stringify({ tenantId: 'tenant-1', codeVerifier: 'verifier-xyz' })
/** Legacy stored state without PKCE — used to exercise the backward-compatible branch. */
const STORED_STATE_NO_PKCE = JSON.stringify({ tenantId: 'tenant-1' })

// Mock plugin — implements the OAuthProviderPlugin interface.
const mockPlugin = {
  name: 'google',
  authorizeUrl: jest.fn<string, [string, string | undefined]>(),
  exchangeCode: jest.fn(),
  fetchProfile: jest.fn()
}

const mockUserRepo = {
  findByOAuthId: jest.fn(),
  findByEmail: jest.fn(),
  createWithOAuth: jest.fn(),
  linkOAuth: jest.fn(),
  findById: jest.fn()
}

const mockHooks = {
  onOAuthLogin: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  getdel: jest.fn()
}

const mockTokenManager = {
  issueTokens: jest.fn(),
  // Used by the OAuth + MFA branch. Tests that do not exercise that branch
  // simply leave this mock unconfigured — the existing handleCallback paths
  // for non-MFA users never call it.
  issueMfaTempToken: jest.fn()
}

const mockSessionService = {
  createSession: jest.fn()
}

// Default options with sessions disabled — tests that need sessions override this.
const MOCK_OPTIONS = {
  sessions: { enabled: false }
}

const mockRes = {
  redirect: jest.fn()
} as unknown as Response

/**
 * Builds an OAuthService backed by a single plugin whose `name` is provided by
 * the caller. Used to prove the `resolvePlugin` format guard rejects malformed
 * provider strings even when a (misconfigured) plugin is registered under that
 * exact malformed name — i.e. the guard is a real defence, not a redundant
 * pre-filter of the registry `find`.
 */
async function buildServiceWithPluginName(pluginName: string): Promise<OAuthService> {
  const plugin = {
    name: pluginName,
    authorizeUrl: jest.fn().mockReturnValue('https://provider.example.com/auth'),
    exchangeCode: jest.fn(),
    fetchProfile: jest.fn()
  }
  const module = await Test.createTestingModule({
    providers: [
      OAuthService,
      { provide: OAUTH_PLUGINS, useValue: [plugin] },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: TokenManagerService, useValue: mockTokenManager },
      { provide: SessionService, useValue: mockSessionService },
      { provide: BYMAX_AUTH_OPTIONS, useValue: MOCK_OPTIONS }
    ]
  }).compile()
  return module.get(OAuthService)
}

// ---------------------------------------------------------------------------
// OAuthService — initiateOAuth
// ---------------------------------------------------------------------------

describe('OAuthService', () => {
  let service: OAuthService

  beforeEach(async () => {
    jest.resetAllMocks()
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
    // No email collision unless a test arranges one — `create` is the common arrangement here,
    // and every one of those cases assumes the address is free.
    mockUserRepo.findByEmail.mockResolvedValue(null)

    const module = await Test.createTestingModule({
      providers: [
        OAuthService,
        { provide: OAUTH_PLUGINS, useValue: [mockPlugin] },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: SessionService, useValue: mockSessionService },
        { provide: BYMAX_AUTH_OPTIONS, useValue: MOCK_OPTIONS }
      ]
    }).compile()

    service = module.get(OAuthService)
  })

  describe('initiateOAuth', () => {
    // Verifies the happy path: a valid provider name resolves the plugin, stores
    // the CSRF state in Redis with the correct key format and TTL, and redirects
    // the user to the URL returned by plugin.authorizeUrl().
    it('should store state in Redis and redirect to the provider auth URL', async () => {
      mockPlugin.authorizeUrl.mockReturnValue(
        'https://accounts.google.com/o/oauth2/v2/auth?state=abc'
      )

      await service.initiateOAuth('google', 'tenant-1', mockRes)

      // Verify that the plugin's authorizeUrl was called with the generated state
      // and a PKCE code challenge (second positional parameter).
      expect(mockPlugin.authorizeUrl).toHaveBeenCalledTimes(1)
      const [generatedState, codeChallenge] = mockPlugin.authorizeUrl.mock.calls[0] as [
        string,
        string | undefined
      ]

      // Redis key must be 'os:{sha256(state)}' so the raw state is never server-persisted.
      const expectedKey = `os:${sha256(generatedState)}`
      const [keyArg, payloadArg, ttlArg] = mockRedis.set.mock.calls[0] as [string, string, number]
      expect(keyArg).toBe(expectedKey)
      expect(ttlArg).toBe(600) // OAUTH_STATE_TTL_SECONDS

      // Stored payload contains the tenant AND the PKCE code_verifier — the
      // verifier stays server-side; only the challenge hash travels to the provider.
      const parsedPayload = JSON.parse(payloadArg) as { tenantId: string; codeVerifier: string }
      expect(parsedPayload.tenantId).toBe('tenant-1')
      expect(parsedPayload.codeVerifier).toMatch(/^[0-9a-f]{64}$/)
      expect(codeChallenge).toBeDefined()
      expect(codeChallenge!.length).toBeGreaterThanOrEqual(43)

      // The response must redirect to the URL returned by the plugin.
      expect(mockRes.redirect).toHaveBeenCalledWith(
        'https://accounts.google.com/o/oauth2/v2/auth?state=abc'
      )
    })

    // Verifies that the code_challenge passed to the plugin is the base64url-encoded
    // SHA-256 of the stored code_verifier. This is the PKCE S256 derivation (RFC 7636)
    // that binds the authorize URL to the server-held verifier.
    it('should pass the SHA-256 base64url(code_verifier) as the PKCE challenge', async () => {
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example.com/auth')
      await service.initiateOAuth('google', 'tenant-1', mockRes)

      const [, codeChallenge] = mockPlugin.authorizeUrl.mock.calls[0] as [
        string,
        string | undefined
      ]
      const [, payloadArg] = mockRedis.set.mock.calls[0] as [string, string, number]
      const { codeVerifier } = JSON.parse(payloadArg) as { codeVerifier: string }

      const expectedChallenge = createHash('sha256')
        .update(codeVerifier, 'utf8')
        .digest('base64url')
      expect(codeChallenge).toBe(expectedChallenge)
    })

    // Verifies that the generated CSRF state is 64 hexadecimal characters (32 bytes),
    // matching the documented security requirement for the CSRF nonce.
    it('should generate a 64-char hex state nonce', async () => {
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example.com/auth')

      await service.initiateOAuth('google', 'tenant-1', mockRes)

      const [state] = mockPlugin.authorizeUrl.mock.calls[0] as [string, string | undefined]
      expect(state).toMatch(/^[0-9a-f]{64}$/)
    })

    // Verifies that the Redis TTL is exactly 600 seconds (10 minutes) as documented.
    it('should store state with a TTL of 600 seconds', async () => {
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example.com/auth')

      await service.initiateOAuth('google', 'tenant-1', mockRes)

      const ttlArg = (mockRedis.set.mock.calls[0] as [string, string, number])[2]
      expect(ttlArg).toBe(600)
    })

    // Verifies that an unknown provider name triggers OAUTH_FAILED before any Redis
    // write — the validation happens before the state is stored.
    it('should throw AuthException(OAUTH_FAILED) for an unknown provider', async () => {
      await expect(service.initiateOAuth('github', 'tenant-1', mockRes)).rejects.toThrow(
        AuthException
      )
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Verifies that provider names with uppercase letters fail format validation
    // before the plugin registry is consulted.
    it('should throw OAUTH_FAILED for a provider with uppercase letters', async () => {
      await expect(service.initiateOAuth('GOOGLE', 'tenant-1', mockRes)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that path-traversal style provider names are rejected by format validation.
    it('should throw OAUTH_FAILED for a provider with path-traversal characters', async () => {
      await expect(service.initiateOAuth('../etc', 'tenant-1', mockRes)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that an empty string is rejected by format validation (requires 1+ chars).
    it('should throw OAUTH_FAILED for an empty provider string', async () => {
      await expect(service.initiateOAuth('', 'tenant-1', mockRes)).rejects.toThrow(AuthException)
    })

    // Pins that the format guard runs at all (and is not stubbed away). Even when a
    // plugin is registered under an UPPERCASE name that the registry `find` would
    // match, the `/^[a-z0-9-]{1,64}$/` guard must reject the malformed provider
    // BEFORE the lookup — so no state is written. A mutant that removes the guard
    // (or empties its throw block) would resolve the plugin and write to Redis.
    it('should reject an uppercase provider even if a plugin is registered under that exact name', async () => {
      const svc = await buildServiceWithPluginName('GOOGLE')

      await expect(svc.initiateOAuth('GOOGLE', 'tenant-1', mockRes)).rejects.toThrow(AuthException)
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockRes.redirect).not.toHaveBeenCalled()
    })

    // Pins the leading `^` anchor of the provider-format regex. A name with an
    // invalid LEADING character (here a leading space) but an otherwise valid tail
    // must be rejected. Dropping `^` would let the tail match and resolve the
    // (matching) plugin, writing state to Redis. Edge-case: anchor regression.
    it('should reject a provider with a leading space even if a plugin matches that name (pins ^)', async () => {
      const svc = await buildServiceWithPluginName(' google')

      await expect(svc.initiateOAuth(' google', 'tenant-1', mockRes)).rejects.toThrow(AuthException)
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Pins the trailing `$` anchor of the provider-format regex. A name with a
    // valid prefix but an invalid TRAILING character (here a trailing space) must
    // be rejected. Dropping `$` would let the prefix match and resolve the
    // (matching) plugin, writing state to Redis. Edge-case: anchor regression.
    it('should reject a provider with a trailing space even if a plugin matches that name (pins $)', async () => {
      const svc = await buildServiceWithPluginName('google ')

      await expect(svc.initiateOAuth('google ', 'tenant-1', mockRes)).rejects.toThrow(AuthException)
      expect(mockRedis.set).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // handleCallback
  // ---------------------------------------------------------------------------

  describe('handleCallback', () => {
    // Helper: builds the standard call arguments for handleCallback.
    const callCallback = (
      overrides?: Partial<
        Parameters<OAuthService['handleCallback']>[0] extends string ? never : object
      >
    ) =>
      service.handleCallback(
        'google',
        'auth-code-xyz',
        'csrf-state-abc',
        '1.2.3.4',
        'TestBrowser/1.0',
        { 'x-request-id': 'req-123' }
      )

    // Sets up the default happy-path mock state. Tests that diverge from this
    // arrange their own overrides.
    const setupHappyPathCreate = () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at-xyz', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'create' })
      mockUserRepo.createWithOAuth.mockResolvedValue(AUTH_USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
    }

    // Scenario: the provider hands back an address it has NOT verified.
    // Expected: the account is created unverified, so the consumer's own verification flow
    // still has to run. Why: the account belongs to whoever controls the OAuth account, not to
    // whoever controls the mailbox — marking it verified anyway would make "this email is
    // proven" false from the first login, which is how an account gets taken over by
    // registering with someone else's address at a provider that does not check.
    it('creates the account unverified when the provider did not verify the email', async () => {
      setupHappyPathCreate()
      mockPlugin.fetchProfile.mockResolvedValue({ ...OAUTH_PROFILE, emailVerified: false })

      await callCallback()

      expect(mockUserRepo.createWithOAuth).toHaveBeenCalledWith(
        expect.objectContaining({ emailVerified: false })
      )
    })

    // Verifies that the 'create' action provisions a new user, strips credentials
    // before calling issueTokens, and returns the full AuthResult.
    it("should create a new user and issue tokens for hook action 'create'", async () => {
      setupHappyPathCreate()

      const result = await callCallback()

      expect(mockUserRepo.createWithOAuth).toHaveBeenCalledWith(
        expect.objectContaining({
          email: OAUTH_PROFILE.email,
          tenantId: 'tenant-1',
          emailVerified: true,
          oauthProvider: 'google',
          oauthProviderId: OAUTH_PROFILE.providerId
        })
      )
      expect(mockTokenManager.issueTokens).toHaveBeenCalledWith(
        expect.not.objectContaining({ passwordHash: expect.anything() }),
        '1.2.3.4',
        'TestBrowser/1.0'
      )
      expect(result).toBe(AUTH_RESULT)
    })

    // Pins the success log message. On a successful OAuth login the service emits a
    // structured line carrying provider, userId, tenantId, and the resolved action.
    // These fields are the audit trail for OAuth sign-ins; an emptied log string
    // would silently drop them. Assert the load-bearing fields are present.
    it('should log the success line with provider, userId, tenantId and action on create', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {})
      setupHappyPathCreate()

      await callCallback()

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('provider=google userId=user-1 tenantId=tenant-1 action=create')
      )
      logSpy.mockRestore()
    })

    // Verifies that the PKCE code_verifier from the stored state is forwarded to
    // `plugin.exchangeCode` — without this the token exchange would be unable to
    // prove possession of the verifier to the provider's token endpoint.
    it('should forward the stored code_verifier to plugin.exchangeCode', async () => {
      setupHappyPathCreate()
      await callCallback()
      expect(mockPlugin.exchangeCode).toHaveBeenCalledWith('auth-code-xyz', 'verifier-xyz')
    })

    // Verifies backward compatibility: a legacy stored state without codeVerifier
    // still completes the flow — exchangeCode receives `undefined` for the verifier.
    it('should forward undefined verifier when the stored state predates PKCE', async () => {
      setupHappyPathCreate()
      mockRedis.getdel.mockResolvedValue(STORED_STATE_NO_PKCE)
      await callCallback()
      expect(mockPlugin.exchangeCode).toHaveBeenCalledWith('auth-code-xyz', undefined)
    })

    // Verifies that a stored state whose `codeVerifier` is not a string is rejected
    // with OAUTH_FAILED — the type guard prevents malformed shapes from flowing into
    // the plugin's exchangeCode call.
    it('should reject stored state with a non-string codeVerifier field', async () => {
      setupHappyPathCreate()
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ tenantId: 'tenant-1', codeVerifier: 123 })
      )
      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Verifies that passwordHash, mfaSecret, and mfaRecoveryCodes are NOT passed to
    // issueTokens — ensures credential fields never leak into the AuthResult.user payload.
    it('should strip credential fields from the user before calling issueTokens', async () => {
      setupHappyPathCreate()

      await callCallback()

      const firstArg = (mockTokenManager.issueTokens.mock.calls[0] as [unknown])[0] as Record<
        string,
        unknown
      >
      expect(firstArg).not.toHaveProperty('passwordHash')
      expect(firstArg).not.toHaveProperty('mfaSecret')
      expect(firstArg).not.toHaveProperty('mfaRecoveryCodes')
    })

    // Verifies the 'link' action: links the OAuth identity to an existing user,
    // re-fetches by ID (not by OAuth identity), and returns tokens for that user.
    it("should link OAuth identity and re-fetch user by ID for hook action 'link'", async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at-xyz', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(AUTH_USER)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(AUTH_USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      const result = await callCallback()

      expect(mockUserRepo.linkOAuth).toHaveBeenCalledWith(
        AUTH_USER.id,
        'google',
        OAUTH_PROFILE.providerId
      )
      // Re-fetch must use findById (primary key) not findByOAuthId for efficiency.
      expect(mockUserRepo.findById).toHaveBeenCalledWith(AUTH_USER.id)
      expect(result).toBe(AUTH_RESULT)
    })

    // Verifies that a session is created when sessions.enabled is true (create action).
    it("should create a session when sessions are enabled (action 'create')", async () => {
      setupHappyPathCreate()

      // Rebuild module with sessions.enabled: true.
      const moduleWithSessions = await Test.createTestingModule({
        providers: [
          OAuthService,
          { provide: OAUTH_PLUGINS, useValue: [mockPlugin] },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_OPTIONS, useValue: { sessions: { enabled: true } } }
        ]
      }).compile()

      const svc = moduleWithSessions.get(OAuthService)
      await svc.handleCallback('google', 'code', 'state', '1.2.3.4', 'UA', {})

      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        SAFE_USER.id,
        AUTH_RESULT.rawRefreshToken,
        '1.2.3.4',
        'UA'
      )
    })

    // Verifies that a session is created when sessions.enabled is true (link action).
    it("should create a session when sessions are enabled (action 'link')", async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(AUTH_USER)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(AUTH_USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      const moduleWithSessions = await Test.createTestingModule({
        providers: [
          OAuthService,
          { provide: OAUTH_PLUGINS, useValue: [mockPlugin] },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_OPTIONS, useValue: { sessions: { enabled: true } } }
        ]
      }).compile()

      const svc = moduleWithSessions.get(OAuthService)
      await svc.handleCallback('google', 'code', 'state', '1.2.3.4', 'UA', {})

      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        SAFE_USER.id,
        AUTH_RESULT.rawRefreshToken,
        '1.2.3.4',
        'UA'
      )
    })

    // Verifies that sessions are NOT created when sessions.enabled is false (default).
    it('should not create a session when sessions are disabled', async () => {
      setupHappyPathCreate()

      await callCallback()

      expect(mockSessionService.createSession).not.toHaveBeenCalled()
    })

    // Scenario: the hook says 'create', but the address already belongs to an account that is
    // not linked to this OAuth identity — a local registration, or a link to a different
    // provider. Expected: a 409 `auth.oauth_email_mismatch`, and no create attempted. Why:
    // `findByOAuthId` cannot see that account, so creating would hit the repository's
    // uniqueness constraint and surface as an opaque 500 the caller can do nothing with. It is
    // a conflict, and it is actionable (sign in and link instead). rust-auth answers the same
    // 409 for the same collision.
    it('should reject a create whose email already belongs to another account', async () => {
      setupHappyPathCreate()
      mockUserRepo.findByEmail.mockResolvedValue(AUTH_USER)

      await expect(callCallback()).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.OAUTH_EMAIL_MISMATCH } },
        status: 409
      })
      expect(mockUserRepo.createWithOAuth).not.toHaveBeenCalled()
    })

    // Scenario: the collision above. Expected: the warning names the tenant and a MASKED
    // address. Why: an operator correlating repeated collisions needs to know which tenant and
    // roughly which account, and the log must not become a store of full addresses.
    it('should log the refused create with a masked address', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      setupHappyPathCreate()
      mockUserRepo.findByEmail.mockResolvedValue(AUTH_USER)

      await expect(callCallback()).rejects.toThrow(AuthException)

      const logged = warnSpy.mock.calls.map((call) => String(call[0])).join('\n')
      expect(logged).toContain('oauth: create refused')
      expect(logged).toContain(maskEmail(OAUTH_PROFILE.email))
      expect(logged).not.toContain(OAUTH_PROFILE.email)
      warnSpy.mockRestore()
    })

    // Verifies that 'reject' action from the hook triggers OAUTH_FAILED.
    it("should throw OAUTH_FAILED when the hook returns action 'reject'", async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'reject', reason: 'Domain not allowed' })

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Verifies that a missing CSRF state in Redis (null from getdel) results in OAUTH_FAILED.
    it('should throw OAUTH_FAILED when the state is not found in Redis', async () => {
      mockRedis.getdel.mockResolvedValue(null)

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Pins the diagnostic warn message emitted on an invalid/expired state. The
    // message must carry the provider so operators can correlate the failure; an
    // emptied log string would erase that signal. Assert the provider is present
    // rather than the full sentence (which is otherwise free to be reworded).
    it('should log a warning that includes the provider when the state is invalid', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      mockRedis.getdel.mockResolvedValue(null)

      await expect(callCallback()).rejects.toThrow(AuthException)
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('provider=google'))
      warnSpy.mockRestore()
    })

    // Verifies that malformed JSON in the stored state value results in OAUTH_FAILED,
    // not an unhandled JSON.parse exception.
    it('should throw OAUTH_FAILED when the stored state contains malformed JSON', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.getdel.mockResolvedValue('{invalid-json')

      await expect(callCallback()).rejects.toThrow(AuthException)
      // Corrupted storage and a stale callback answer the caller identically, so the log is
      // the only place they are distinguishable — and the difference decides whether an
      // operator goes looking at Redis or at the user's browser.
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('unparseable OAuth state'))
      warnSpy.mockRestore()
    })

    // Verifies that a valid JSON object that is missing the tenantId field fails the
    // isStoredOAuthState type guard and results in OAUTH_FAILED.
    it('should throw OAUTH_FAILED when the stored state JSON has invalid shape', async () => {
      mockRedis.getdel.mockResolvedValue(JSON.stringify({ wrongField: 'value' }))

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Pins the `typeof v['tenantId'] !== 'string'` guard in isStoredOAuthState.
    // Here the WHOLE downstream flow is wired to succeed, so the ONLY thing that
    // can make handleCallback throw is the missing-tenantId rejection. If that
    // guard were removed (or flipped to `return true`), the malformed state would
    // be accepted, the flow would complete, and no exception would be raised.
    it('should throw OAUTH_FAILED for state missing tenantId even when the downstream flow would otherwise succeed', async () => {
      // Full happy-path collaborators — nothing here throws on its own.
      mockRedis.getdel.mockResolvedValue(JSON.stringify({ wrongField: 'value' }))
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at-xyz', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'create' })
      mockUserRepo.createWithOAuth.mockResolvedValue(AUTH_USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      await expect(callCallback()).rejects.toThrow(AuthException)
      // The guard must reject before any token exchange is attempted.
      expect(mockPlugin.exchangeCode).not.toHaveBeenCalled()
    })

    // Verifies that a stored state value of JSON null (typeof === 'object' but === null)
    // also fails the isStoredOAuthState type guard and results in OAUTH_FAILED.
    // This exercises the `value === null` branch in isStoredOAuthState.
    it('should throw OAUTH_FAILED when the stored state JSON parses to null', async () => {
      mockRedis.getdel.mockResolvedValue('null')

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Verifies that an invalid provider format is caught BEFORE the Redis getdel call,
    // preserving the CSRF state for the user to retry with a corrected request.
    it('should throw OAUTH_FAILED for invalid provider format without consuming Redis state', async () => {
      await expect(
        service.handleCallback('GOOGLE', 'code', 'state', '1.2.3.4', 'UA', {})
      ).rejects.toThrow(AuthException)

      expect(mockRedis.getdel).not.toHaveBeenCalled()
    })

    // Verifies that an unknown provider (valid format, not registered) does NOT consume
    // the Redis state — resolvePlugin() runs before getdel(), so the CSRF state is
    // preserved for the user to retry after configuration is corrected.
    it('should NOT consume Redis state for a valid-format but unregistered provider', async () => {
      await expect(
        service.handleCallback('github', 'code', 'state', '1.2.3.4', 'UA', {})
      ).rejects.toThrow(AuthException)

      expect(mockRedis.getdel).not.toHaveBeenCalled()
    })

    // Verifies that a null hooks injection (no hooks provider configured at all)
    // results in OAUTH_FAILED — OAuth sign-in must require the hook to be enabled.
    it('should throw OAUTH_FAILED when hooks is null (no hook provider configured)', async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)

      // Build a module with null hooks to test the @Optional() injection path.
      const moduleNullHooks = await Test.createTestingModule({
        providers: [
          OAuthService,
          { provide: OAUTH_PLUGINS, useValue: [mockPlugin] },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_OPTIONS, useValue: MOCK_OPTIONS }
        ]
      }).compile()

      const svc = moduleNullHooks.get(OAuthService)
      await expect(
        svc.handleCallback('google', 'code', 'state', '1.2.3.4', 'UA', {})
      ).rejects.toThrow(AuthException)
    })

    // Verifies that hooks present but onOAuthLogin returning undefined/null also
    // results in OAUTH_FAILED — the hook must return a valid OAuthLoginResult.
    it('should throw OAUTH_FAILED when onOAuthLogin returns undefined', async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      // onOAuthLogin returns undefined — simulates a hook that handles no case.
      mockHooks.onOAuthLogin.mockResolvedValue(undefined)

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Verifies that a plugin.exchangeCode() failure logs an error at ERROR level
    // and throws OAUTH_FAILED rather than propagating the raw plugin error.
    it('should log and throw OAUTH_FAILED when plugin.exchangeCode throws', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockRejectedValue(new Error('Network timeout'))

      await expect(callCallback()).rejects.toThrow(AuthException)
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining("OAuth plugin 'google'"),
        expect.any(Error)
      )
    })

    // Verifies that a plugin.fetchProfile() failure logs an error and throws OAUTH_FAILED.
    it('should log and throw OAUTH_FAILED when plugin.fetchProfile throws', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockRejectedValue(new Error('Unverified email'))

      await expect(callCallback()).rejects.toThrow(AuthException)
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.stringContaining("OAuth plugin 'google'"),
        expect.any(Error)
      )
    })

    // Verifies that 'link' action with no existingAuthUser throws OAUTH_FAILED —
    // the hook must not return 'link' when there is no user to link to.
    it("should throw OAUTH_FAILED when hook returns 'link' but no existing user", async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      // No existing user — but hook still says 'link'.
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Verifies that when findById returns null after linkOAuth (unexpected DB state),
    // OAUTH_FAILED is thrown rather than using the stale pre-link record.
    it('should throw OAUTH_FAILED when findById returns null after linkOAuth', async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(AUTH_USER)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      // findById returns null — simulates a race condition or DB error post-link.
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Verifies that the headers passed to handleCallback reach the onOAuthLogin hook
    // context as sanitized headers — sensitive values like 'authorization' are stripped.
    it('should pass sanitized headers to the onOAuthLogin hook context', async () => {
      setupHappyPathCreate()
      // 'authorization' is a sensitive header that sanitizeHeaders strips.
      const headersWithSensitive = {
        'x-request-id': 'req-001',
        authorization: 'Bearer secret-token',
        'user-agent': 'TestBrowser'
      }

      await service.handleCallback('google', 'code', 'state', '1.2.3.4', 'UA', headersWithSensitive)

      const hookContext = (
        mockHooks.onOAuthLogin.mock.calls[0] as [
          unknown,
          unknown,
          { sanitizedHeaders: Record<string, string> }
        ]
      )[2]
      // 'authorization' must be stripped from sanitized headers.
      expect(hookContext.sanitizedHeaders).not.toHaveProperty('authorization')
      // Non-sensitive headers should remain.
      expect(hookContext.sanitizedHeaders).toHaveProperty('x-request-id', 'req-001')
    })

    // Verifies that the CSRF state key stored in Redis follows the 'os:{sha256(state)}' format.
    it('should use os:{sha256(state)} as the Redis key for state validation', async () => {
      setupHappyPathCreate()
      const state = 'my-test-state-value'

      await service.handleCallback('google', 'code', state, '1.2.3.4', 'UA', {})

      expect(mockRedis.getdel).toHaveBeenCalledWith(`os:${sha256(state)}`)
    })

    // Verifies that the 'default' case in the switch (unexpected action values)
    // also results in OAUTH_FAILED — prevents undefined behaviour from unknown hook results.
    it('should throw OAUTH_FAILED for an unknown hook action value', async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      // Return an unrecognised action to exercise the default branch.
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'unknown' } as never)

      await expect(callCallback()).rejects.toThrow(AuthException)
    })

    // Verifies that profile.name is used in createWithOAuth when provided by the plugin.
    it('should use profile.name as the user name when creating a new user', async () => {
      setupHappyPathCreate()

      await callCallback()

      expect(mockUserRepo.createWithOAuth).toHaveBeenCalledWith(
        expect.objectContaining({ name: OAUTH_PROFILE.name })
      )
    })

    // Verifies that when profile.name is absent, the local part of profile.email is used.
    it('should fall back to email local part as name when profile.name is absent', async () => {
      const profileNoName = { ...OAUTH_PROFILE, name: undefined }
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(profileNoName)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'create' })
      mockUserRepo.createWithOAuth.mockResolvedValue(AUTH_USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      await service.handleCallback('google', 'code', 'state', '1.2.3.4', 'UA', {})

      expect(mockUserRepo.createWithOAuth).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'user' }) // local part of 'user@example.com'
      )
    })

    // Verifies that the existing user is passed to the hook as a SafeAuthUser (no credentials).
    it('should pass existing user to the hook as SafeAuthUser without credential fields', async () => {
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      // An existing user is found — it has credential fields that must be stripped.
      mockUserRepo.findByOAuthId.mockResolvedValue(AUTH_USER)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(AUTH_USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)

      await callCallback()

      const existingUserArg = (
        mockHooks.onOAuthLogin.mock.calls[0] as [unknown, unknown]
      )[1] as Record<string, unknown>
      expect(existingUserArg).not.toHaveProperty('passwordHash')
      expect(existingUserArg).not.toHaveProperty('mfaSecret')
      expect(existingUserArg).not.toHaveProperty('mfaRecoveryCodes')
    })

    // Verifies that when no existing user is found, null is passed to the hook.
    it('should pass null as existingUser to the hook when no OAuth user exists', async () => {
      setupHappyPathCreate()

      await callCallback()

      const existingUserArg = (mockHooks.onOAuthLogin.mock.calls[0] as [unknown, unknown])[1]
      expect(existingUserArg).toBeNull()
    })

    // Verifies that AUTH_ERROR_CODES.OAUTH_FAILED is the specific code used for
    // all OAUTH_FAILED exceptions, not a generic error.
    it('should throw AuthException with OAUTH_FAILED code for unknown provider', async () => {
      await expect(
        service.handleCallback('github', 'code', 'state', '1.2.3.4', 'UA', {})
      ).rejects.toMatchObject({
        getResponse: expect.any(Function)
      })
    })

    // ─── MFA branch (1.0.7) ────────────────────────────────────────────────

    /**
     * Verifies the OAuth + MFA branch: when the resolved user has
     * `mfaEnabled: true`, the service must issue an MFA temp token via
     * `TokenManagerService.issueMfaTempToken` and return the
     * `{ mfaRequired: true, mfaTempToken }` discriminator INSTEAD of a session.
     * Issuing a regular session would leave the user with `mfaVerified: false`,
     * which `MfaRequiredGuard` rejects on every subsequent request.
     */
    it('should return OAuthMfaChallengeResult when the resolved user has MFA enabled', async () => {
      const mfaEnabledUser = { ...AUTH_USER, mfaEnabled: true }
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'create' })
      mockUserRepo.createWithOAuth.mockResolvedValue(mfaEnabledUser)
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.jwt')

      const result = await callCallback()

      // Assert the discriminant + payload.
      expect(result).toEqual({ mfaRequired: true, mfaTempToken: 'mfa.temp.jwt' })
      // Tokens must NOT have been issued — the MFA challenge gates the session.
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
      // No session is created either — that happens after the MFA challenge.
      expect(mockSessionService.createSession).not.toHaveBeenCalled()
      // The temp token issuer is called with the user id and 'dashboard' context.
      expect(mockTokenManager.issueMfaTempToken).toHaveBeenCalledWith(
        mfaEnabledUser.id,
        'dashboard'
      )
    })

    /**
     * Verifies the MFA branch also fires on the 'link' action — a previously
     * linked user with MFA enabled who comes through the OAuth flow again must
     * be routed to the challenge rather than handed a session directly.
     */
    it('should return OAuthMfaChallengeResult for the link action when the linked user has MFA enabled', async () => {
      const mfaEnabledUser = { ...AUTH_USER, mfaEnabled: true }
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(mfaEnabledUser)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(mfaEnabledUser)
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.jwt')

      const result = await callCallback()

      expect(result).toEqual({ mfaRequired: true, mfaTempToken: 'mfa.temp.jwt' })
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

    /**
     * Pins the MFA log line so the audit trail keeps `provider`, `userId`,
     * `tenantId`, and the resolved hook `action` even when the flow short-
     * circuits to the challenge branch. A future refactor that drops one of
     * those fields would surface here.
     */
    it('should log the MFA challenge line with provider, userId, tenantId, and action', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {})
      const mfaEnabledUser = { ...AUTH_USER, mfaEnabled: true }
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
      mockUserRepo.findByOAuthId.mockResolvedValue(null)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'create' })
      mockUserRepo.createWithOAuth.mockResolvedValue(mfaEnabledUser)
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.jwt')

      await callCallback()

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          `provider=google userId=${mfaEnabledUser.id} tenantId=tenant-1 action=create`
        )
      )
      logSpy.mockRestore()
    })
  })
})
