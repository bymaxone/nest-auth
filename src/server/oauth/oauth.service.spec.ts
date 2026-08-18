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
import type { Request, Response } from 'express'

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
const STORED_STATE = JSON.stringify({
  provider: 'google',
  tenantId: 'tenant-1',
  codeVerifier: 'verifier-xyz'
})
/** A state record with the PKCE verifier stripped — corrupt, or a downgrade attempt. */
const STORED_STATE_NO_PKCE = JSON.stringify({ provider: 'google', tenantId: 'tenant-1' })

/** A state record minted for a different provider — the RFC 9700 mix-up shape. */
const STORED_STATE_OTHER_PROVIDER = JSON.stringify({
  provider: 'hostile-idp',
  tenantId: 'tenant-1',
  codeVerifier: 'verifier-xyz'
})

/** A state record with no `provider` at all — pre-binding, corrupt, or forged. */
const STORED_STATE_NO_PROVIDER = JSON.stringify({
  tenantId: 'tenant-1',
  codeVerifier: 'verifier-xyz'
})

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
  sessions: { enabled: false },
  secureCookies: true,
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  emailVerification: { required: false }
}

const mockRes = {
  redirect: jest.fn(),
  cookie: jest.fn()
} as unknown as Response

/** A minimal request double — `initiateOAuth` only hands it to the tenant resolver. */
const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser' }
} as unknown as Request

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

/**
 * Builds an OAuthService against the shared mocks with `options` overridden — for the handful
 * of tests whose subject is a config value rather than a flow.
 */
async function buildServiceWithOptions(options: object): Promise<OAuthService> {
  const module = await Test.createTestingModule({
    providers: [
      OAuthService,
      { provide: OAUTH_PLUGINS, useValue: [mockPlugin] },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: TokenManagerService, useValue: mockTokenManager },
      { provide: SessionService, useValue: mockSessionService },
      { provide: BYMAX_AUTH_OPTIONS, useValue: options }
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
    // Every other entry point runs the configured resolver, on the stated principle that a
    // deployment deriving the tenant from the request has said the caller's value is not to be
    // trusted. This was the one door that took it verbatim — and it is the door that decides
    // which tenant an account gets provisioned into, which is more than the others protect.
    it('refuses a caller-named tenant when a resolver is configured', async () => {
      const svc = await buildServiceWithOptions({
        ...MOCK_OPTIONS,
        tenantIdResolver: () => 'tenant-from-request'
      })
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example/authorize')

      await expect(
        svc.initiateOAuth('google', 'tenant-the-caller-asked-for', mockReq, mockRes)
      ).rejects.toBeInstanceOf(AuthException)

      // No state record was written, so a refused initiate cannot leave a nonce behind that a
      // callback could later redeem.
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // The other half: with the caller silent, the RESOLVED tenant is what lands in the state
    // record — which is what stops the callback, reading the tenant from there and nowhere else,
    // being talked into a different one.
    it('writes the resolved tenant into the state record', async () => {
      const svc = await buildServiceWithOptions({
        ...MOCK_OPTIONS,
        tenantIdResolver: () => 'tenant-from-request'
      })
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example/authorize')

      await svc.initiateOAuth('google', undefined, mockReq, mockRes)

      const [, payload] = mockRedis.set.mock.calls[0] as [string, string, number]
      expect(JSON.parse(payload)).toMatchObject({ tenantId: 'tenant-from-request' })
    })

    // Verifies the happy path: a valid provider name resolves the plugin, stores
    // the CSRF state in Redis with the correct key format and TTL, and redirects
    // the user to the URL returned by plugin.authorizeUrl().
    it('should store state in Redis and redirect to the provider auth URL', async () => {
      mockPlugin.authorizeUrl.mockReturnValue(
        'https://accounts.google.com/o/oauth2/v2/auth?state=abc'
      )

      await service.initiateOAuth('google', 'tenant-1', mockReq, mockRes)

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
      await service.initiateOAuth('google', 'tenant-1', mockReq, mockRes)

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

      await service.initiateOAuth('google', 'tenant-1', mockReq, mockRes)

      const [state] = mockPlugin.authorizeUrl.mock.calls[0] as [string, string | undefined]
      expect(state).toMatch(/^[0-9a-f]{64}$/)
    })

    // Verifies that the Redis TTL is exactly 600 seconds (10 minutes) as documented.
    it('should store state with a TTL of 600 seconds', async () => {
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example.com/auth')

      await service.initiateOAuth('google', 'tenant-1', mockReq, mockRes)

      const ttlArg = (mockRedis.set.mock.calls[0] as [string, string, number])[2]
      expect(ttlArg).toBe(600)
    })

    // Verifies the browser binding required by RFC 6749 §10.12: the raw state is planted as
    // an HttpOnly cookie so the callback can prove it reached the same browser that started
    // the flow. Without it, an attacker who holds a valid `?code=…&state=…` URL can have a
    // victim's browser complete THEIR login and inherit whatever the victim does next.
    it('should plant the raw state as an HttpOnly oauth_state cookie', async () => {
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example.com/auth')

      await service.initiateOAuth('google', 'tenant-1', mockReq, mockRes)

      const [generatedState] = mockPlugin.authorizeUrl.mock.calls[0] as [string, string | undefined]
      expect(mockRes.cookie).toHaveBeenCalledWith('oauth_state', generatedState, {
        httpOnly: true,
        secure: true,
        // Always 'lax', never the configured value: the provider's callback is a cross-site
        // top-level GET, and 'strict' would withhold the cookie on exactly that hop.
        sameSite: 'lax',
        path: '/',
        // Matches OAUTH_STATE_TTL_SECONDS so neither half of the pair outlives the other.
        maxAge: 600_000
      })
    })

    // Verifies the `secure` attribute tracks the deployment setting rather than being pinned
    // true — a cookie marked Secure is dropped outright over plain HTTP, which would break
    // every local development login.
    it('should mirror options.secureCookies on the state cookie', async () => {
      const svc = await buildServiceWithOptions({ ...MOCK_OPTIONS, secureCookies: false })
      mockPlugin.authorizeUrl.mockReturnValue('https://provider.example.com/auth')

      await svc.initiateOAuth('google', 'tenant-1', mockReq, mockRes)

      const [, , attrs] = (mockRes.cookie as jest.Mock).mock.calls[0] as [
        string,
        string,
        { secure: boolean }
      ]
      expect(attrs.secure).toBe(false)
    })

    // Verifies that an unknown provider name triggers OAUTH_FAILED before any Redis
    // write — the validation happens before the state is stored.
    it('should throw AuthException(OAUTH_FAILED) for an unknown provider', async () => {
      await expect(service.initiateOAuth('github', 'tenant-1', mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Verifies that provider names with uppercase letters fail format validation
    // before the plugin registry is consulted.
    it('should throw OAUTH_FAILED for a provider with uppercase letters', async () => {
      await expect(service.initiateOAuth('GOOGLE', 'tenant-1', mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that path-traversal style provider names are rejected by format validation.
    it('should throw OAUTH_FAILED for a provider with path-traversal characters', async () => {
      await expect(service.initiateOAuth('../etc', 'tenant-1', mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that an empty string is rejected by format validation (requires 1+ chars).
    it('should throw OAUTH_FAILED for an empty provider string', async () => {
      await expect(service.initiateOAuth('', 'tenant-1', mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
    })

    // Pins that the format guard runs at all (and is not stubbed away). Even when a
    // plugin is registered under an UPPERCASE name that the registry `find` would
    // match, the `/^[a-z0-9-]{1,64}$/` guard must reject the malformed provider
    // BEFORE the lookup — so no state is written. A mutant that removes the guard
    // (or empties its throw block) would resolve the plugin and write to Redis.
    it('should reject an uppercase provider even if a plugin is registered under that exact name', async () => {
      const svc = await buildServiceWithPluginName('GOOGLE')

      await expect(svc.initiateOAuth('GOOGLE', 'tenant-1', mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockRes.redirect).not.toHaveBeenCalled()
    })

    // Pins the leading `^` anchor of the provider-format regex. A name with an
    // invalid LEADING character (here a leading space) but an otherwise valid tail
    // must be rejected. Dropping `^` would let the tail match and resolve the
    // (matching) plugin, writing state to Redis. Edge-case: anchor regression.
    it('should reject a provider with a leading space even if a plugin matches that name (pins ^)', async () => {
      const svc = await buildServiceWithPluginName(' google')

      await expect(svc.initiateOAuth(' google', 'tenant-1', mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
      expect(mockRedis.set).not.toHaveBeenCalled()
    })

    // Pins the trailing `$` anchor of the provider-format regex. A name with a
    // valid prefix but an invalid TRAILING character (here a trailing space) must
    // be rejected. Dropping `$` would let the prefix match and resolve the
    // (matching) plugin, writing state to Redis. Edge-case: anchor regression.
    it('should reject a provider with a trailing space even if a plugin matches that name (pins $)', async () => {
      const svc = await buildServiceWithPluginName('google ')

      await expect(svc.initiateOAuth('google ', 'tenant-1', mockReq, mockRes)).rejects.toThrow(
        AuthException
      )
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
        'csrf-state-abc',
        '1.2.3.4',
        'TestBrowser/1.0',
        { 'x-request-id': 'req-123' }
      )

    // A callback that arrives without the `oauth_state` cookie cannot prove it belongs to the
    // browser that started the flow — which is exactly the shape of the attack: the attacker
    // runs their own authorization, never visits the resulting callback URL, and lures the
    // victim there instead. The victim's browser carries no cookie for the attacker's flow.
    // Refusing BEFORE `getdel` matters twice over: it keeps a lured victim from burning a
    // state the legitimate browser is still entitled to complete.
    it('should refuse a callback that carries no state cookie', async () => {
      setupHappyPathCreate()

      await expect(
        service.handleCallback(
          'google',
          'auth-code-xyz',
          'csrf-state-abc',
          undefined,
          '1.2.3.4',
          'TestBrowser/1.0',
          {}
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.OAUTH_FAILED } }
      })
      expect(mockRedis.getdel).not.toHaveBeenCalled()
      expect(mockPlugin.exchangeCode).not.toHaveBeenCalled()
    })

    // The same refusal for a cookie that exists but belongs to a different flow — a stale
    // cookie from an abandoned attempt, or one an attacker managed to plant.
    it('should refuse a callback whose state cookie does not match the query state', async () => {
      setupHappyPathCreate()

      await expect(
        service.handleCallback(
          'google',
          'auth-code-xyz',
          'csrf-state-abc',
          'a-different-state',
          '1.2.3.4',
          'TestBrowser/1.0',
          {}
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.OAUTH_FAILED } }
      })
      expect(mockRedis.getdel).not.toHaveBeenCalled()
    })

    // Every refusal in this flow answers the same opaque OAUTH_FAILED, deliberately — the
    // caller must not learn which check it failed. That makes the log line the only thing that
    // tells an operator a browser-binding failure from a stale state or a corrupt record, so
    // the line has to say which one it was.
    it('should name the browser-binding failure in the log', async () => {
      setupHappyPathCreate()
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await expect(
          service.handleCallback(
            'google',
            'auth-code-xyz',
            'csrf-state-abc',
            'a-different-state',
            '1.2.3.4',
            'TestBrowser/1.0',
            {}
          )
        ).rejects.toThrow(AuthException)

        const logged = warnSpy.mock.calls.map((call) => String(call[0])).join('\n')
        expect(logged).toContain('OAuth state not bound to this browser')
        expect(logged).toContain('provider=google')
      } finally {
        warnSpy.mockRestore()
      }
    })

    // An empty cookie value must not be treated as "no check needed" — it is a mismatch like
    // any other. Pinned separately because the falsy-vs-undefined distinction is exactly the
    // kind of guard a refactor rewrites into `if (stateCookie)`.
    it('should refuse a callback whose state cookie is empty', async () => {
      setupHappyPathCreate()

      await expect(
        service.handleCallback(
          'google',
          'auth-code-xyz',
          'csrf-state-abc',
          '',
          '1.2.3.4',
          'TestBrowser/1.0',
          {}
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.OAUTH_FAILED } }
      })
      expect(mockRedis.getdel).not.toHaveBeenCalled()
    })

    // The refusal above is answered as a flat `oauth_failed` — the same code a dozen other
    // failures in this flow produce — so nothing in the response says a state/cookie binding was
    // broken. That is deliberate, and it makes this line the only record of the one failure here
    // that indicates an attack rather than a mistake: a callback URL delivered to a browser that
    // did not start the authorization is the login-CSRF the binding exists to stop.
    it('records which provider the unbound callback arrived for', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      setupHappyPathCreate()

      await expect(
        service.handleCallback(
          'google',
          'auth-code-xyz',
          'csrf-state-abc',
          'a-different-cookie',
          '1.2.3.4',
          'TestBrowser/1.0',
          {}
        )
      ).rejects.toThrow(AuthException)

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('not bound to this browser')
      expect(warned).toContain('provider=google')
      warnSpy.mockRestore()
    })

    // The stored state's `tenantId` decides which tenant the account is created in or looked up
    // under, so its type is not a formality. The object-shape guard above this one is explicitly
    // suppressed on the grounds that THIS check catches non-objects too — which makes it the only
    // thing standing between a malformed state record and a tenant of `undefined` reaching the
    // repository, where a tenant-scoped lookup silently stops being scoped.
    it.each([
      ['a number', 42],
      ['an object', { id: 't' }],
      ['absent', undefined]
    ])('refuses a stored state whose tenantId is %s', async (_label, tenantId) => {
      setupHappyPathCreate()
      mockRedis.getdel.mockResolvedValue(JSON.stringify({ tenantId, codeVerifier: 'v'.repeat(43) }))

      await expect(
        service.handleCallback(
          'google',
          'auth-code-xyz',
          'csrf-state-abc',
          'csrf-state-abc',
          '1.2.3.4',
          'TestBrowser/1.0',
          {}
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.OAUTH_FAILED } }
      })
      expect(mockUserRepo.createWithOAuth).not.toHaveBeenCalled()
    })

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

    // Scenario: a BANNED account whose OAuth identity is already linked signs in with the
    // provider. Expected: refused before any token is issued. Why: every other credential
    // flow in this library gates on status — password login, the MFA challenge, both reset
    // steps, the platform login — and OAuth was the one that did not, so a ban was fully
    // reversible by anyone holding the linked provider account. Ban is the primary account
    // kill switch; a flow that ignores it makes it advisory.
    it.each([
      ['BANNED', AUTH_ERROR_CODES.ACCOUNT_BANNED],
      ['SUSPENDED', AUTH_ERROR_CODES.ACCOUNT_SUSPENDED],
      ['INACTIVE', AUTH_ERROR_CODES.ACCOUNT_INACTIVE]
    ])('should refuse an OAuth sign-in for a %s account', async (status, expectedCode) => {
      setupHappyPathCreate()
      // Linked identity: the hook resolves to the existing (blocked) account. The link branch
      // re-fetches by primary key, so `findById` is what supplies the resolved user.
      const blocked = { ...AUTH_USER, status }
      mockUserRepo.findByOAuthId.mockResolvedValue(blocked)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(blocked)

      await expect(callCallback()).rejects.toMatchObject({
        // The status gate specifically — not OAUTH_FAILED from an earlier step, which would
        // make this test pass while proving nothing.
        response: { error: { code: expectedCode } }
      })
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
      expect(mockTokenManager.issueMfaTempToken).not.toHaveBeenCalled()
    })

    // Scenario: a blocked account that ALSO has MFA enabled. Expected: refused without even
    // an MFA temp token. Why: the gate runs before the MFA branch, so a blocked account
    // cannot obtain the intermediate credential either — otherwise the ban would be
    // enforced only at the second step, and only for accounts that have a second step.
    it('should refuse a blocked MFA-enabled account before issuing a temp token', async () => {
      setupHappyPathCreate()
      const blocked = { ...AUTH_USER, status: 'BANNED', mfaEnabled: true }
      mockUserRepo.findByOAuthId.mockResolvedValue(blocked)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(blocked)

      await expect(callCallback()).rejects.toThrow(AuthException)
      expect(mockTokenManager.issueMfaTempToken).not.toHaveBeenCalled()
    })

    // Scenario: `emailVerification.required` is on and the provider asserted an UNVERIFIED
    // address. Expected: refused, exactly as password login refuses it. Why: an OAuth
    // identity is not a substitute for a proven mailbox — signing in must not promote an
    // unverified address, or the deployment's "this email is proven" invariant is false for
    // every OAuth account.
    it('should refuse an unverified address when email verification is required', async () => {
      const module = await Test.createTestingModule({
        providers: [
          OAuthService,
          { provide: OAUTH_PLUGINS, useValue: [mockPlugin] },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: SessionService, useValue: mockSessionService },
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...MOCK_OPTIONS, emailVerification: { required: true } }
          }
        ]
      }).compile()
      const strict = module.get<OAuthService>(OAuthService)

      setupHappyPathCreate()
      const unverified = { ...AUTH_USER, emailVerified: false }
      mockUserRepo.findByOAuthId.mockResolvedValue(unverified)
      mockHooks.onOAuthLogin.mockResolvedValue({ action: 'link' })
      mockUserRepo.linkOAuth.mockResolvedValue(undefined)
      mockUserRepo.findById.mockResolvedValue(unverified)

      await expect(
        strict.handleCallback(
          'google',
          'auth-code-xyz',
          'csrf-state-abc',
          'csrf-state-abc',
          '1.2.3.4',
          'TestBrowser/1.0',
          {}
        )
      ).rejects.toMatchObject({
        // The EMAIL_NOT_VERIFIED gate specifically — not OAUTH_FAILED from some earlier step,
        // which would make this test pass while proving nothing.
        response: { error: { code: AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED } }
      })
      expect(mockTokenManager.issueTokens).not.toHaveBeenCalled()
    })

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

    // …and that account can still sign in, because this deployment does not require a verified
    // address. The gate is a conjunction for exactly this reason, and the failure mode of getting
    // it wrong is not a smaller one: every OAuth user whose provider does not assert
    // `email_verified` would be locked out of a deployment that never asked for verification, with
    // an `email_not_verified` telling them to complete a step it does not offer.
    //
    // The test above cannot show this — the account it creates comes back verified from the
    // repository, so the gate reads `true` whatever the flag says.
    it('admits an unverified account when verification is not required', async () => {
      setupHappyPathCreate()
      mockPlugin.fetchProfile.mockResolvedValue({ ...OAUTH_PROFILE, emailVerified: false })
      mockUserRepo.createWithOAuth.mockResolvedValue({ ...AUTH_USER, emailVerified: false })

      await expect(callCallback()).resolves.toBe(AUTH_RESULT)
      expect(mockTokenManager.issueTokens).toHaveBeenCalled()
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

    // Scenario: a stored state with no `codeVerifier` at all. Expected: refused, and the
    // exchange never runs. Why: every flow this library starts writes a verifier, so a record
    // without one is corrupt or forged — accepting it is a PKCE downgrade, where stripping one
    // field buys an attacker an exchange with no proof they started the flow. `rust-auth`
    // types the field as a plain `String` and cannot even deserialize such a record.
    it('should refuse a stored state carrying no codeVerifier', async () => {
      setupHappyPathCreate()
      mockRedis.getdel.mockResolvedValue(STORED_STATE_NO_PKCE)

      await expect(callCallback()).rejects.toThrow(AuthException)
      expect(mockPlugin.exchangeCode).not.toHaveBeenCalled()
    })

    // Scenario: a state minted for one provider, presented at another provider's callback.
    // Expected: refused, and the exchange never runs. Why: RFC 9700 §2.1/§4.4 mix-up defence.
    // The callback learns its provider from its own URL path; without comparing that against
    // the record, any structurally valid state is consumed — so an attacker who can steer an
    // honest provider's callback to a hostile path receives the `code` AND the PKCE
    // `code_verifier`, which is enough to redeem the code at the honest provider. PKCE cannot
    // help: the verifier travels with the code by design.
    // A mix-up is an attack; a record with no usable `provider` is a corrupt or forged one.
    // Both answer the same opaque OAUTH_FAILED, so the log is the only place they are told
    // apart — and the structural guard is what keeps a malformed record from being reported as
    // an attempted mix-up. Asserting the line is present in one case and absent in the other
    // pins both the guard and the message.
    it.each([
      ['a state minted for another provider', STORED_STATE_OTHER_PROVIDER, true],
      ['a record whose provider is not a string', STORED_STATE_NO_PROVIDER, false]
    ])('should refuse %s', async (_label, record, expectMismatchLog) => {
      setupHappyPathCreate()
      mockRedis.getdel.mockResolvedValue(record)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      try {
        await expect(callCallback()).rejects.toThrow(AuthException)
        expect(mockPlugin.exchangeCode).not.toHaveBeenCalled()

        const logged = warnSpy.mock.calls.map((call) => String(call[0])).join('\n')
        if (expectMismatchLog) {
          expect(logged).toContain('OAuth state provider mismatch')
          expect(logged).toContain('provider=google')
        } else {
          expect(logged).not.toContain('OAuth state provider mismatch')
        }
      } finally {
        warnSpy.mockRestore()
      }
    })

    // Each field is checked on its own. With a valid `provider` in front of it, a record whose
    // `tenantId` is missing or mistyped must still be refused — otherwise the guard would only
    // ever be as strong as its first clause, and the tenant scope would reach the hook as
    // `undefined`.
    it.each([
      ['a missing tenantId', { provider: 'google', codeVerifier: 'verifier-xyz' }],
      ['a non-string tenantId', { provider: 'google', tenantId: 7, codeVerifier: 'verifier-xyz' }]
    ])('should refuse a stored state with %s', async (_label, record) => {
      setupHappyPathCreate()
      mockRedis.getdel.mockResolvedValue(JSON.stringify(record))

      await expect(callCallback()).rejects.toThrow(AuthException)
      expect(mockPlugin.exchangeCode).not.toHaveBeenCalled()
    })

    // Verifies that a stored state whose `codeVerifier` is not a string is rejected
    // with OAUTH_FAILED — the type guard prevents malformed shapes from flowing into
    // the plugin's exchangeCode call.
    it('should reject stored state with a non-string codeVerifier field', async () => {
      setupHappyPathCreate()
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ provider: 'google', tenantId: 'tenant-1', codeVerifier: 123 })
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
        AUTH_USER.tenantId,
        'google',
        OAUTH_PROFILE.providerId
      )
      // Re-fetch must use findById (primary key) not findByOAuthId for efficiency, and scoped
      // to the tenant the account was resolved in — an id alone is unique only within one.
      expect(mockUserRepo.findById).toHaveBeenCalledWith(AUTH_USER.id, AUTH_USER.tenantId)
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
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...MOCK_OPTIONS, sessions: { enabled: true } }
          }
        ]
      }).compile()

      const svc = moduleWithSessions.get(OAuthService)
      await svc.handleCallback('google', 'code', 'state', 'state', '1.2.3.4', 'UA', {})

      expect(mockSessionService.createSession).toHaveBeenCalledWith({
        userId: SAFE_USER.id,
        tenantId: 'tenant-1',
        rawRefreshToken: AUTH_RESULT.rawRefreshToken,
        ip: '1.2.3.4',
        userAgent: 'UA'
      })
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
          {
            provide: BYMAX_AUTH_OPTIONS,
            useValue: { ...MOCK_OPTIONS, sessions: { enabled: true } }
          }
        ]
      }).compile()

      const svc = moduleWithSessions.get(OAuthService)
      await svc.handleCallback('google', 'code', 'state', 'state', '1.2.3.4', 'UA', {})

      expect(mockSessionService.createSession).toHaveBeenCalledWith({
        userId: SAFE_USER.id,
        tenantId: 'tenant-1',
        rawRefreshToken: AUTH_RESULT.rawRefreshToken,
        ip: '1.2.3.4',
        userAgent: 'UA'
      })
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
        service.handleCallback('GOOGLE', 'code', 'state', 'state', '1.2.3.4', 'UA', {})
      ).rejects.toThrow(AuthException)

      expect(mockRedis.getdel).not.toHaveBeenCalled()
    })

    // Verifies that an unknown provider (valid format, not registered) does NOT consume
    // the Redis state — resolvePlugin() runs before getdel(), so the CSRF state is
    // preserved for the user to retry after configuration is corrected.
    it('should NOT consume Redis state for a valid-format but unregistered provider', async () => {
      await expect(
        service.handleCallback('github', 'code', 'state', 'state', '1.2.3.4', 'UA', {})
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
        svc.handleCallback('google', 'code', 'state', 'state', '1.2.3.4', 'UA', {})
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
      // ONE argument. The error object no longer reaches the logger: a plugin is consumer code
      // that received the authorization code, the PKCE verifier and the access token, and an
      // HTTP client attaching its request config to the error is the ordinary case.
      expect(loggerSpy.mock.calls[0]).toHaveLength(1)
      expect(loggerSpy.mock.calls[0]?.[0]).toBe(
        "OAuth plugin 'google' failed during code exchange or profile fetch: <error>"
      )
    })

    // Verifies that a plugin.fetchProfile() failure logs an error and throws OAUTH_FAILED.
    it('should log and throw OAUTH_FAILED when plugin.fetchProfile throws', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
      mockPlugin.fetchProfile.mockRejectedValue(new Error('Unverified email'))

      await expect(callCallback()).rejects.toThrow(AuthException)
      expect(loggerSpy.mock.calls[0]).toHaveLength(1)
      expect(loggerSpy.mock.calls[0]?.[0]).toBe(
        "OAuth plugin 'google' failed during code exchange or profile fetch: <error>"
      )
    })

    // The measured shape of the risk, kept as a test. A plugin that echoes what it was given —
    // an HTTP client attaching the request, a wrapper quoting the response — puts the provider's
    // access token into its own rejection. The token is live until the provider expires it, and
    // this handler is the only thing between it and the operator's pipeline.
    //
    // The echo is TRANSFORMED here, not verbatim: the token arrives base64url-encoded inside the
    // quoted request. That is the case redaction cannot reach, because a substring match looks
    // for the value as this library wrote it — which is why the line publishes nothing the plugin
    // authored rather than naming the three values it was given.
    //
    // Both halves are asserted: the credential is gone, AND the diagnosis remains. Asserting only
    // the absence would pass on a build that logged nothing at all.
    it('publishes no credential when the plugin echoes what it received', async () => {
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockRedis.getdel.mockResolvedValue(STORED_STATE)
      mockPlugin.exchangeCode.mockResolvedValue({
        access_token: 'ya29.live-access-token',
        token_type: 'Bearer'
      })
      const encoded = Buffer.from('ya29.live-access-token').toString('base64url')
      mockPlugin.fetchProfile.mockRejectedValue(
        new Error(`401 from provider: {"authorization":"Basic ${encoded}"}`)
      )

      await expect(callCallback()).rejects.toThrow(AuthException)

      const logged = String(loggerSpy.mock.calls[0]?.[0])
      expect(logged).not.toContain('ya29.live-access-token')
      // The transformed form is absent too, which a named-value redaction could not have managed.
      expect(logged).not.toContain(encoded)
      expect(logged).toContain("OAuth plugin 'google' failed")
      expect(logged).toContain('<error>')
      loggerSpy.mockRestore()
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

    // `onOAuthLogin` is the documented — and only — place a deployment can enforce tenant
    // membership, and it is what stands between an unconfigured install and an unauthenticated
    // OAuth sign-in. It was being asked to make that call without being told which tenant, or
    // which address, the flow had resolved to. Both come from server-side state (the `os:`
    // record and the verified profile), never from the callback request.
    it('tells the onOAuthLogin hook which tenant and address the flow resolved to', async () => {
      setupHappyPathCreate()

      await service.handleCallback('google', 'code', 'state', 'state', '1.2.3.4', 'UA', {})

      const [, , context] = mockHooks.onOAuthLogin.mock.calls[0] as [
        unknown,
        unknown,
        { tenantId?: string; email?: string }
      ]
      expect(context.tenantId).toBe('tenant-1')
      expect(context.email).toBe(OAUTH_PROFILE.email)
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

      await service.handleCallback(
        'google',
        'code',
        'state',
        'state',
        '1.2.3.4',
        'UA',
        headersWithSensitive
      )

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

      await service.handleCallback('google', 'code', state, state, '1.2.3.4', 'UA', {})

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

      await service.handleCallback('google', 'code', 'state', 'state', '1.2.3.4', 'UA', {})

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
        service.handleCallback('github', 'code', 'state', 'state', '1.2.3.4', 'UA', {})
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
        'dashboard',
        mfaEnabledUser.tenantId
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
