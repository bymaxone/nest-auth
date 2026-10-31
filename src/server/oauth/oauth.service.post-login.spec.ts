/**
 * OAuthService — what runs after a sign-in has succeeded.
 *
 * A sign-in through the provider is a login like any other: the account's last-login time moves
 * and the host's `afterLogin` hook runs, as for a password login, and neither can change the
 * outcome. Kept apart from `oauth.service.spec.ts` because it is a separate responsibility and
 * that file is already over the size limit.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { OAUTH_PLUGINS } from './oauth.constants'
import { OAuthService } from './oauth.service'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { TokenManagerService } from '../services/token-manager.service'

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

const STORED_STATE = JSON.stringify({
  provider: 'google',
  tenantId: 'tenant-1',
  codeVerifier: 'verifier-xyz'
})

const mockPlugin = {
  name: 'google',
  authorizeUrl: jest.fn(),
  exchangeCode: jest.fn(),
  fetchProfile: jest.fn()
}

const mockUserRepo = {
  updateLastLogin: jest.fn(),
  findByOAuthId: jest.fn(),
  findByEmail: jest.fn(),
  createWithOAuth: jest.fn(),
  linkOAuth: jest.fn(),
  findById: jest.fn()
}

const mockHooks = {
  onOAuthLogin: jest.fn(),
  afterLogin: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  getdel: jest.fn()
}

const mockTokenManager = {
  issueTokens: jest.fn(),
  issueMfaTempToken: jest.fn()
}

const mockSessionService = {
  createSession: jest.fn()
}

const MOCK_OPTIONS = {
  sessions: { enabled: false },
  secureCookies: true,
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED'],
  emailVerification: { required: false }
}

describe('OAuthService — after a successful sign-in', () => {
  let service: OAuthService

  beforeEach(async () => {
    jest.resetAllMocks()
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
    mockUserRepo.findByEmail.mockResolvedValue(null)
    mockUserRepo.updateLastLogin.mockResolvedValue(undefined)

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

  const callCallback = () =>
    service.handleCallback(
      'google',
      'auth-code-xyz',
      'csrf-state-abc',
      'csrf-state-abc',
      '1.2.3.4',
      'TestBrowser/1.0',
      { 'x-request-id': 'req-123' }
    )

  /** The ordinary arrangement: an unlinked identity that the hook creates an account for. */
  const setupHappyPathCreate = () => {
    mockRedis.getdel.mockResolvedValue(STORED_STATE)
    mockPlugin.exchangeCode.mockResolvedValue({ access_token: 'at-xyz', token_type: 'Bearer' })
    mockPlugin.fetchProfile.mockResolvedValue(OAUTH_PROFILE)
    mockUserRepo.findByOAuthId.mockResolvedValue(null)
    mockHooks.onOAuthLogin.mockResolvedValue({ action: 'create' })
    mockUserRepo.createWithOAuth.mockResolvedValue(AUTH_USER)
    mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
  }

  // ─── Post-login side effects ──────────────────────────────────────────

  // A sign-in through the provider is a login like any other: the account's last-login time
  // moves and the host's `afterLogin` hook runs, exactly as for a password login. Both are
  // fire-and-forget, so the assertions drain the microtask queue first.
  describe('post-login side effects', () => {
    const drain = async () => {
      await Promise.resolve()
      await Promise.resolve()
    }

    it.each(['create', 'link'] as const)(
      'should record the last login and run afterLogin for the %s action',
      async (action) => {
        setupHappyPathCreate()
        mockHooks.onOAuthLogin.mockResolvedValue({ action })
        mockUserRepo.linkOAuth.mockResolvedValue(undefined)
        mockUserRepo.findById.mockResolvedValue(AUTH_USER)
        mockUserRepo.findByOAuthId.mockResolvedValue(action === 'link' ? AUTH_USER : null)

        await callCallback()
        await drain()

        expect(mockUserRepo.updateLastLogin).toHaveBeenCalledTimes(1)
        expect(mockUserRepo.updateLastLogin).toHaveBeenCalledWith({
          id: AUTH_USER.id,
          tenantId: AUTH_USER.tenantId
        })
        expect(mockHooks.afterLogin).toHaveBeenCalledTimes(1)
        expect(mockHooks.afterLogin).toHaveBeenCalledWith(
          SAFE_USER,
          expect.objectContaining({
            plane: 'dashboard',
            userId: AUTH_USER.id,
            tenantId: AUTH_USER.tenantId,
            ip: '1.2.3.4',
            userAgent: 'TestBrowser/1.0'
          })
        )
      }
    )

    // The session is not complete until the second factor passes, so nothing is recorded here:
    // the MFA challenge completion records it once, for the login that actually happened.
    it('should not record a login when the user must pass an MFA challenge', async () => {
      setupHappyPathCreate()
      mockUserRepo.createWithOAuth.mockResolvedValue({ ...AUTH_USER, mfaEnabled: true })
      mockTokenManager.issueMfaTempToken.mockResolvedValue('mfa.temp.jwt')

      await callCallback()
      await drain()

      expect(mockUserRepo.updateLastLogin).not.toHaveBeenCalled()
      expect(mockHooks.afterLogin).not.toHaveBeenCalled()
    })

    // A refused sign-in is not a login.
    it('should not record a login for a blocked account', async () => {
      setupHappyPathCreate()
      mockUserRepo.createWithOAuth.mockResolvedValue({ ...AUTH_USER, status: 'BANNED' })

      await expect(callCallback()).rejects.toThrow(AuthException)
      await drain()

      expect(mockUserRepo.updateLastLogin).not.toHaveBeenCalled()
      expect(mockHooks.afterLogin).not.toHaveBeenCalled()
    })

    // Neither side effect may turn a completed sign-in into a failure, and neither may leak
    // the account id or the hook's own text into the log.
    it('should still sign in when updateLastLogin fails, and log without the id', async () => {
      setupHappyPathCreate()
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockUserRepo.updateLastLogin.mockRejectedValue(new Error(`boom ${AUTH_USER.id}`))

      await expect(callCallback()).resolves.toBe(AUTH_RESULT)
      await drain()

      const lines = error.mock.calls.map((c) => String(c[0]))
      expect(lines.some((l) => l.includes('updateLastLogin failed'))).toBe(true)
      expect(lines.join('\n')).not.toContain(AUTH_USER.id)
    })

    it.each([
      ['rejects', () => Promise.reject(new Error('siem secret=XYZ'))],
      [
        'throws synchronously',
        () => {
          throw new Error('siem secret=XYZ')
        }
      ]
    ])('should still sign in when afterLogin %s, and log without its text', async (_n, impl) => {
      setupHappyPathCreate()
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {})
      mockHooks.afterLogin.mockImplementation(impl)

      await expect(callCallback()).resolves.toBe(AUTH_RESULT)
      await drain()

      const lines = error.mock.calls.map((c) => String(c[0]))
      expect(lines.some((l) => l.includes('afterLogin hook threw'))).toBe(true)
      expect(lines.join('\n')).not.toContain('XYZ')
    })

    // A host with no `afterLogin` implementation is the ordinary case.
    it('should sign in when the hooks object has no afterLogin', async () => {
      setupHappyPathCreate()
      const { afterLogin, ...withoutAfterLogin } = mockHooks
      void afterLogin
      const module = await Test.createTestingModule({
        providers: [
          OAuthService,
          { provide: OAUTH_PLUGINS, useValue: [mockPlugin] },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_HOOKS, useValue: withoutAfterLogin },
          { provide: AuthRedisService, useValue: mockRedis },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: SessionService, useValue: mockSessionService },
          { provide: BYMAX_AUTH_OPTIONS, useValue: MOCK_OPTIONS }
        ]
      }).compile()

      await expect(
        module
          .get(OAuthService)
          .handleCallback('google', 'c', 'csrf-state-abc', 'csrf-state-abc', '1.2.3.4', 'UA', {})
      ).resolves.toBe(AUTH_RESULT)
      expect(mockUserRepo.updateLastLogin).toHaveBeenCalledTimes(1)
    })
  })
})
