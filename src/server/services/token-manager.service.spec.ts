import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const FIXED_JWT = 'signed.jwt.token'
const FIXED_UUID = '00000000-0000-0000-0000-000000000001'

const mockJwtService = {
  sign: jest.fn().mockReturnValue(FIXED_JWT),
  decode: jest.fn(),
  verify: jest.fn()
}

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  eval: jest.fn(),
  getdel: jest.fn()
}

const mockOptions = {
  jwt: {
    accessExpiresIn: '15m',
    refreshExpiresInDays: 7,
    refreshGraceWindowSeconds: 30,
    algorithm: 'HS256'
  }
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

const SAFE_ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01')
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

// Use inline string to avoid TDZ — jest.mock factories run before const declarations.
jest.mock('node:crypto', () => ({
  ...jest.requireActual('node:crypto'),
  randomUUID: jest.fn().mockReturnValue('00000000-0000-0000-0000-000000000001')
}))

describe('TokenManagerService', () => {
  let service: TokenManagerService

  beforeEach(async () => {
    jest.clearAllMocks()
    mockJwtService.sign.mockReturnValue(FIXED_JWT)

    const module = await Test.createTestingModule({
      providers: [
        TokenManagerService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: AuthRedisService, useValue: mockRedis }
      ]
    }).compile()

    service = module.get(TokenManagerService)
  })

  // ---------------------------------------------------------------------------
  // issueAccess
  // ---------------------------------------------------------------------------

  describe('issueAccess', () => {
    // Verifies that issueAccess calls JwtService.sign with a generated jti and returns the signed token.
    it('should sign a JWT with a generated jti', () => {
      const token = service.issueAccess({
        sub: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        type: 'dashboard',
        status: 'active',
        mfaVerified: false
      })

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ sub: 'user-1', jti: FIXED_UUID }),
        expect.objectContaining({ expiresIn: '15m', algorithm: 'HS256' })
      )
      expect(token).toBe(FIXED_JWT)
    })
  })

  // ---------------------------------------------------------------------------
  // issueTokens
  // ---------------------------------------------------------------------------

  describe('issueTokens', () => {
    // Verifies that issueTokens stores the refresh session in Redis with the correct TTL in seconds.
    it('should store refresh session in Redis with correct TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issueTokens(SAFE_USER, '1.2.3.4', 'TestBrowser')

      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^rt:/),
        expect.any(String),
        7 * 86_400
      )
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_UUID)
      expect(result.user).toEqual(SAFE_USER)
    })

    // Verifies that the stored session JSON contains the expected fields (userId, tenantId, role, ip, device).
    it('should store a JSON session with correct fields', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '127.0.0.1', 'Chrome')

      const storedJson = mockRedis.set.mock.calls[0]?.[1] as string
      const session = JSON.parse(storedJson) as Record<string, unknown>
      expect(session['userId']).toBe('user-1')
      expect(session['tenantId']).toBe('tenant-1')
      expect(session['role']).toBe('member')
      expect(session['ip']).toBe('127.0.0.1')
      expect(session['device']).toBe('Chrome')
    })
  })

  // ---------------------------------------------------------------------------
  // issuePlatformTokens
  // ---------------------------------------------------------------------------

  describe('issuePlatformTokens', () => {
    // Verifies that the access token payload uses type 'platform' for platform admin sessions.
    it('should use type:platform in the access token payload', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'platform', sub: 'admin-1' }),
        expect.any(Object)
      )
      expect(result.rawRefreshToken).toBe(FIXED_UUID)
      expect(result.admin).toEqual(SAFE_ADMIN)
    })

    // Verifies that platform refresh sessions are stored under the 'prt:' prefix to separate them from user sessions.
    it('should store the session under prt: prefix', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^prt:/),
        expect.any(String),
        7 * 86_400
      )
    })
  })

  // ---------------------------------------------------------------------------
  // reissueTokens
  // ---------------------------------------------------------------------------

  describe('reissueTokens', () => {
    const OLD_SESSION = JSON.stringify({
      userId: 'user-1',
      tenantId: 'tenant-1',
      role: 'member',
      device: 'Browser',
      ip: '1.2.3.4',
      createdAt: '2026-01-01T00:00:00.000Z'
    })

    // Verifies that a primary rotation (existing session found via Lua eval) returns new tokens.
    it('should create a new session and return new tokens when old session exists', async () => {
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.eval).toHaveBeenCalled()
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_UUID)
      // RotatedTokenResult: identity in session field, not a full SafeAuthUser
      expect(result.session.userId).toBe('user-1')
      expect(result.session.tenantId).toBe('tenant-1')
      expect(result.session.role).toBe('member')
    })

    // Verifies that primary rotation writes both a new session (rt:) and a grace pointer (rp:) to Redis.
    it('should write both new session and grace pointer on primary rotation', async () => {
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // Two redis.set calls: new session (rt:) and grace pointer (rp:)
      expect(mockRedis.set).toHaveBeenCalledTimes(2)
      const keys = mockRedis.set.mock.calls.map((c: unknown[]) => String(c[0]))
      expect(keys.some((k) => k.startsWith('rt:'))).toBe(true)
      expect(keys.some((k) => k.startsWith('rp:'))).toBe(true)
    })

    // Verifies that when the primary session key is null, the grace window pointer is checked via getdel.
    it('should use grace window session when Lua returns null', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_SESSION) // grace pointer found (atomic GETDEL)
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.getdel).toHaveBeenCalledWith(expect.stringMatching(/^rp:/))
      expect(result.rawRefreshToken).toBe(FIXED_UUID)
    })

    // Verifies that grace-window rotation also writes a new session and a new grace pointer.
    it('should write new session AND new grace pointer on grace-window rotation', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // Two redis.set calls: new session (rt:) and new grace pointer (rp:)
      expect(mockRedis.set).toHaveBeenCalledTimes(2)
      const keys = mockRedis.set.mock.calls.map((c: unknown[]) => String(c[0]))
      expect(keys.some((k) => k.startsWith('rt:'))).toBe(true)
      expect(keys.some((k) => k.startsWith('rp:'))).toBe(true)
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when neither the session nor the grace pointer exists.
    it('should throw REFRESH_TOKEN_INVALID when neither old session nor grace window found', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(null)

      await expect(service.reissueTokens('invalid-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )

      try {
        await service.reissueTokens('invalid-token-2', '1.2.3.4', 'Browser')
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID })
        })
      }
    })
  })

  // ---------------------------------------------------------------------------
  // decodeToken
  // ---------------------------------------------------------------------------

  describe('decodeToken', () => {
    // Verifies that decodeToken returns the full decoded payload when the jti claim is present.
    it('should return the decoded payload when jti is present', () => {
      const payload = { jti: 'some-uuid', sub: 'user-1', type: 'dashboard' }
      mockJwtService.decode.mockReturnValue(payload)

      const result = service.decodeToken('some.jwt.token')

      expect(result).toEqual(payload)
      expect(mockJwtService.decode).toHaveBeenCalledWith('some.jwt.token')
    })

    // Verifies that TOKEN_INVALID is thrown when the decoded payload lacks a jti claim.
    it('should throw TOKEN_INVALID when jti is missing', () => {
      mockJwtService.decode.mockReturnValue({ sub: 'user-1' }) // no jti

      expect(() => service.decodeToken('some.jwt.token')).toThrow(AuthException)
    })

    // Verifies that TOKEN_INVALID is thrown when JwtService.decode returns null (malformed token).
    it('should throw TOKEN_INVALID when decode returns null', () => {
      mockJwtService.decode.mockReturnValue(null)

      expect(() => service.decodeToken('malformed-token')).toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // issueMfaTempToken
  // ---------------------------------------------------------------------------

  describe('issueMfaTempToken', () => {
    // Verifies that an MFA challenge token is signed with type 'mfa_challenge' and stored in Redis with a 300s TTL.
    it('should sign an MFA JWT and store it in Redis with 300s TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const token = await service.issueMfaTempToken('user-1', 'dashboard')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ sub: 'user-1', type: 'mfa_challenge', context: 'dashboard' }),
        expect.objectContaining({ expiresIn: '300s' })
      )
      expect(mockRedis.set).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/), 'user-1', 300)
      expect(token).toBe(FIXED_JWT)
    })

    // Verifies that platform MFA challenges use context 'platform' in the token payload.
    it('should use context:platform for platform MFA challenges', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueMfaTempToken('admin-1', 'platform')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ context: 'platform', sub: 'admin-1' }),
        expect.any(Object)
      )
    })
  })

  // ---------------------------------------------------------------------------
  // verifyMfaTempToken
  // ---------------------------------------------------------------------------

  describe('verifyMfaTempToken', () => {
    // Verifies that verifyMfaTempToken returns userId and context when the token is valid and present in Redis.
    it('should return userId and context when token is valid and in Redis', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.getdel.mockResolvedValue('user-1') // atomic GET+DEL returns stored userId

      const result = await service.verifyMfaTempToken(FIXED_JWT)

      expect(result).toEqual({ userId: 'user-1', context: 'dashboard' })
    })

    // Verifies that verifyMfaTempToken uses atomic getdel to consume the token and prevent replay.
    it('should atomically consume the token (getdel) after verification', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.getdel.mockResolvedValue('user-1')

      await service.verifyMfaTempToken(FIXED_JWT)

      expect(mockRedis.getdel).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/))
      // Ensure separate get/del are not used (would allow TOCTOU)
      expect(mockRedis.get).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Verifies that MFA_TEMP_TOKEN_INVALID is thrown when the token is not found in Redis (already consumed or expired).
    it('should throw MFA_TEMP_TOKEN_INVALID when token is not in Redis', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.getdel.mockResolvedValue(null) // not found / already consumed

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
    })
  })
})
