import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { JwtAuthGuard } from './jwt-auth.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const VALID_PAYLOAD = {
  jti: '11111111-2222-4333-8444-555555555555',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard',
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

const mockJwtService = {
  verify: jest.fn()
}

const mockTokenDelivery = {
  extractAccessToken: jest.fn()
}

const mockRedis = {
  get: jest.fn()
}

const mockOptions = {
  jwt: { algorithm: 'HS256' }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeContext(
  token: string | undefined,
  metadata: Record<string, boolean> = {}
): {
  getHandler: () => jest.Mock
  getClass: () => jest.Mock
  switchToHttp: () => { getRequest: () => Record<string, unknown> }
} {
  const request: Record<string, unknown> = {}
  mockTokenDelivery.extractAccessToken.mockReturnValue(token)
  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: () => ({ getRequest: () => request })
  }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard
  let reflector: Reflector

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        JwtAuthGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: Reflector, useClass: Reflector },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(JwtAuthGuard)
    reflector = module.get(Reflector)
  })

  // ---------------------------------------------------------------------------
  // @Public routes
  // ---------------------------------------------------------------------------

  describe('@Public routes', () => {
    // Verifies that routes decorated with @Public() bypass JWT verification entirely.
    it('should return true without verifying token when @Public() is set', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true)
      const ctx = makeContext(undefined)

      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(mockJwtService.verify).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // Missing token
  // ---------------------------------------------------------------------------

  describe('missing token', () => {
    // Verifies that a request with no token (neither cookie nor header) throws an AuthException.
    it('should throw AuthException when no token is present', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext(undefined)

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // Valid token
  // ---------------------------------------------------------------------------

  describe('valid token', () => {
    // Verifies that a valid dashboard token is verified, payload is set on request.user, and the guard returns true.
    it('should populate request.user and return true for a valid dashboard token', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)

      const request: Record<string, unknown> = {}
      const ctx = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({ getRequest: () => request })
      }
      mockTokenDelivery.extractAccessToken.mockReturnValue('some.jwt.token')

      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(request['user']).toEqual(VALID_PAYLOAD)
    })

    // Verifies that JwtService.verify is called with the algorithm pinned from resolved options.
    it('should call jwtService.verify with algorithms: [HS256]', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)

      const ctx = makeContext('some.jwt.token')
      await guard.canActivate(ctx as never)

      expect(mockJwtService.verify).toHaveBeenCalledWith(
        'some.jwt.token',
        expect.objectContaining({ algorithms: ['HS256'] })
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Token type validation
  // ---------------------------------------------------------------------------

  describe('token type validation', () => {
    // Verifies that a valid JWT with type 'platform' is rejected by the dashboard guard.
    it('should reject a platform token (type: platform)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, type: 'platform' })
      mockRedis.get.mockResolvedValue(null)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // Verifies that an mfa_challenge token is rejected because it is not a dashboard token.
    it('should reject an mfa_challenge token', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, type: 'mfa_challenge' })
      mockRedis.get.mockResolvedValue(null)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // Revocation check
  // ---------------------------------------------------------------------------

  describe('revocation check', () => {
    // Verifies that a token whose jti appears in the Redis revocation blacklist is rejected
    // with TOKEN_INVALID. TOKEN_REVOKED is kept off the wire so HTTP clients cannot
    // use the response code to distinguish "token was valid but logged out" from
    // "token was malformed" — that distinction is logged server-side only.
    it('should throw TOKEN_INVALID when jti is in the blacklist', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue('1') // blacklisted

      const ctx = makeContext('some.jwt.token')
      let caught: AuthException | undefined
      try {
        await guard.canActivate(ctx as never)
      } catch (e) {
        caught = e as AuthException
      }
      expect(caught).toBeInstanceOf(AuthException)
      expect((caught!.getResponse() as { error: { code: string } }).error.code).toBe(
        AUTH_ERROR_CODES.TOKEN_INVALID
      )
    })

    // Verifies that the revocation lookup uses the exact Redis key rv:{jti}.
    it('should check Redis with the key rv:{jti}', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)

      const ctx = makeContext('some.jwt.token')
      await guard.canActivate(ctx as never)

      expect(mockRedis.get).toHaveBeenCalledWith(`rv:${VALID_PAYLOAD.jti}`)
    })
  })

  // ---------------------------------------------------------------------------
  // Expired / invalid signature
  // ---------------------------------------------------------------------------

  describe('invalid token', () => {
    // Verifies that a token that fails JwtService.verify (expired or bad signature) throws an AuthException.
    it('should throw AuthException when jwtService.verify throws', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('jwt expired')
      })

      const ctx = makeContext('expired.jwt.token')
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // Verifies that a token payload missing the jti claim is rejected (cannot build the revocation key).
    it('should throw when jti is missing from payload', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const { jti: _jti, ...payloadWithoutJti } = VALID_PAYLOAD
      mockJwtService.verify.mockReturnValue(payloadWithoutJti)
      mockRedis.get.mockResolvedValue(null)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })
  })
})
