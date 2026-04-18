import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { OptionalAuthGuard } from './optional-auth.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const VALID_PAYLOAD = {
  jti: 'some-jti-uuid',
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

function makeContext(token: string | undefined): {
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

describe('OptionalAuthGuard', () => {
  let guard: OptionalAuthGuard
  let reflector: Reflector

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        OptionalAuthGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: Reflector, useClass: Reflector },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(OptionalAuthGuard)
    reflector = module.get(Reflector)
  })

  // ----------------- No token present -----------------

  describe('no token present', () => {
    // Verifies that when no token is present the request.user is set to null and true is returned.
    it('should return true and set request.user to null when no token is present', async () => {
      // Arrange
      const ctx = makeContext(undefined)

      // Act
      const result = await guard.canActivate(ctx as never)

      // Assert
      expect(result).toBe(true)
      expect(ctx.switchToHttp().getRequest()['user']).toBeNull()
      expect(mockJwtService.verify).not.toHaveBeenCalled()
    })

    // Verifies that an empty-string token is treated as absent, setting request.user to null and returning true.
    it('should return true and set request.user to null when token is empty string', async () => {
      // Arrange
      const ctx = makeContext('')

      // Act
      const result = await guard.canActivate(ctx as never)

      // Assert
      expect(result).toBe(true)
      expect(ctx.switchToHttp().getRequest()['user']).toBeNull()
      expect(mockJwtService.verify).not.toHaveBeenCalled()
    })
  })

  // ----------------- Valid token present -----------------

  describe('valid token present', () => {
    // Verifies that a valid dashboard token delegates to super, sets request.user, and returns true.
    it('should populate request.user and return true for a valid dashboard token (delegates to super)', async () => {
      // Arrange
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)

      const request: Record<string, unknown> = {}
      mockTokenDelivery.extractAccessToken.mockReturnValue('some.jwt.token')
      const ctx = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({ getRequest: () => request })
      }

      // Act
      const result = await guard.canActivate(ctx as never)

      // Assert
      expect(result).toBe(true)
      expect(request['user']).toEqual(VALID_PAYLOAD)
    })
  })

  // ----------------- Token present but invalid -----------------

  describe('token present but invalid', () => {
    // Verifies that an invalid token (bad signature or expired) causes super to throw AuthException.
    it('should throw AuthException when token is present but invalid (delegates to super)', async () => {
      // Arrange
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('jwt malformed')
      })
      const ctx = makeContext('bad.jwt.token')

      // Act & Assert
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // Verifies that a token payload missing the jti claim causes super to throw AuthException.
    it('should throw AuthException when token is present but jti missing (delegates to super)', async () => {
      // Arrange
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const { jti: _jti, ...payloadWithoutJti } = VALID_PAYLOAD
      mockJwtService.verify.mockReturnValue(payloadWithoutJti)
      mockRedis.get.mockResolvedValue(null)
      const ctx = makeContext('some.jwt.token')

      // Act & Assert
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // Verifies that a blacklisted jti causes super to throw AuthException.
    it('should throw AuthException when token is present but blacklisted (delegates to super)', async () => {
      // Arrange
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue('1') // blacklisted

      const ctx = makeContext('some.jwt.token')

      // Act & Assert
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // Verifies that a platform token presented to the optional-auth guard is rejected by super.
    it('should throw AuthException when token has wrong type (e.g., platform) (delegates to super)', async () => {
      // Arrange
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, type: 'platform' })
      mockRedis.get.mockResolvedValue(null)

      const ctx = makeContext('some.jwt.token')

      // Act & Assert
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })
  })
})
