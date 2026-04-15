/**
 * JwtPlatformGuard — unit tests
 *
 * Tests the platform-admin JWT authentication guard. The guard:
 *  - Short-circuits to true for routes decorated with @Public()
 *  - Extracts and verifies the access token using JwtService
 *  - Validates the jti claim is a UUID v4 string
 *  - Rejects tokens whose type !== 'platform' with PLATFORM_AUTH_REQUIRED
 *  - Checks the Redis revocation list and throws TOKEN_INVALID if revoked
 *  - Pins the signing algorithm from resolved options to prevent confusion attacks
 *
 * Mocking strategy: all collaborators (JwtService, TokenDeliveryService,
 * AuthRedisService) are replaced with plain jest mock objects. The Reflector
 * is instantiated via useClass so jest.spyOn works correctly on its prototype.
 */

import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { JwtPlatformGuard } from './jwt-platform.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// Real UUID v4 used as the valid jti across happy-path tests
const VALID_JTI = 'a1b2c3d4-1234-4abc-8def-a1b2c3d4e5f6'

const VALID_PAYLOAD = {
  jti: VALID_JTI,
  sub: 'platform-admin-1',
  role: 'super_admin',
  type: 'platform' as const,
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

const mockJwtService = {
  verify: jest.fn()
}

const mockTokenDelivery = {
  extractPlatformAccessToken: jest.fn()
}

const mockRedis = {
  get: jest.fn()
}

const mockOptions = {
  jwt: { algorithm: 'HS256' }
}

// ---------------------------------------------------------------------------
// Helper — builds a minimal ExecutionContext
// ---------------------------------------------------------------------------

function makeContext(token: string | undefined): {
  getHandler: () => jest.Mock
  getClass: () => jest.Mock
  switchToHttp: () => { getRequest: () => Record<string, unknown> }
} {
  const request: Record<string, unknown> = {}
  mockTokenDelivery.extractPlatformAccessToken.mockReturnValue(token)
  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: () => ({ getRequest: () => request })
  }
}

// ---------------------------------------------------------------------------
// Suite — JwtPlatformGuard
// ---------------------------------------------------------------------------

describe('JwtPlatformGuard', () => {
  let guard: JwtPlatformGuard
  let reflector: Reflector

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        JwtPlatformGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: Reflector, useClass: Reflector },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(JwtPlatformGuard)
    reflector = module.get(Reflector)
  })

  // ---------------------------------------------------------------------------
  // @Public routes — early exit
  // ---------------------------------------------------------------------------

  describe('@Public routes', () => {
    // Routes decorated with @Public() must bypass all token validation entirely,
    // returning true immediately without touching JwtService or Redis.
    it('should return true without verifying token when @Public() is set', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true)
      const ctx = makeContext(undefined)

      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(mockJwtService.verify).not.toHaveBeenCalled()
      expect(mockRedis.get).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // Missing token
  // ---------------------------------------------------------------------------

  describe('missing token', () => {
    // When no token is present in the request (neither cookie nor Authorization header),
    // the guard must throw TOKEN_INVALID rather than allowing the request through.
    it('should throw AuthException(TOKEN_INVALID) when no token is present', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext(undefined)

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // Confirm the specific error code (not just that an AuthException is thrown)
    // so callers receive a stable, predictable signal.
    it('should set error code TOKEN_INVALID when no token is present', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext(undefined)

      let caughtError: AuthException | undefined
      try {
        await guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })
  })

  // ---------------------------------------------------------------------------
  // JwtService.verify failures
  // ---------------------------------------------------------------------------

  describe('token verification failures', () => {
    // An expired or tampered token causes JwtService.verify to throw.
    // The guard must catch that and re-throw as TOKEN_INVALID (not TOKEN_EXPIRED)
    // to prevent oracle-timing leakage.
    it('should throw TOKEN_INVALID when jwtService.verify throws', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('jwt expired')
      })
      const ctx = makeContext('expired.jwt.token')

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // Confirms the error code, not just the exception type.
    it('should set error code TOKEN_INVALID when jwtService.verify throws', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('invalid signature')
      })
      const ctx = makeContext('bad.signature.token')

      let caughtError: AuthException | undefined
      try {
        await guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })
  })

  // ---------------------------------------------------------------------------
  // jti validation (UUID v4 format)
  // ---------------------------------------------------------------------------

  describe('jti validation', () => {
    // Without a jti claim the guard cannot build the Redis revocation key,
    // so it must reject the token as TOKEN_INVALID.
    it('should throw TOKEN_INVALID when jti is missing from the payload', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const { jti: _jti, ...payloadWithoutJti } = VALID_PAYLOAD
      mockJwtService.verify.mockReturnValue(payloadWithoutJti)
      const ctx = makeContext('some.jwt.token')

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // The guard requires jti to be a string typed value. A numeric jti (typeof !== 'string')
    // must be rejected to prevent key-shape injection into Redis.
    it('should throw TOKEN_INVALID when jti is not a string type', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, jti: 12345 })
      const ctx = makeContext('some.jwt.token')

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // An attacker might supply a jti that is a string but does not conform to UUID v4 format
    // (e.g. 'not-a-uuid'). The guard must reject it to prevent Redis key injection.
    it('should throw TOKEN_INVALID when jti is a non-UUID-v4 string', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, jti: 'not-a-uuid' })
      const ctx = makeContext('some.jwt.token')

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })

    // A UUID v1 or UUID v3 string looks similar to v4 but has a different version nibble.
    // The guard's regex requires the 4th group to start with '4', so v1-shaped strings
    // must be rejected.
    it('should throw TOKEN_INVALID when jti is not a v4 UUID (wrong version nibble)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      // This UUID has version '1' (13th hex char = '1') instead of '4'
      mockJwtService.verify.mockReturnValue({
        ...VALID_PAYLOAD,
        jti: 'a1b2c3d4-1234-1abc-8def-a1b2c3d4e5f6'
      })
      const ctx = makeContext('some.jwt.token')

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // Token type validation
  // ---------------------------------------------------------------------------

  describe('token type validation', () => {
    // A dashboard token (type: 'dashboard') must be rejected with PLATFORM_AUTH_REQUIRED,
    // not TOKEN_INVALID, so callers can distinguish the wrong-context from a broken token.
    it('should throw PLATFORM_AUTH_REQUIRED when token type is "dashboard"', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, type: 'dashboard' })
      const ctx = makeContext('some.jwt.token')

      let caughtError: AuthException | undefined
      try {
        await guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    })

    // An MFA challenge token (type: 'mfa_challenge') must also be rejected with
    // PLATFORM_AUTH_REQUIRED — it is a valid token but for the wrong context.
    it('should throw PLATFORM_AUTH_REQUIRED when token type is "mfa_challenge"', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, type: 'mfa_challenge' })
      const ctx = makeContext('some.jwt.token')

      let caughtError: AuthException | undefined
      try {
        await guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.PLATFORM_AUTH_REQUIRED)
    })
  })

  // ---------------------------------------------------------------------------
  // Revocation check
  // ---------------------------------------------------------------------------

  describe('revocation check', () => {
    // When a jti appears in the Redis blacklist (rv:{jti} key exists), the token has
    // been revoked via logout. The guard must reject it with TOKEN_INVALID, not TOKEN_REVOKED,
    // to avoid revealing revocation state to potential attackers.
    it('should throw TOKEN_INVALID when the token jti is in the Redis blacklist', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue('1') // non-null means revoked

      const ctx = makeContext('some.jwt.token')

      let caughtError: AuthException | undefined
      try {
        await guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // Confirms the guard queries Redis with the correct key pattern: 'rv:{jti}'
    it('should query Redis with key rv:{jti}', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)

      const ctx = makeContext('some.jwt.token')
      await guard.canActivate(ctx as never)

      expect(mockRedis.get).toHaveBeenCalledWith(`rv:${VALID_JTI}`)
    })
  })

  // ---------------------------------------------------------------------------
  // Algorithm pinning
  // ---------------------------------------------------------------------------

  describe('algorithm pinning', () => {
    // The guard must pass the algorithm from options to JwtService.verify to prevent
    // algorithm-confusion attacks (alg:none or RS256 substitution).
    it('should call jwtService.verify with algorithms: ["HS256"] from options', async () => {
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
  // Happy path
  // ---------------------------------------------------------------------------

  describe('happy path', () => {
    // A valid platform token with a UUID v4 jti that is not revoked must:
    //  - return true
    //  - attach the decoded payload to request.user
    it('should return true and set request.user for a valid non-revoked platform token', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)

      const request: Record<string, unknown> = {}
      mockTokenDelivery.extractPlatformAccessToken.mockReturnValue('valid.platform.token')
      const ctx = {
        getHandler: jest.fn(),
        getClass: jest.fn(),
        switchToHttp: () => ({ getRequest: () => request })
      }

      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(request['user']).toEqual(VALID_PAYLOAD)
    })
  })
})
