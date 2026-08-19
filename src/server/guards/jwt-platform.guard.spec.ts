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
import type { TestingModule } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { IS_PUBLIC_KEY } from '../decorators/public.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AuthRevocationService } from '../services/auth-revocation.service'
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
  get: jest.fn(),
  getUserTokenEpoch: jest.fn()
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
  // getHandler/getClass return distinct, defined, stable sentinels so that
  // toHaveBeenCalledWith(KEY, [handler, class]) cannot be satisfied by an empty
  // array — Jest's argument matcher treats [undefined, undefined] as equal to [].
  const handlerRef = jest.fn()
  const classRef = jest.fn()
  return {
    getHandler: jest.fn(() => handlerRef),
    getClass: jest.fn(() => classRef),
    switchToHttp: () => ({ getRequest: () => request })
  }
}

// ---------------------------------------------------------------------------
// Suite — JwtPlatformGuard
// ---------------------------------------------------------------------------

describe('JwtPlatformGuard', () => {
  let guard: JwtPlatformGuard
  let reflector: Reflector
  let testModule: TestingModule

  beforeEach(async () => {
    jest.clearAllMocks()
    // Never bumped unless a test arranges it — the numeric zero every fresh admin reads as.
    mockRedis.getUserTokenEpoch.mockResolvedValue(0)

    const module = await Test.createTestingModule({
      providers: [
        JwtPlatformGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery },
        { provide: AuthRedisService, useValue: mockRedis },
        AuthRevocationService,
        { provide: Reflector, useClass: Reflector },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(JwtPlatformGuard)
    reflector = module.get(Reflector)
    testModule = module
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

    /**
     * Metadata lookup targets.
     *
     * The @Public() flag must be read from BOTH the handler and the class
     * (NestJS override order). Pins the targets array: collapsing it to []
     * would make @Public() undetectable on platform routes.
     */
    it('should read IS_PUBLIC_KEY metadata from the handler and class', async () => {
      const spy = jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true)
      const ctx = makeContext(undefined)

      await guard.canActivate(ctx as never)

      expect(spy).toHaveBeenCalledWith(IS_PUBLIC_KEY, [ctx.getHandler(), ctx.getClass()])
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

    // The four tests above name TOKEN_INVALID and never assert it — they check only that SOME
    // AuthException came out. That is enough to survive deleting `assertValidJti(payload.jti)`
    // entirely: a malformed jti then flows past the guard and something further down the pipeline
    // refuses it for its own reason, which the generic assertion accepts. Stryker v10 reported
    // exactly that, and this is the test that closes it.
    //
    // Same for `assertValidSub`. Both are asserted on the CODE, so a rejection arriving from a
    // later check under a different code fails here instead of passing as equivalent.
    it.each([
      ['jti', { jti: 'not-a-uuid' }],
      ['sub', { sub: '' }]
    ])('refuses a malformed %s BEFORE the revocation lookup', async (_claim, override) => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const revocation = testModule.get(AuthRevocationService)
      const lookup = jest.spyOn(revocation, 'isAccessTokenRevoked')
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, ...override })
      const ctx = makeContext('some.jwt.token')

      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)

      // The assertion that carries the weight. Every test above checks only that SOME
      // AuthException came out, which stays true when the claim validation is deleted entirely —
      // the malformed value simply travels further and is refused later, under the same code.
      // Stryker v10 reported both `assertValidJti` and `assertValidSub` as deletable for exactly
      // that reason.
      //
      // What must not happen is the value reaching this call, because `isAccessTokenRevoked`
      // builds a Redis key from `jti` and `sub`. Rejecting afterwards is not the same as
      // rejecting before: the key has already been shaped by the token.
      expect(lookup).not.toHaveBeenCalled()
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
  // Token epoch — bulk revocation on the platform plane
  // ---------------------------------------------------------------------------

  describe('token epoch', () => {
    // A token stamped below the admin's current generation predates an invalidating event
    // (an MFA state change, a revoke-all) and must be rejected. Platform tokens have carried
    // the stamp since they were introduced; without this read-back, a platform epoch bump
    // revoked nothing — "log out everywhere" killed the refresh sessions while every access
    // token worked on to expiry. rust-auth's verify has always enforced the admin epoch.
    it('should reject a platform token stamped below the current epoch', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: 1 })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(2)

      const ctx = makeContext('some.jwt.token')
      let caught: AuthException | undefined
      try {
        await guard.canActivate(ctx as never)
      } catch (e) {
        caught = e as AuthException
      }
      expect(caught).toBeInstanceOf(AuthException)
      // TOKEN_INVALID, not a dedicated code — indistinguishable from a malformed token, so
      // the response leaks no oracle for whether this admin has been bumped.
      expect((caught!.getResponse() as { error: { code: string } }).error.code).toBe(
        AUTH_ERROR_CODES.TOKEN_INVALID
      )
      // The PLATFORM epoch — the two planes have colliding id spaces, so reading `ep:` here
      // would let a dashboard user's reset revoke an unrelated admin's tokens and vice versa.
      expect(mockRedis.getUserTokenEpoch).toHaveBeenCalledWith(
        VALID_PAYLOAD.sub,
        undefined,
        'platform'
      )
    })

    // A token stamped at the current generation is still valid — the bump must not lock the
    // admin out of the session they established after the invalidating event.
    it('should allow a platform token stamped at the current epoch', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: 2 })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(2)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
    })

    // With no bump recorded the check is a pure no-op: the stored epoch is 0 and so is every
    // token's stamp, so nothing is rejected until an invalidating event actually happens.
    it('should allow an unstamped platform token when the admin has never been bumped', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(0)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
    })

    // A token whose epoch claim is unusable (a string, NaN) reads as generation 0, so a
    // bumped admin's stale-but-tampered token still dies rather than sailing past the check.
    it('should reject a token whose epoch claim is unusable once the admin is bumped', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: 'abc' })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(1)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
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
