import { Reflector } from '@nestjs/core'
import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { IS_PUBLIC_KEY } from '../decorators/public.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AuthRevocationService } from '../services/auth-revocation.service'
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
  get: jest.fn(),
  getUserTokenEpoch: jest.fn()
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
// Suite
// ---------------------------------------------------------------------------

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard
  let reflector: Reflector

  beforeEach(async () => {
    jest.clearAllMocks()
    // Default: the user has never been bumped, so the bulk-revocation
    // check is a no-op for every existing test. Cutoff-specific tests override this.
    mockRedis.getUserTokenEpoch.mockResolvedValue(0)

    const module = await Test.createTestingModule({
      providers: [
        JwtAuthGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery },
        { provide: AuthRedisService, useValue: mockRedis },
        AuthRevocationService,
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

    /**
     * Metadata lookup targets.
     *
     * The @Public() flag must be read from BOTH the handler and the class
     * (NestJS override order). Pins the targets array: collapsing it to []
     * would make @Public() undetectable, forcing token verification on routes
     * the developer explicitly opted out of.
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
  // Per-user access-token cutoff (bulk revocation)
  // ---------------------------------------------------------------------------

  describe('token epoch', () => {
    // A token stamped below the user's current generation predates a password reset and must
    // be rejected, closing the window where a pre-reset access token stays usable until its
    // natural exp.
    it('should reject a token stamped below the current epoch', async () => {
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
      expect((caught!.getResponse() as { error: { code: string } }).error.code).toBe(
        AUTH_ERROR_CODES.TOKEN_INVALID
      )
      expect(mockRedis.getUserTokenEpoch).toHaveBeenCalledWith(VALID_PAYLOAD.sub, 'dashboard')
    })

    // A token stamped at the current generation is still valid — the bump must not lock the
    // user out of the session they established after the reset.
    it('should allow a token stamped at the current epoch', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: 2 })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(2)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
    })

    // With no bump recorded the check is a pure no-op: the stored epoch is 0 and so is every
    // token's, including tokens issued before the claim existed.
    it('should allow an unstamped token when the user has never been bumped', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(0)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
    })

    // A token with an unusable epoch claim reads as generation 0, so a bumped user's stale
    // token cannot slip past the `<` comparison by carrying a non-numeric value.
    it('should reject a token whose epoch claim is unusable once the user is bumped', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: 'zzz' })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(1)

      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
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

  // ---------------------------------------------------------------------------
  // Tenant binding (enforceTenantBinding)
  // ---------------------------------------------------------------------------
  describe('tenant binding', () => {
    const errorCodeOf = (e: unknown): string =>
      ((e as AuthException).getResponse() as { error: { code: string } }).error.code

    async function buildGuard(
      overrides: Record<string, unknown>
    ): Promise<{ guard: JwtAuthGuard; reflector: Reflector }> {
      const module = await Test.createTestingModule({
        providers: [
          JwtAuthGuard,
          { provide: JwtService, useValue: mockJwtService },
          { provide: TokenDeliveryService, useValue: mockTokenDelivery },
          { provide: AuthRedisService, useValue: mockRedis },
          AuthRevocationService,
          { provide: Reflector, useClass: Reflector },
          { provide: BYMAX_AUTH_OPTIONS, useValue: { ...mockOptions, ...overrides } }
        ]
      }).compile()
      return { guard: module.get(JwtAuthGuard), reflector: module.get(Reflector) }
    }

    /** Arm the standard valid-token path: not public, signature verifies, not revoked. */
    function armValidToken(reflector: Reflector): void {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)
    }

    // With binding on and the resolved host tenant matching the token, the request is allowed.
    it('allows a token whose tenant matches the resolved request tenant', async () => {
      const resolver = jest.fn().mockReturnValue('tenant-1')
      const { guard, reflector } = await buildGuard({
        enforceTenantBinding: true,
        tenantIdResolver: resolver
      })
      armValidToken(reflector)
      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(resolver).toHaveBeenCalledTimes(1)
    })

    // With binding on and the resolved tenant differing from the token's, the request is refused
    // with TOKEN_INVALID: a token presented under another tenant's host does not pass.
    it('rejects a token whose tenant does not match the resolved request tenant', async () => {
      const resolver = jest.fn().mockReturnValue('tenant-2')
      const { guard, reflector } = await buildGuard({
        enforceTenantBinding: true,
        tenantIdResolver: resolver
      })
      armValidToken(reflector)
      const ctx = makeContext('some.jwt.token')
      const thrown = await guard.canActivate(ctx as never).catch((e: unknown) => e)
      expect(thrown).toBeInstanceOf(AuthException)
      expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // Defensive fallback only: `resolveOptions` rejects `enforceTenantBinding` without a resolver
    // at startup, so this pairing never reaches a running guard. Constructed directly here to pin
    // the guard's own `&& tenantIdResolver` short-circuit — if that operand were dropped, the guard
    // would call an undefined resolver and crash instead of passing through.
    it('passes through when binding is on but no resolver is configured (unreachable in production)', async () => {
      const { guard, reflector } = await buildGuard({ enforceTenantBinding: true })
      armValidToken(reflector)
      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
    })

    // Default off: a configured resolver is not consulted unless binding is explicitly enabled.
    it('does not consult the resolver when binding is not enabled', async () => {
      const resolver = jest.fn().mockReturnValue('tenant-2')
      const { guard, reflector } = await buildGuard({ tenantIdResolver: resolver })
      armValidToken(reflector)
      const ctx = makeContext('some.jwt.token')
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(resolver).not.toHaveBeenCalled()
    })
  })
})
