/**
 * WsJwtGuard — unit tests
 *
 * Tests the WebSocket JWT authentication guard. The guard:
 *  - Dynamically imports @nestjs/websockets and throws a plain Error if absent
 *  - Extracts tokens exclusively from the handshake Authorization header (not query params)
 *  - Rejects tokens with type !== 'dashboard' (platform, mfa_challenge)
 *  - Validates the jti claim is a string type
 *  - Checks the Redis revocation list and throws TOKEN_REVOKED if revoked
 *  - Pins the signing algorithm from resolved options to prevent confusion attacks
 *  - Populates client.data.user with the decoded payload on success
 *
 * Mocking strategy: JwtService, AuthRedisService, and BYMAX_AUTH_OPTIONS are replaced
 * with plain jest mock objects. The dynamic @nestjs/websockets import is intercepted in
 * the "not installed" test via jest.resetModules() + jest.doMock() + fresh require.
 */

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AuthException } from '../errors/auth-exception'
import type { ResolvedOptions } from '../config/resolved-options'
import { AuthRedisService } from '../redis/auth-redis.service'
import { WsJwtGuard } from './ws-jwt.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const VALID_PAYLOAD = {
  jti: 'some-jti-uuid',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard' as const,
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

const mockJwtService = {
  verify: jest.fn()
}

const mockRedis = {
  get: jest.fn()
}

const mockOptions = {
  jwt: { algorithm: 'HS256' }
}

// ---------------------------------------------------------------------------
// Helper — builds a mock WS ExecutionContext
// ---------------------------------------------------------------------------

/**
 * Builds a minimal ExecutionContext whose switchToWs().getClient() returns a
 * WS-shaped client object. The returned `clientData` reference lets assertions
 * inspect client.data.user after canActivate resolves.
 */
function makeWsContext(authorizationHeader: string | undefined): {
  context: {
    switchToWs: () => {
      getClient: () => {
        handshake: { headers: Record<string, string | undefined> }
        data: Record<string, unknown>
      }
    }
  }
  clientData: Record<string, unknown>
} {
  const clientData: Record<string, unknown> = {}
  const context = {
    switchToWs: () => ({
      getClient: () => ({
        handshake: {
          headers: {
            authorization: authorizationHeader
          }
        },
        data: clientData
      })
    })
  }
  return { context, clientData }
}

// ---------------------------------------------------------------------------
// Suite — WsJwtGuard
// ---------------------------------------------------------------------------

describe('WsJwtGuard', () => {
  let guard: WsJwtGuard

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        WsJwtGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(WsJwtGuard)
  })

  // ----------------- Peer-dependency check -----------------

  describe('peer-dependency check', () => {
    // Verifies that when @nestjs/websockets is installed onModuleInit resolves without error.
    it('should resolve without error when @nestjs/websockets is installed', async () => {
      // Act + Assert — guard was compiled with the real @nestjs/websockets in scope.
      await expect(guard.onModuleInit()).resolves.toBeUndefined()
    })

    // Verifies that when @nestjs/websockets is not installed onModuleInit throws a
    // descriptive plain Error (not an AuthException).
    it('should throw a generic Error from onModuleInit when @nestjs/websockets is not installed', async () => {
      // Arrange: replace the module with a throwing factory, then reload the guard fresh.
      jest.resetModules()
      jest.doMock('@nestjs/websockets', () => {
        throw new Error("Cannot find module '@nestjs/websockets'")
      })

      const { WsJwtGuard: FreshGuard } = await import('./ws-jwt.guard')
      const freshGuard = new FreshGuard(
        mockJwtService as unknown as JwtService,
        mockRedis as unknown as AuthRedisService,
        mockOptions as unknown as ResolvedOptions
      )

      // Act + Assert
      await expect(freshGuard.onModuleInit()).rejects.toThrow(
        'WsJwtGuard requires @nestjs/websockets to be installed'
      )

      jest.dontMock('@nestjs/websockets')
    })
  })

  // ----------------- Token extraction -----------------

  describe('token extraction', () => {
    // Verifies that the guard reads the token from the handshake Authorization header
    // using the Bearer prefix, passing it correctly to JwtService.verify.
    it('should extract token from the handshake Authorization header (not query params)', async () => {
      // Arrange
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)
      const { context } = makeWsContext('Bearer valid.jwt.token')

      // Act
      await guard.canActivate(context as never)

      // Assert
      expect(mockJwtService.verify).toHaveBeenCalledWith(
        'valid.jwt.token',
        expect.objectContaining({ algorithms: ['HS256'] })
      )
    })

    // Verifies that a missing Authorization header causes an immediate TOKEN_INVALID rejection.
    it('should throw TOKEN_INVALID when Authorization header is missing', async () => {
      // Arrange
      const { context } = makeWsContext(undefined)

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })

    // Verifies that an Authorization header without the 'Bearer ' prefix is treated as
    // a missing token and causes a TOKEN_INVALID rejection.
    it('should throw TOKEN_INVALID when header lacks Bearer prefix', async () => {
      // Arrange
      const { context } = makeWsContext('Basic dXNlcjpwYXNz')

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })
  })

  // ----------------- Token verification -----------------

  describe('token verification', () => {
    // Verifies that when JwtService.verify throws (expired or invalid signature),
    // the guard converts the error to an AuthException with TOKEN_INVALID.
    it('should throw TOKEN_INVALID when jwt.verify throws', async () => {
      // Arrange
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('jwt expired')
      })
      const { context } = makeWsContext('Bearer expired.jwt.token')

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })
  })

  // ----------------- jti validation -----------------

  describe('jti validation', () => {
    // Verifies that a payload missing the jti claim is rejected because the guard
    // cannot build a Redis revocation key without a string jti.
    it('should throw TOKEN_INVALID when jti is missing from payload', async () => {
      // Arrange
      const { jti: _jti, ...payloadWithoutJti } = VALID_PAYLOAD
      mockJwtService.verify.mockReturnValue(payloadWithoutJti)
      mockRedis.get.mockResolvedValue(null)
      const { context } = makeWsContext('Bearer some.jwt.token')

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })

    // Verifies that a payload where jti is a number (not a string) is rejected to
    // prevent key-shape injection into Redis (typeof payload.jti !== 'string' guard).
    it('should throw TOKEN_INVALID when jti is not a string (e.g. number)', async () => {
      // Arrange
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, jti: 12345 })
      mockRedis.get.mockResolvedValue(null)
      const { context } = makeWsContext('Bearer some.jwt.token')

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })
  })

  // ----------------- Token type validation -----------------

  describe('token type validation', () => {
    // Verifies that a token with type 'platform' is rejected by the dashboard WS guard —
    // platform tokens must only be accepted by the platform-specific guard.
    it('should reject a JWT with type platform', async () => {
      // Arrange
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, type: 'platform' })
      mockRedis.get.mockResolvedValue(null)
      const { context } = makeWsContext('Bearer some.jwt.token')

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })

    // Verifies that a token with type 'mfa_challenge' is rejected because it is an
    // intermediate token, not a fully authenticated dashboard access token.
    it('should reject a JWT with type mfa_challenge', async () => {
      // Arrange
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, type: 'mfa_challenge' })
      mockRedis.get.mockResolvedValue(null)
      const { context } = makeWsContext('Bearer some.jwt.token')

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })
  })

  // ----------------- Revocation check -----------------

  describe('revocation check', () => {
    // Verifies that a token whose jti is present in the Redis revocation blacklist
    // is rejected — the guard must honour the rv:{jti} key written on logout.
    it('should reject a token whose jti is in the Redis blacklist', async () => {
      // Arrange
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue('1') // non-null means revoked
      const { context } = makeWsContext('Bearer some.jwt.token')

      // Act + Assert
      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })
  })

  // ----------------- Happy path -----------------

  describe('happy path', () => {
    // Verifies that a valid dashboard token with a non-revoked jti causes the guard
    // to return true and populate client.data.user with the decoded payload.
    it('should accept a JWT with type dashboard and populate client.data.user', async () => {
      // Arrange
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)
      const { context, clientData } = makeWsContext('Bearer valid.jwt.token')

      // Act
      const result = await guard.canActivate(context as never)

      // Assert
      expect(result).toBe(true)
      expect(clientData['user']).toEqual(VALID_PAYLOAD)
    })
  })
})
