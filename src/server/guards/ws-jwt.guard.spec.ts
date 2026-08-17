/**
 * WsJwtGuard — unit tests
 *
 * Tests the WebSocket JWT authentication guard. The guard:
 *  - Dynamically imports @nestjs/websockets and throws a plain Error if absent
 *  - Extracts tokens exclusively from the handshake Authorization header (not query params)
 *  - Rejects tokens with type !== 'dashboard' (platform, mfa_challenge)
 *  - Validates the jti claim is a string type
 *  - Checks the Redis revocation list and throws TOKEN_INVALID if revoked
 *  - Pins the signing algorithm from resolved options to prevent confusion attacks
 *  - Populates client.data.user with the decoded payload on success
 *
 * Mocking strategy: JwtService, AuthRedisService, and BYMAX_AUTH_OPTIONS are replaced
 * with plain jest mock objects. The dynamic @nestjs/websockets import is intercepted in
 * the "not installed" test via jest.resetModules() + jest.doMock() + fresh require.
 */

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import type { ExecutionContext } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { ResolvedOptions } from '../config/resolved-options'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AuthRevocationService } from '../services/auth-revocation.service'
import { WsTicketService } from '../services/ws-ticket.service'
import { WsJwtGuard } from './ws-jwt.guard'

// An `Authorization` header carrying a scheme other than Bearer. Encoded at runtime rather
// than written as a base64 literal, which would read as a leaked credential to a scanner and
// force a reader to decode it to see it is a dummy. Only the scheme matters here.
const NON_BEARER_AUTHORIZATION = `Basic ${Buffer.from('user:pass').toString('base64')}`

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/** The wire code an `AuthException` carries, or `undefined` for anything else. */
function errorCodeOf(err: unknown): string | undefined {
  if (!(err instanceof AuthException)) return undefined
  return (err.getResponse() as { error: { code: string } }).error.code
}

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
  get: jest.fn(),
  getUserTokenEpoch: jest.fn()
}

/** The ticket service, so the guard's redemption path can be driven without Redis. */
const mockWsTickets = {
  redeem: jest.fn()
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
    // Default: no ticket is ever redeemable, so the existing header-path tests are unaffected.
    mockWsTickets.redeem.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID))
    // Default: no per-user cutoff, so the bulk-revocation check is a no-op for the
    // existing tests. Cutoff-specific tests override this.
    mockRedis.getUserTokenEpoch.mockResolvedValue(0)

    const module = await Test.createTestingModule({
      providers: [
        WsJwtGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: AuthRedisService, useValue: mockRedis },
        AuthRevocationService,
        { provide: WsTicketService, useValue: mockWsTickets },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(WsJwtGuard)
  })

  // The transport this guard cannot authenticate on, measured rather than assumed: with
  // `@nestjs/platform-ws` the client handed to a gateway is the raw `ws` WebSocket, which carries
  // no `handshake` — and `ws` does not retain the upgrade request either, so both credential
  // channels are simply absent.
  //
  // Before this refusal existed, the first property access threw a `TypeError`. That is not an
  // `AuthException`, so no auth filter could answer it: the socket died with no close frame and
  // the caller learned nothing. Refused with the same code a missing credential gets, because a
  // caller must not learn from the code which of the two happened. Driven over a real native
  // adapter in `test/e2e/ws-guard.e2e-spec.ts`.
  // Both nullish forms, because they arrive from different places: an adapter that never sets
  // the property at all, and one that sets it to `null` for a connection it could not describe.
  // The property access that used to throw does not care which, so neither does the refusal.
  it.each([
    ['no handshake at all', {}],
    ['a null handshake', { handshake: null }]
  ])('refuses a client with %s instead of throwing on it', async (_why, client) => {
    const context = {
      switchToWs: () => ({ getClient: () => ({ data: {}, ...client }) })
    } as unknown as ExecutionContext

    await expect(guard.canActivate(context)).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.TOKEN_INVALID } }
    })
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
        new AuthRevocationService(mockRedis as unknown as AuthRedisService),
        mockWsTickets as unknown as WsTicketService,
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
      const { context } = makeWsContext(NON_BEARER_AUTHORIZATION)

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
      // Pin the revocation key shape: the guard must look up `rv:${jti}`, not an
      // empty or differently-prefixed key, or revoked tokens would slip through.
      expect(mockRedis.get).toHaveBeenCalledWith(`rv:${VALID_PAYLOAD.jti}`)
    })

    // The socket answers a revoked token exactly as `JwtAuthGuard` answers one: TOKEN_INVALID.
    // TOKEN_REVOKED told the caller their token had been valid until someone logged it out,
    // which is the same oracle the HTTP surface deliberately refuses to give — and the
    // handshake is a cheaper place to ask, not a more private one.
    it('should answer a revoked token exactly as it answers a malformed one', async () => {
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue('1')
      const { context } = makeWsContext('Bearer some.jwt.token')

      const revoked = await guard.canActivate(context as never).catch((e: unknown) => e)

      mockJwtService.verify.mockImplementation(() => {
        throw new Error('malformed')
      })
      const malformed = await guard
        .canActivate(makeWsContext('Bearer nonsense').context as never)
        .catch((e: unknown) => e)

      expect(errorCodeOf(revoked)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
      expect(errorCodeOf(revoked)).toBe(errorCodeOf(malformed))
    })
  })

  // ----------------- Token epoch (bulk revocation) -----------------

  describe('token epoch', () => {
    // A token stamped below the user's current generation must be rejected on the WS surface
    // too, mirroring JwtAuthGuard — otherwise a password reset would not kill already-issued
    // WebSocket access tokens.
    it('should reject a token stamped below the current epoch', async () => {
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: 1 })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(2)
      const { context } = makeWsContext('Bearer some.jwt.token')

      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
      expect(mockRedis.getUserTokenEpoch).toHaveBeenCalledWith(
        VALID_PAYLOAD.sub,
        'tenant-1',
        'dashboard'
      )
    })

    // A token stamped at the current generation is still valid — the bump must not lock out
    // the session established after the revocation event.
    it('should allow a token stamped at the current epoch', async () => {
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: 2 })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(2)
      const { context } = makeWsContext('Bearer some.jwt.token')

      await expect(guard.canActivate(context as never)).resolves.toBe(true)
    })

    // With no bump recorded the check is a pure no-op and an unstamped token passes.
    it('should allow an unstamped token when the user has never been bumped', async () => {
      mockJwtService.verify.mockReturnValue(VALID_PAYLOAD)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(0)
      const { context } = makeWsContext('Bearer some.jwt.token')

      await expect(guard.canActivate(context as never)).resolves.toBe(true)
    })

    // An unusable epoch claim reads as generation 0, so a bumped user's stale token cannot
    // slip past the comparison by carrying a non-numeric value.
    it('should reject a token whose epoch claim is unusable once the user is bumped', async () => {
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, epoch: Number.NaN })
      mockRedis.get.mockResolvedValue(null)
      mockRedis.getUserTokenEpoch.mockResolvedValue(1)
      const { context } = makeWsContext('Bearer some.jwt.token')

      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
    })

    // A malformed sub must be rejected before it keys the epoch lookup (`ep:{sub}`),
    // mirroring the HTTP guard's assertValidSub.
    it('should reject a token whose sub is empty', async () => {
      mockJwtService.verify.mockReturnValue({ ...VALID_PAYLOAD, sub: '' })
      mockRedis.get.mockResolvedValue(null)
      const { context } = makeWsContext('Bearer some.jwt.token')

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

  // ----------------- Single-use upgrade ticket -----------------

  describe('upgrade ticket', () => {
    const snapshot = {
      sub: 'user-7',
      tenantId: 'tenant-7',
      role: 'MEMBER',
      status: 'ACTIVE',
      mfaEnabled: true,
      mfaVerified: true
    }

    /** A handshake carrying a parsed query, the shape Socket.IO provides. */
    function ticketContext(query: Record<string, string | string[] | undefined>, url?: string) {
      const client = {
        handshake: { headers: {}, query, ...(url === undefined ? {} : { url }) },
        data: {} as Record<string, unknown>
      }
      return { client, context: { switchToWs: () => ({ getClient: () => client }) } }
    }

    // Scenario: a valid ticket in the parsed query. Expected: the socket is authorized as the
    // snapshot, and no JWT verification is attempted. Why: the ticket is the browser's only
    // path — a guard that still demanded a header would leave it unusable.
    it('should authorize the socket from a redeemed ticket', async () => {
      mockWsTickets.redeem.mockResolvedValue(snapshot)
      const { client, context } = ticketContext({ ticket: 'raw-ticket' })

      await expect(guard.canActivate(context as never)).resolves.toBe(true)
      expect(mockWsTickets.redeem).toHaveBeenCalledWith('raw-ticket')
      expect(client.data['user']).toStrictEqual(snapshot)
      expect(mockJwtService.verify).not.toHaveBeenCalled()
    })

    // Scenario: a ticket the service refuses. Expected: the refusal propagates. Why: a guard
    // that fell through to the header path on a bad ticket would let a client retry with a
    // token the ticket flow exists to avoid putting on the wire.
    it('should propagate a refused ticket rather than falling back', async () => {
      mockWsTickets.redeem.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID))
      const { context } = ticketContext({ ticket: 'stale' })

      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
      expect(mockJwtService.verify).not.toHaveBeenCalled()
    })

    // Scenario: the ticket only in the raw upgrade URL, as a bare `ws` server exposes it.
    it('should read the ticket from the raw upgrade URL', async () => {
      mockWsTickets.redeem.mockResolvedValue(snapshot)
      const { context } = ticketContext({}, '/socket?ticket=from-url')

      await expect(guard.canActivate(context as never)).resolves.toBe(true)
      expect(mockWsTickets.redeem).toHaveBeenCalledWith('from-url')
    })

    // Scenario: the parameter repeated. Expected: treated as ticketless, so the request falls
    // through to the header path and is refused there. Why: taking the first of two values
    // lets a caller smuggle a second past whatever inspected the first.
    it.each([
      ['a repeated query parameter', { ticket: ['a', 'b'] }, undefined],
      // The repeated parameter poisons the WHOLE request, not just the query. Falling through to
      // the URL instead would hand the caller the smuggling route back: send two values where the
      // parsed query is inspected and a single clean one in the raw URL, and whatever looked at
      // the query is bypassed by the value the guard actually redeems.
      [
        'a repeated query parameter even when the URL carries a single good one',
        { ticket: ['a', 'b'] },
        '/socket?ticket=from-url'
      ],
      ['a repeated URL parameter', {}, '/socket?ticket=a&ticket=b'],
      ['an empty query parameter', { ticket: '' }, undefined],
      ['an empty URL parameter', {}, '/socket?ticket='],
      ['no ticket at all', {}, '/socket'],
      ['an empty URL', {}, ''],
      // A base does not make every string parseable: `http://[` throws `ERR_INVALID_URL` even
      // with one. The string comes off the wire, so a throw here would escape the guard —
      // unhandled, and reachable by anyone who can attempt a connection. An unparseable URL
      // carries no ticket, which is the answer a URL carrying none already gets.
      ['an unparseable URL', {}, 'http://['],
      ['a URL that is only a scheme delimiter', {}, '//']
    ])('should ignore %s', async (_label, query, url) => {
      const { context } = ticketContext(query as Record<string, string | string[]>, url)

      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
      expect(mockWsTickets.redeem).not.toHaveBeenCalled()
    })

    // A redemption proves the ticket existed and was unspent. It does not prove which identity
    // plane minted it: `wst:` is one keyspace, shared with rust-auth over one Redis, and
    // `tenantId` is optional on the snapshot precisely because a platform ticket omits it. This
    // guard authorizes a DASHBOARD identity, so it has to ask.
    //
    // `AuthUser.tenantId` is not optional, so every ticket this library mints carries one — a
    // snapshot without it was written by something else. The refusal matches the one a bad
    // ticket already produces, so the two stay indistinguishable to a caller probing the
    // keyspace.
    it.each([
      ['a platform ticket, which carries no tenant', { ...snapshot, tenantId: undefined }],
      ['a record whose tenant decoded empty', { ...snapshot, tenantId: '' }],
      ['a record whose tenant is not a string', { ...snapshot, tenantId: 42 }],
      ['a record that lost its subject', { ...snapshot, sub: '' }],
      // The type, not just the emptiness. A numeric `sub` is truthy and non-empty, so an
      // emptiness-only check admits it — and the socket then carries a principal that every
      // downstream `sub === userId` comparison silently fails to match, or matches by coercion.
      ['a record whose subject is not a string', { ...snapshot, sub: 42 }]
    ])('should refuse %s rather than open the socket', async (_label, bad) => {
      mockWsTickets.redeem.mockResolvedValue(bad)
      const { client, context } = ticketContext({ ticket: 'raw-ticket' })

      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
      // The point of the refusal: the socket must not be carrying an authorization whose scope
      // is `undefined`, which every downstream tenant check would then compare against nothing.
      expect(client.data['user']).toBeUndefined()
    })
  })
})
