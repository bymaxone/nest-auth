/**
 * WsJwtGuard — the single-use upgrade ticket path
 *
 * A ticket is the browser's only credential channel (the `WebSocket` API cannot set handshake
 * headers). The guard redeems it through `WsTicketService` and never reaches the verifier, so the
 * verifier here is a mock that must stay untouched.
 */

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthTokenVerifierService } from '../services/auth-token-verifier.service'
import { WsTicketService } from '../services/ws-ticket.service'
import { WsJwtGuard } from './ws-jwt.guard'

/** What the guard reads off the context to find a decorator: a handler and its class. */
const HANDLER_AND_CLASS = {
  getHandler: () => () => undefined,
  getClass: () => class Gateway {}
}

const mockVerifier = { verifyAccessToken: jest.fn() }
const mockWsTickets = { redeem: jest.fn() }
const mockOptions = { jwt: { algorithm: 'HS256' } }

describe('WsJwtGuard upgrade ticket', () => {
  let guard: WsJwtGuard

  beforeEach(async () => {
    jest.clearAllMocks()
    const module = await Test.createTestingModule({
      providers: [
        WsJwtGuard,
        { provide: AuthTokenVerifierService, useValue: mockVerifier },
        { provide: WsTicketService, useValue: mockWsTickets },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()
    guard = module.get(WsJwtGuard)
  })

  describe('upgrade ticket', () => {
    const snapshot = {
      sub: 'user-7',
      tenantId: 'tenant-7',
      role: 'MEMBER',
      status: 'ACTIVE',
      mfaEnabled: true,
      mfaVerified: true,
      jti: 'jti-7',
      epoch: 0
    }

    /** A handshake carrying a parsed query, the shape Socket.IO provides. */
    function ticketContext(query: Record<string, string | string[] | undefined>, url?: string) {
      const client = {
        handshake: { headers: {}, query, ...(url === undefined ? {} : { url }) },
        data: {} as Record<string, unknown>
      }
      return {
        client,
        context: { ...HANDLER_AND_CLASS, switchToWs: () => ({ getClient: () => client }) }
      }
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
      expect(mockVerifier.verifyAccessToken).not.toHaveBeenCalled()
    })

    // Scenario: a ticket the service refuses. Expected: the refusal propagates. Why: a guard
    // that fell through to the header path on a bad ticket would let a client retry with a
    // token the ticket flow exists to avoid putting on the wire.
    it('should propagate a refused ticket rather than falling back', async () => {
      mockWsTickets.redeem.mockRejectedValue(new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID))
      const { context } = ticketContext({ ticket: 'stale' })

      await expect(guard.canActivate(context as never)).rejects.toThrow(AuthException)
      expect(mockVerifier.verifyAccessToken).not.toHaveBeenCalled()
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
