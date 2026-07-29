/**
 * @fileoverview Unit tests for {@link WsTicketService}.
 *
 * The ticket exists so a browser can authenticate a WebSocket upgrade without putting an access
 * token in a URL. Everything asserted here is about that trade holding: the ticket must carry
 * the session's identity and nothing more, must not be mintable by a session that could not
 * make the equivalent HTTP request, and must be worth nothing after one redemption.
 */

import { Test } from '@nestjs/testing'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'

import { WS_TICKET_TTL_SECONDS } from '../interfaces/ws-ticket.interface'
import { WsTicketService } from './ws-ticket.service'

import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'

const mockRedis = {
  mintWsTicket: jest.fn(),
  redeemWsTicket: jest.fn()
}

/** A verified dashboard payload, as the guards would have admitted it. */
function payload(overrides: Partial<DashboardJwtPayload> = {}): DashboardJwtPayload {
  return {
    jti: 'jti-1',
    sub: 'user-1',
    tenantId: 'tenant-1',
    role: 'MEMBER',
    type: 'dashboard',
    status: 'ACTIVE',
    mfaEnabled: false,
    mfaVerified: false,
    iat: 1_700_000_000,
    exp: 1_700_000_900,
    ...overrides
  } as DashboardJwtPayload
}

describe('WsTicketService', () => {
  let service: WsTicketService

  beforeEach(async () => {
    jest.clearAllMocks()
    mockRedis.mintWsTicket.mockResolvedValue('t'.repeat(64))

    const module = await Test.createTestingModule({
      providers: [WsTicketService, { provide: AuthRedisService, useValue: mockRedis }]
    }).compile()

    service = module.get(WsTicketService)
  })

  describe('issue', () => {
    // Scenario: a plain authenticated session. Expected: the snapshot carries exactly the six
    // contract fields and the agreed TTL. Why: an extra field is a credential widened without
    // anyone deciding to — `jti` in particular would hand the socket something revocable and
    // replayable, which is the property the ticket exists to avoid.
    it('should bind exactly the identity the token proved', async () => {
      const result = await service.issue(payload())

      expect(mockRedis.mintWsTicket).toHaveBeenCalledTimes(1)
      const [snapshot, ttl] = mockRedis.mintWsTicket.mock.calls[0] as [WsTicketSnapshot, number]
      expect(snapshot).toStrictEqual({
        sub: 'user-1',
        tenantId: 'tenant-1',
        role: 'MEMBER',
        status: 'ACTIVE',
        mfaEnabled: false,
        mfaVerified: false
      })
      expect(ttl).toBe(WS_TICKET_TTL_SECONDS)
      expect(result).toStrictEqual({ ticket: 't'.repeat(64), expiresIn: WS_TICKET_TTL_SECONDS })
    })

    // Scenario: an MFA-enrolled session that has cleared its challenge. Expected: minted, with
    // `mfaVerified` carried through. Why: the socket has to know the second factor was
    // satisfied — a snapshot that flattened it to false would make every MFA-gated handler
    // refuse a user who did everything right.
    it('should mint for an enrolled session that satisfied its second factor', async () => {
      await service.issue(payload({ mfaEnabled: true, mfaVerified: true }))

      const [snapshot] = mockRedis.mintWsTicket.mock.calls[0] as [WsTicketSnapshot]
      expect(snapshot.mfaEnabled).toBe(true)
      expect(snapshot.mfaVerified).toBe(true)
    })

    // Scenario: an enrolled session that has NOT cleared its challenge. Expected: 403
    // `auth.mfa_required`, nothing minted. Why: this is the whole reason the check exists. A
    // ticket outlives the request that minted it, so an unsatisfied session could otherwise
    // trade its half-authenticated token for a socket that no MFA gate ever sees again.
    it('should refuse an enrolled session that has not satisfied MFA', async () => {
      await expect(
        service.issue(payload({ mfaEnabled: true, mfaVerified: false }))
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.MFA_REQUIRED } },
        status: 403
      })
      expect(mockRedis.mintWsTicket).not.toHaveBeenCalled()
    })

    // Scenario: a token whose `mfaEnabled` is not a boolean. Expected: `auth.token_invalid`,
    // nothing minted. Why: `undefined` is falsy, so a missing claim would slip past the
    // enrolment check entirely and mint a ticket for a session nobody vouched for.
    it('should refuse a token whose mfaEnabled claim is malformed', async () => {
      const malformed = payload({ mfaEnabled: undefined as unknown as boolean })

      await expect(service.issue(malformed)).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.TOKEN_INVALID } }
      })
      expect(mockRedis.mintWsTicket).not.toHaveBeenCalled()
    })
  })

  describe('redeem', () => {
    // Scenario: a ticket the store returns a snapshot for. Expected: the snapshot, unchanged.
    it('should return the bound snapshot', async () => {
      const snapshot: WsTicketSnapshot = {
        sub: 'user-9',
        tenantId: 'tenant-9',
        role: 'ADMIN',
        status: 'ACTIVE',
        mfaEnabled: true,
        mfaVerified: true
      }
      mockRedis.redeemWsTicket.mockResolvedValue(snapshot)

      await expect(service.redeem('raw-ticket')).resolves.toStrictEqual(snapshot)
      expect(mockRedis.redeemWsTicket).toHaveBeenCalledWith('raw-ticket')
    })

    // Scenario: unknown, expired, or already-redeemed — the store returns null for all three.
    // Expected: `auth.token_invalid`. Why: the three must stay indistinguishable, or the error
    // becomes an oracle for whether a captured ticket was ever valid.
    it('should refuse a ticket the store cannot redeem', async () => {
      mockRedis.redeemWsTicket.mockResolvedValue(null)

      await expect(service.redeem('stale')).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.TOKEN_INVALID } }
      })
    })

    // Scenario: an empty ticket. Expected: refused without touching Redis. Why: an empty string
    // would hash to a fixed, guessable key — `sha256('')` is a constant — and a lookup on it is
    // a request nobody should be able to make.
    it('should refuse an empty ticket without consulting the store', async () => {
      await expect(service.redeem('')).rejects.toThrow(AuthException)
      expect(mockRedis.redeemWsTicket).not.toHaveBeenCalled()
    })
  })
})
