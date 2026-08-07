/**
 * @fileoverview Unit tests for {@link WsTicketService}.
 *
 * The ticket exists so a browser can authenticate a WebSocket upgrade without putting an access
 * token in a URL. Everything asserted here is about that trade holding: the ticket must carry
 * the session's identity and nothing more, must not be mintable by a session that could not
 * make the equivalent HTTP request, and must be worth nothing after one redemption.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
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

const mockUserRepo = { findById: jest.fn() }

describe('WsTicketService', () => {
  let service: WsTicketService

  beforeEach(async () => {
    jest.clearAllMocks()
    mockRedis.mintWsTicket.mockResolvedValue('t'.repeat(64))
    // The snapshot is read from the account, not the token, so the repository has to answer.
    mockUserRepo.findById.mockResolvedValue({
      id: 'user-1',
      email: 'u@example.com',
      tenantId: 'tenant-1',
      role: 'MEMBER',
      status: 'ACTIVE'
    })

    const module = await Test.createTestingModule({
      providers: [
        WsTicketService,
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: { blockedStatuses: ['BANNED', 'SUSPENDED'] } },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
      ]
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

    // A ticket authorizes a socket for that socket's whole lifetime — there is no per-request
    // gate behind it — so the snapshot is the last chance to describe the account correctly.
    // Copying the token's `status` did not: rotation stamps that claim empty by construction,
    // so a ticket minted from any rotated token carried no status at all and the socket ran
    // with a blank authorization field for as long as it stayed open.
    it('reads the snapshot from the account, not the rotated token', async () => {
      mockUserRepo.findById.mockResolvedValue({
        id: 'user-1',
        email: 'u@example.com',
        tenantId: 'tenant-live',
        role: 'ADMIN',
        status: 'ACTIVE'
      })

      // The token is the shape rotation produces: empty status, and authority frozen at login.
      await service.issue(payload({ status: '', role: 'MEMBER', tenantId: 'tenant-old' }))

      expect(mockRedis.mintWsTicket).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'ACTIVE', role: 'ADMIN', tenantId: 'tenant-live' }),
        WS_TICKET_TTL_SECONDS
      )
    })

    // The socket outlives every per-request check, so a blocked account must not get one at
    // all — there is nothing downstream that would notice.
    it.each([['BANNED'], ['SUSPENDED']])('refuses to mint for a %s account', async (status) => {
      mockUserRepo.findById.mockResolvedValue({
        id: 'user-1',
        email: 'u@example.com',
        tenantId: 'tenant-1',
        role: 'MEMBER',
        status
      })

      await expect(service.issue(payload())).rejects.toThrow(AuthException)
      expect(mockRedis.mintWsTicket).not.toHaveBeenCalled()
    })

    // The account was deleted while the token was still inside its lifetime.
    it('refuses to mint when the account is gone', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(service.issue(payload())).rejects.toMatchObject({
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

    // Scenario: a ticket that will not redeem. Expected: a warning is emitted. Why: the caller
    // gets a deliberately uninformative `token_invalid`, so the log line is the ONLY place the
    // event is recorded — and a run of them is either replayed upgrade URLs or clients missing
    // the window, which is the distinction an operator acts on. Silence here is indistinguishable
    // from no traffic.
    it('should record the refusal for an operator', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      mockRedis.redeemWsTicket.mockResolvedValue(null)

      await expect(service.redeem('stale')).rejects.toThrow(AuthException)

      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('redemption refused'))
      warnSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // Observability
  // ---------------------------------------------------------------------------

  describe('observability', () => {
    // The two lines below are what an operator has to correlate a socket with an account. Both
    // assert the identifying FIELD rather than the prose, so rewording the message stays free
    // while emptying it does not.

    // Scenario: an enrolled session that never cleared its challenge tries to mint. Expected:
    // the refusal names the user. Why: this is the one refusal that means "a second factor was
    // skipped", and it is invisible in the response — `mfa_required` is what a first, honest
    // attempt gets too.
    it('should name the user when refusing a session that skipped its second factor', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})

      await expect(
        service.issue(payload({ mfaEnabled: true, mfaVerified: false }))
      ).rejects.toThrow(AuthException)

      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('userId=user-1'))
      warnSpy.mockRestore()
    })

    // Scenario: a successful mint. Expected: the line carries both user and tenant. Why: a
    // ticket authorizes a socket for its whole lifetime with no per-request gate behind it, so
    // this line is the audit record of that grant — and without the tenant it cannot be
    // attributed on a shared table.
    it('should record an issued ticket with the user and tenant it authorizes', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {})

      await service.issue(payload())

      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('userId=user-1'))
      expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('tenantId=tenant-1'))
      logSpy.mockRestore()
    })
  })
})
