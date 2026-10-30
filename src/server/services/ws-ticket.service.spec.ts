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
import { AuthRevocationService } from './auth-revocation.service'

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
const mockRevocation = { isAccessTokenRevoked: jest.fn() }

describe('WsTicketService', () => {
  let service: WsTicketService

  /** The clock the fixture payload's `iat`/`exp` are written against: 900 s of life remaining. */
  const NOW_MS = 1_700_000_000_000

  beforeEach(async () => {
    jest.clearAllMocks()
    jest.spyOn(Date, 'now').mockReturnValue(NOW_MS)
    mockRedis.mintWsTicket.mockResolvedValue('t'.repeat(64))
    mockRevocation.isAccessTokenRevoked.mockResolvedValue(false)
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
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: AuthRevocationService, useValue: mockRevocation }
      ]
    }).compile()

    service = module.get(WsTicketService)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('issue', () => {
    // Scenario: tokens with different amounts of life left. Expected: the ticket lives for the
    // smaller of the 30-second ceiling and what the token has left, and the response reports that
    // same value. Why: a logout blacklists the token only for its remaining life, so a longer
    // ticket outlives the entry that would refuse it.
    it.each([
      ['more than the ceiling', 900, WS_TICKET_TTL_SECONDS],
      ['exactly the ceiling', 30, 30],
      ['less than the ceiling', 5, 5],
      ['one second', 1, 1]
    ])('should cap the lifetime when the token has %s left', async (_label, left, expected) => {
      const result = await service.issue(payload({ exp: NOW_MS / 1000 + left }))

      const [, ttl] = mockRedis.mintWsTicket.mock.calls[0] as [WsTicketSnapshot, number]
      expect(ttl).toBe(expected)
      expect(result.expiresIn).toBe(expected)
    })

    // Scenario: a clock part-way through a second. Expected: the lifetime is rounded down against
    // the token, so the ticket is never longer-lived than it. Why: exp is whole seconds, and
    // rounding the clock the other way would leave the ticket up to a second past the token.
    it('should round so the ticket never outlasts the token', async () => {
      jest.spyOn(Date, 'now').mockReturnValue(NOW_MS + 400)

      await service.issue(payload({ exp: NOW_MS / 1000 + 3 }))

      const [, ttl] = mockRedis.mintWsTicket.mock.calls[0] as [WsTicketSnapshot, number]
      expect(ttl).toBe(2)
    })

    // Scenario: a token with no life left, and one whose expiry is unusable. Expected: nothing is
    // minted and the refusal is `auth.token_invalid`. Why: a ticket needs a positive lifetime, and
    // a malformed expiry must not default to the 30-second ceiling.
    it.each([
      ['no life left', NOW_MS / 1000],
      ['a past expiry', NOW_MS / 1000 - 10],
      ['no expiry', undefined],
      ['a non-numeric expiry', 'soon']
    ])('should mint nothing for a token with %s', async (_label, exp) => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})

      await expect(service.issue(payload({ exp: exp as number }))).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.TOKEN_INVALID } }
      })
      expect(mockRedis.mintWsTicket).not.toHaveBeenCalled()
      expect(mockUserRepo.findById).not.toHaveBeenCalled()
      // The refusal answers a deliberately uninformative code, so the log line is where an
      // operator learns why a ticket was not minted.
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('no life left'))
    })

    // Scenario: a plain authenticated session. Expected: the snapshot carries exactly the contract
    // fields and the agreed TTL. Why: an extra field is a credential widened without anyone
    // deciding to. `jti` and `epoch` are the identifiers the two revocation checks are keyed by,
    // and neither can be presented to the REST surface or replayed as a credential.
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
        mfaVerified: false,
        jti: 'jti-1',
        epoch: 0
      })
      expect(ttl).toBe(WS_TICKET_TTL_SECONDS)
      expect(result).toStrictEqual({ ticket: 't'.repeat(64), expiresIn: WS_TICKET_TTL_SECONDS })
    })

    // Scenario: a token stamped with an epoch, and one stamped with nothing usable. Expected: the
    // epoch is carried; an absent or malformed stamp is written as 0. Why: the ticket is compared
    // with the user's current epoch at redemption, and the same reading of the stamp has to apply
    // there as on a bearer token.
    it.each([
      ['an epoch of 4', 4, 4],
      ['no epoch', undefined, 0],
      ['a malformed epoch', 'four', 0]
    ])("should bind the minting token's epoch for %s", async (_label, stamped, bound) => {
      await service.issue(payload({ epoch: stamped } as Partial<DashboardJwtPayload>))

      const [snapshot] = mockRedis.mintWsTicket.mock.calls[0] as [WsTicketSnapshot]
      expect(snapshot.epoch).toBe(bound)
      expect(snapshot.jti).toBe('jti-1')
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
        tenantId: 'tenant-1',
        role: 'ADMIN',
        status: 'ACTIVE'
      })

      // The token is the shape rotation produces: empty status, and authority frozen at login.
      await service.issue(payload({ status: '', role: 'MEMBER' }))

      expect(mockRedis.mintWsTicket).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'ACTIVE', role: 'ADMIN', tenantId: 'tenant-1' }),
        WS_TICKET_TTL_SECONDS
      )
    })

    // The account is looked up inside the token's tenant. A user id is unique only within a
    // tenant, so a lookup by id alone could return another tenant's account and mint a ticket
    // that describes it; the repository can only honour the scope it is given.
    it('looks the account up by id within the token tenant', async () => {
      mockUserRepo.findById.mockResolvedValue({
        id: 'user-1',
        email: 'u@example.com',
        tenantId: 'tenant-7',
        role: 'MEMBER',
        status: 'ACTIVE'
      })

      await service.issue(payload({ tenantId: 'tenant-7' }))

      expect(mockUserRepo.findById).toHaveBeenCalledWith({ id: 'user-1', tenantId: 'tenant-7' })
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
        mfaVerified: true,
        jti: 'jti-9',
        epoch: 2
      }
      mockRedis.redeemWsTicket.mockResolvedValue(snapshot)

      await expect(service.redeem('raw-ticket')).resolves.toStrictEqual(snapshot)
      expect(mockRedis.redeemWsTicket).toHaveBeenCalledWith('raw-ticket')
    })

    // Scenario: the session that minted the ticket was revoked between the mint and the upgrade.
    // Expected: `auth.token_invalid`, the same code as every other refusal, and a warning. Why:
    // the socket is authenticated once and never revalidated, so this is the only gate.
    it('should refuse a ticket whose minting session was revoked', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
      mockRedis.redeemWsTicket.mockResolvedValue({
        sub: 'user-9',
        tenantId: 'tenant-9',
        role: 'MEMBER',
        status: 'ACTIVE',
        mfaEnabled: false,
        mfaVerified: false,
        jti: 'jti-9',
        epoch: 2
      })
      mockRevocation.isAccessTokenRevoked.mockResolvedValue(true)

      await expect(service.redeem('raw-ticket')).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.TOKEN_INVALID } }
      })
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('session that minted it'))
      warnSpy.mockRestore()
    })

    // Scenario: a live dashboard ticket and a tenant-less one. Expected: the revocation check is
    // asked about the ticket's own jti, subject, epoch and tenant, on the plane the tenant names.
    // Why: asking about anything else checks a different token than the one that minted it.
    it.each([
      ['a dashboard ticket', 'tenant-9', 'dashboard'],
      ['a ticket with no tenant', undefined, 'platform']
    ])('should check revocation for %s on the %s plane', async (_label, tenantId, plane) => {
      mockRedis.redeemWsTicket.mockResolvedValue({
        sub: 'user-9',
        ...(tenantId === undefined ? {} : { tenantId }),
        role: 'MEMBER',
        status: 'ACTIVE',
        mfaEnabled: false,
        mfaVerified: false,
        jti: 'jti-9',
        epoch: 2
      })

      await service.redeem('raw-ticket')

      expect(mockRevocation.isAccessTokenRevoked).toHaveBeenCalledWith(
        { jti: 'jti-9', sub: 'user-9', epoch: 2, tenantId },
        plane
      )
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
