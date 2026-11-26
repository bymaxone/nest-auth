/**
 * @fileoverview What {@link WsTicketService.redeem} checks beyond the minting token's revocation:
 * the token's expiry, the tenant the caller expects and the account as it stands now.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { expectEvent } from '../__tests__/log-events'
import { BYMAX_AUTH_OPTIONS, GUARDED_USER_REPOSITORY } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { WsTicketSnapshot } from '../interfaces/ws-ticket.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import { WsTicketService } from './ws-ticket.service'

const NOW_MS = 1_700_000_000_000
const NOW_SECONDS = NOW_MS / 1000

const redis = { mintWsTicket: jest.fn(), redeemWsTicket: jest.fn() }
const userRepo = { findById: jest.fn() }
const revocation = { isAccessTokenRevoked: jest.fn() }
const accountStatus = { assertPlatformAccountUsable: jest.fn() }

/** A stored dashboard snapshot. */
function snapshot(overrides: Partial<WsTicketSnapshot> = {}): WsTicketSnapshot {
  return {
    sub: 'user-9',
    tenantId: 'tenant-9',
    role: 'MEMBER',
    status: 'ACTIVE',
    mfaEnabled: false,
    mfaVerified: false,
    jti: 'jti-9',
    epoch: 0,
    ...overrides
  }
}

/** A stored snapshot that names no tenant, as only another writer of the keyspace leaves one. */
function platformSnapshot(): WsTicketSnapshot {
  const { tenantId: _tenantId, ...rest } = snapshot()
  return rest
}

const refusedAs = (code: string): object => ({ response: { error: { code } } })

describe('WsTicketService.redeem against the present', () => {
  let service: WsTicketService
  let warn: jest.SpyInstance

  beforeEach(async () => {
    jest.resetAllMocks()
    jest.spyOn(Date, 'now').mockReturnValue(NOW_MS)
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})
    redis.redeemWsTicket.mockResolvedValue(snapshot())
    revocation.isAccessTokenRevoked.mockResolvedValue(false)
    userRepo.findById.mockResolvedValue({ id: 'user-9', tenantId: 'tenant-9', status: 'ACTIVE' })

    const module = await Test.createTestingModule({
      providers: [
        WsTicketService,
        { provide: AuthRedisService, useValue: redis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: { blockedStatuses: ['SUSPENDED'] } },
        { provide: GUARDED_USER_REPOSITORY, useValue: userRepo },
        { provide: AuthRevocationService, useValue: revocation },
        { provide: AccountStatusService, useValue: accountStatus }
      ]
    }).compile()
    service = module.get(WsTicketService)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // The ticket was minted by an account in good standing; the socket is opened on what the
  // account is now, because nothing revalidates it afterwards.
  it('refuses an account blocked after the ticket was minted, naming the status', async () => {
    userRepo.findById.mockResolvedValue({ id: 'user-9', tenantId: 'tenant-9', status: 'SUSPENDED' })

    await expect(service.redeem('t')).rejects.toMatchObject(
      refusedAs(AUTH_ERROR_CODES.ACCOUNT_SUSPENDED)
    )
    expectEvent(warn, 'AUTH_WS_TICKET_REFUSED', { reason: 'account_blocked' }, ['user-9'])
  })

  it('refuses an account that is gone', async () => {
    userRepo.findById.mockResolvedValue(null)

    await expect(service.redeem('t')).rejects.toMatchObject(
      refusedAs(AUTH_ERROR_CODES.TOKEN_INVALID)
    )
    expectEvent(warn, 'AUTH_WS_TICKET_REFUSED', { reason: 'account_gone' }, ['user-9'])
  })

  it('reads the account of the snapshot in the tenant of the snapshot', async () => {
    await service.redeem('t')

    expect(userRepo.findById).toHaveBeenCalledWith({ id: 'user-9', tenantId: 'tenant-9' })
    expect(accountStatus.assertPlatformAccountUsable).not.toHaveBeenCalled()
  })

  it('surfaces a repository failure as itself', async () => {
    userRepo.findById.mockRejectedValue(new Error('database down'))

    await expect(service.redeem('t')).rejects.toThrow('database down')
    expect(warn).not.toHaveBeenCalled()
  })

  it('checks a snapshot with no tenant against the platform account', async () => {
    redis.redeemWsTicket.mockResolvedValue(platformSnapshot())
    accountStatus.assertPlatformAccountUsable.mockRejectedValue(
      new AuthException(AUTH_ERROR_CODES.ACCOUNT_BANNED)
    )

    await expect(service.redeem('t')).rejects.toMatchObject(
      refusedAs(AUTH_ERROR_CODES.ACCOUNT_BANNED)
    )
    expect(accountStatus.assertPlatformAccountUsable).toHaveBeenCalledWith('user-9')
    expect(userRepo.findById).not.toHaveBeenCalled()
  })

  // Scenario: a dashboard caller redeems a snapshot with no tenant. Expected: refused, and nothing
  // is read for it. Why: the socket is refused either way, so the reads buy nothing.
  it.each([
    ['no tenant', platformSnapshot()],
    ['an empty tenant', snapshot({ tenantId: '' })]
  ])('refuses %s before any read when a tenant is required', async (_label, stored) => {
    redis.redeemWsTicket.mockResolvedValue(stored)

    await expect(service.redeem('t', undefined, { requireTenant: true })).rejects.toMatchObject(
      refusedAs(AUTH_ERROR_CODES.TOKEN_INVALID)
    )
    expect(revocation.isAccessTokenRevoked).not.toHaveBeenCalled()
    expect(accountStatus.assertPlatformAccountUsable).not.toHaveBeenCalled()
    expect(userRepo.findById).not.toHaveBeenCalled()
    expect(warn).not.toHaveBeenCalled()
  })

  it.each([[{}], [{ requireTenant: false }], [undefined]])(
    'checks the platform account of a tenantless snapshot under %p',
    async (options) => {
      redis.redeemWsTicket.mockResolvedValue(platformSnapshot())

      await service.redeem('t', undefined, options)

      expect(accountStatus.assertPlatformAccountUsable).toHaveBeenCalledWith('user-9')
    }
  )

  it('admits a snapshot with a tenant when one is required', async () => {
    await expect(service.redeem('t', undefined, { requireTenant: true })).resolves.toStrictEqual(
      snapshot()
    )
  })

  it.each([
    ['ended a second ago', NOW_SECONDS - 1],
    ['ends now', NOW_SECONDS]
  ])('refuses a snapshot whose token %s', async (_label, exp) => {
    redis.redeemWsTicket.mockResolvedValue(snapshot({ exp }))

    await expect(service.redeem('t')).rejects.toMatchObject(
      refusedAs(AUTH_ERROR_CODES.TOKEN_INVALID)
    )
    expectEvent(warn, 'AUTH_WS_TICKET_REFUSED', { reason: 'expired' })
  })

  it.each([
    ['a token with life left', { exp: NOW_SECONDS + 1 }],
    ['a snapshot written without exp', {}]
  ])('admits %s', async (_label, overrides) => {
    redis.redeemWsTicket.mockResolvedValue(snapshot(overrides))

    await expect(service.redeem('t')).resolves.toStrictEqual(snapshot(overrides))
  })

  it.each([
    ['another tenant', 'tenant-1', snapshot()],
    ['an empty expectation', '', snapshot()],
    ['a snapshot that names no tenant', 'tenant-9', platformSnapshot()]
  ])('refuses on %s', async (_label, expected, stored) => {
    redis.redeemWsTicket.mockResolvedValue(stored)

    await expect(service.redeem('t', expected)).rejects.toMatchObject(
      refusedAs(AUTH_ERROR_CODES.TOKEN_INVALID)
    )
    expectEvent(warn, 'AUTH_WS_TICKET_REFUSED', { reason: 'tenant_mismatch' })
  })

  it('admits the tenant the caller expects', async () => {
    await expect(service.redeem('t', 'tenant-9')).resolves.toStrictEqual(snapshot())
  })
})
