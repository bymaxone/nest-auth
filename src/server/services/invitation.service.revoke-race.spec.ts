/**
 * @fileoverview Tests for the invitee index of a tenant invitation under a concurrent writer: a revoke and an acceptance drop it
 * only while it names the invitation they act on, and a revoke reads a replaced one again, three times at most.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { InvitationService } from './invitation.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'
import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { RELEASE_INDEX_SCRIPT } from '../redis/release-index.script'

const HMAC_KEY = 'invitation-release-spec-key'
const INDEX_KEY = `invidx:tenant-1:${hmacSha256('invited@example.com', HMAC_KEY)}`
const TOKEN_HASH = 'b'.repeat(64)
const TOKEN = 'a'.repeat(64)
const STORED = JSON.stringify({
  email: 'invited@example.com',
  role: 'member',
  tenantId: 'tenant-1',
  inviterUserId: 'inviter-1',
  createdAt: '2026-01-01T00:00:00.000Z'
})
const INVITER = { id: 'inviter-1', role: 'admin', status: 'active', tenantId: 'tenant-1' }
const OPTIONS = {
  hmacKey: HMAC_KEY,
  roles: { hierarchy: { admin: ['member'], member: [] as string[] } },
  invitations: { tokenTtlSeconds: 86_400 },
  sessions: { enabled: false },
  blockedStatuses: ['BANNED']
}

const redis = { get: jest.fn(), del: jest.fn(), getdel: jest.fn(), eval: jest.fn() }
const userRepo = { findById: jest.fn(), findByEmail: jest.fn(), create: jest.fn() }

describe('InvitationService and the invitee index under a concurrent writer', () => {
  let service: InvitationService
  let logged: jest.SpyInstance

  beforeEach(async () => {
    jest.resetAllMocks()
    userRepo.findById.mockResolvedValue(INVITER)
    redis.get.mockImplementation((key: string) =>
      Promise.resolve(key === INDEX_KEY ? TOKEN_HASH : STORED)
    )
    redis.del.mockResolvedValue(true)
    redis.eval.mockResolvedValue(1)
    const module = await Test.createTestingModule({
      providers: [
        InvitationService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: OPTIONS },
        { provide: GUARDED_USER_REPOSITORY, useValue: userRepo },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} },
        { provide: BYMAX_AUTH_HOOKS, useValue: null },
        { provide: PasswordService, useValue: { assertAcceptable: jest.fn() } },
        { provide: SessionService, useValue: {} },
        { provide: TokenManagerService, useValue: {} },
        { provide: AuthRedisService, useValue: redis }
      ]
    }).compile()
    service = module.get(InvitationService)
    // After the compile, which logs on its own.
    logged = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  const revoke = (): Promise<unknown> =>
    service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')

  // Scenario: an acceptance consumes the record. Expected: the index is released against the hash of the consumed token and never
  // deleted outright. Why: a replacement may have claimed the index, and it is the only handle a revoke has on that record.
  it('releases the index of an acceptance against the hash of the token it consumed', async () => {
    redis.getdel.mockResolvedValueOnce(STORED)
    userRepo.findByEmail.mockResolvedValueOnce({ id: 'existing' })

    await expect(
      service.acceptInvitation(
        { token: TOKEN, name: 'Name', password: 'Secure123!' },
        '1.2.3.4',
        'agent',
        {}
      )
    ).rejects.toBeInstanceOf(AuthException)

    expect(redis.eval).toHaveBeenCalledWith(RELEASE_INDEX_SCRIPT, [INDEX_KEY], [sha256(TOKEN)])
    expect(redis.del).not.toHaveBeenCalled()
  })

  // Scenario: a revoke finds its invitation still indexed. Expected: the index is released by comparison, not deleted. Why: the
  // same.
  it('releases the index of a revoke by comparison', async () => {
    await expect(revoke()).resolves.toBe(true)

    expect(redis.eval).toHaveBeenCalledWith(RELEASE_INDEX_SCRIPT, [INDEX_KEY], [TOKEN_HASH])
    expect(redis.del).not.toHaveBeenCalledWith(INDEX_KEY)
  })

  // Scenario: the record is already gone. Expected: `false` and no log. Why: nothing was withdrawn.
  it('logs no withdrawal when no record was removed', async () => {
    redis.del.mockResolvedValue(false)

    await expect(revoke()).resolves.toBe(false)

    expect(logged).not.toHaveBeenCalled()
  })

  // Scenario: the address has no invitation. Expected: `false` and no log. Why: nothing was withdrawn.
  it('logs nothing when the address has no invitation', async () => {
    redis.get.mockResolvedValue(null)

    await expect(revoke()).resolves.toBe(false)

    expect(logged).not.toHaveBeenCalled()
  })

  // Scenario: the revoker ranks below the invited role. Expected: `false`, and the refusal is the one record. Why: a withdrawal
  // logged for a refusal would report what did not happen.
  it('logs the refusal and no withdrawal when the revoker is outranked', async () => {
    userRepo.findById.mockResolvedValue({ ...INVITER, role: 'member' })
    redis.get.mockImplementation((key: string) =>
      Promise.resolve(key === INDEX_KEY ? TOKEN_HASH : STORED.replace('"member"', '"admin"'))
    )
    const warned = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

    await expect(revoke()).resolves.toBe(false)

    expect(logged).not.toHaveBeenCalled()
    expect(JSON.stringify(warned.mock.calls)).toContain('revoke_outranked')
  })

  // Scenario: the index moves before every attempt. Expected: `auth.too_many_requests` after three reads of the address, each
  // record read being deleted and logged. Why: the invitation indexed is no longer the one judged, so the revoke is not complete.
  it('refuses after three attempts while the index keeps moving', async () => {
    redis.eval.mockResolvedValue(0)

    await expect(revoke()).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.TOO_MANY_REQUESTS } }
    })

    expect(redis.get.mock.calls.filter(([key]) => key === INDEX_KEY)).toHaveLength(3)
    expect(redis.del).toHaveBeenCalledTimes(3)
    expect(redis.del).not.toHaveBeenCalledWith(INDEX_KEY)
  })

  // Scenario: the index moves before the first two attempts, then before all three. Expected: the third removes; there is no
  // fourth. Why: the bound is three from both sides.
  it.each([
    [2, 'removes on the third attempt'],
    [3, 'refuses although a fourth attempt would have removed']
  ])('after %i replacements %s', async (replacements) => {
    for (let i = 0; i < replacements; i += 1) redis.eval.mockResolvedValueOnce(0)

    const outcome = await revoke().catch((error: unknown) => error)

    expect(outcome === true).toBe(replacements === 2)
    expect(outcome instanceof AuthException).toBe(replacements === 3)
    expect(redis.eval).toHaveBeenCalledTimes(3)
    expect(logged).toHaveBeenCalledTimes(3)
  })

  // Scenario: the store fails while the record is being deleted. Expected: the index is not released. Why: the index is the only
  // handle a later revoke has on a record that is still there.
  it('keeps the index while the record could not be deleted', async () => {
    redis.del.mockRejectedValueOnce(new Error('connection reset'))

    await expect(revoke()).rejects.toThrow('connection reset')

    expect(redis.eval).not.toHaveBeenCalled()
  })

  // Scenario: the store fails while the index is being released. Expected: the record is already deleted. Why: what stays behind
  // must be an index that names nothing, never a record that can be redeemed.
  it('has deleted the record when the index cannot be released', async () => {
    redis.eval.mockRejectedValueOnce(new Error('connection reset'))

    await expect(revoke()).rejects.toThrow('connection reset')

    expect(redis.del).toHaveBeenCalledWith(`inv:${TOKEN_HASH}`)
  })

  // Scenario: the record is removed and the index is gone by the time it is released. Expected: `true`. Why: this call removed
  // an invitation, whatever happened to the index afterwards.
  it('reports the removal when the index was gone before it could be released', async () => {
    redis.eval.mockResolvedValueOnce(0)
    redis.get
      .mockResolvedValueOnce(TOKEN_HASH)
      .mockResolvedValueOnce(STORED)
      .mockResolvedValue(null)

    await expect(revoke()).resolves.toBe(true)
  })

  // Scenario: the index names no record. Expected: the index is released before the record is deleted. Why: an invite may be
  // about to write that record, and its second claim must then fail.
  it('releases an index that names no record before it deletes under that hash', async () => {
    const order: string[] = []
    redis.get.mockImplementation((key: string) =>
      Promise.resolve(key === INDEX_KEY ? TOKEN_HASH : null)
    )
    redis.eval.mockImplementation(() => Promise.resolve(order.push('release')))
    redis.del.mockImplementation(() => {
      order.push('delete')
      return Promise.resolve(false)
    })

    await expect(revoke()).resolves.toBe(false)

    expect(order).toEqual(['release', 'delete'])
  })

  // Scenario: the index names no record and has moved by the time it is released. Expected: nothing is deleted under the old
  // hash on that attempt and the address is read again. Why: what is indexed now has not been judged.
  it('reads the address again when an index that named no record has moved', async () => {
    redis.get.mockResolvedValueOnce(TOKEN_HASH).mockResolvedValueOnce(null)
    redis.eval.mockResolvedValueOnce(0)

    await expect(revoke()).resolves.toBe(true)

    expect(redis.del).toHaveBeenCalledTimes(1)
    expect(redis.get.mock.calls.filter(([key]) => key === INDEX_KEY)).toHaveLength(2)
  })

  // Scenario: the replacement read on the second attempt ranks above the revoker. Expected: it is not deleted. Why: the ceiling
  // is applied on every attempt, not on the first one only.
  it('applies the role ceiling to the replacement it reads on a later attempt', async () => {
    const replacement = 'c'.repeat(64)
    const above = STORED.replace('"member"', '"owner"')
    redis.eval.mockResolvedValueOnce(0)
    redis.get
      .mockResolvedValueOnce(TOKEN_HASH)
      .mockResolvedValueOnce(STORED)
      .mockResolvedValueOnce(replacement)
      .mockResolvedValueOnce(above)
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

    await expect(revoke()).resolves.toBe(true)

    expect(redis.del.mock.calls).toEqual([[`inv:${TOKEN_HASH}`]])
  })
})
