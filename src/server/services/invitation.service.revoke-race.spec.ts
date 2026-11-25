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

  // Scenario: the index moves before every attempt. Expected: `auth.too_many_requests` after three reads of the address, and no
  // record deleted. Why: the invitation judged is no longer the one indexed.
  it('deletes nothing and refuses after three attempts while the index keeps moving', async () => {
    redis.eval.mockResolvedValue(0)

    await expect(revoke()).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.TOO_MANY_REQUESTS } }
    })

    expect(redis.get.mock.calls.filter(([key]) => key === INDEX_KEY)).toHaveLength(3)
    expect(redis.del).not.toHaveBeenCalled()
    expect(logged).not.toHaveBeenCalled()
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
    expect(logged).toHaveBeenCalledTimes(replacements === 2 ? 1 : 0)
  })
})
