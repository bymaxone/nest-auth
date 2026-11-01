/**
 * @fileoverview The claim `InvitationService.invite` repeats once the invitation record is written.
 *
 * `invite` claims the invitee index first and writes the record second. The index is repeated
 * against the invitation's own hash after the write, so a revoke or a later invite that moved it
 * in between leaves nothing redeemable and no email sent. These cases pin that repeat and what
 * happens to the record on each way it can fail; the lifecycle is covered in
 * `invitation.service.spec.ts` and the interleave over real routes in
 * `test/e2e/invitation-claim-window.e2e-spec.ts`.
 *
 * @layer Service
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthRedisService } from '../redis/auth-redis.service'
import { InvitationService } from './invitation.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

/** An admin: the role hierarchy below lets it invite a member. */
const INVITER = {
  id: 'inviter-1',
  email: 'admin@example.com',
  name: 'Admin User',
  passwordHash: 'scrypt:salt:hash',
  role: 'admin',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const mockUserRepo = { findById: jest.fn(), findByEmail: jest.fn(), create: jest.fn() }
const mockEmailProvider = { sendInvitation: jest.fn() }
const mockRedis = {
  set: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  getdel: jest.fn(),
  // Each script call answers 1 ("claimed") unless a case queues otherwise.
  eval: jest.fn().mockResolvedValue(1)
}

const mockOptions = {
  hmacKey: 'invitation-spec-hmac-key',
  roles: { hierarchy: { admin: ['member'], member: [] as string[] } },
  invitations: { tokenTtlSeconds: 86_400 },
  sessions: { enabled: false },
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED']
}

describe('InvitationService — the claim repeated after the record is written', () => {
  let service: InvitationService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        InvitationService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: { afterInvitationAccepted: jest.fn() } },
        { provide: PasswordService, useValue: {} },
        { provide: SessionService, useValue: {} },
        { provide: TokenManagerService, useValue: {} },
        { provide: AuthRedisService, useValue: mockRedis }
      ]
    }).compile()

    service = module.get(InvitationService)
  })

  describe('the claim is repeated once the record is written', () => {
    beforeEach(() => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.set.mockResolvedValue('OK')
      mockRedis.del.mockResolvedValue(true)
      mockEmailProvider.sendInvitation.mockResolvedValue(undefined)
    })

    /** The key the invitation record was written under. */
    const recordKey = (): string => String(mockRedis.set.mock.calls[0]?.[0])

    // Scenario: the happy path. Expected: the repeat claims against the invitation's OWN hash
    // and with the full TTL. Why: it must hold only while the index still names this record,
    // and it is what renews the TTL the first claim started.
    it('repeats the claim against its own hash with the full TTL', async () => {
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      const [first, second] = mockRedis.eval.mock.calls as [string, string[], string[]][]
      const ownHash = String(recordKey()).replace(/^inv:/, '')
      expect(second?.[1]).toEqual(first?.[1])
      expect(second?.[2]).toEqual([ownHash, first?.[2]?.[1], ownHash])
    })

    // Scenario: the index no longer names this invitation when the record lands (a revoke or a
    // later invite moved it). Expected: the record is withdrawn, no email is sent and the caller
    // is refused. Why: the record would otherwise be live with nothing naming it.
    it('withdraws its own record and sends nothing when the index was moved', async () => {
      mockRedis.eval.mockResolvedValueOnce(1).mockResolvedValueOnce(0)

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE } }
      })

      expect(mockRedis.del).toHaveBeenCalledWith(recordKey())
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
    })

    // Scenario: the repeat fails for a reason that says nothing about the index (the store
    // errors). Expected: the record is withdrawn all the same, the original failure surfaces and
    // no email is sent. Why: an invitation this method could not stand behind must not stay live.
    it('withdraws its own record and surfaces the failure when the repeat errors', async () => {
      const failure = new Error('connection reset')
      mockRedis.eval.mockResolvedValueOnce(1).mockRejectedValueOnce(failure)

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toBe(failure)

      expect(mockRedis.del).toHaveBeenCalledWith(recordKey())
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
    })

    // Scenario: the index moved AND the withdrawal fails. Expected: the refusal is still what the
    // caller sees, the failed withdrawal is logged, and no email is sent. Why: a store failure
    // while cleaning up must not replace the answer about the invitation.
    it('still refuses with insufficient_role when the withdrawal after a moved index fails', async () => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.eval.mockResolvedValueOnce(1).mockResolvedValueOnce(0)
      mockRedis.del.mockRejectedValueOnce(new Error('still down'))

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE } }
      })

      expect(String(warn.mock.calls[0]?.[0])).toContain('could not withdraw the record')
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
      warn.mockRestore()
    })

    // Scenario: the repeat errors AND the withdrawal errors too. Expected: the original failure
    // still surfaces, the second one is logged, and no email is sent.
    it('keeps the original failure when the withdrawal fails as well', async () => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      const failure = new Error('connection reset')
      mockRedis.eval.mockResolvedValueOnce(1).mockRejectedValueOnce(failure)
      // Once, not for good: the shared double keeps implementations across tests.
      mockRedis.del.mockRejectedValueOnce(new Error('still down'))

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toBe(failure)

      expect(String(warn.mock.calls[0]?.[0])).toContain('could not withdraw the record')
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
      warn.mockRestore()
    })
  })
})
