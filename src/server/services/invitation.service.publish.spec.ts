/**
 * @fileoverview The one write `InvitationService.invite` makes to the store, and what follows it.
 *
 * The record, its index and the removal of the superseded record are one script, so these cases pin
 * what the caller sees and what is sent for each way that script can answer or fail. The lifecycle
 * is covered in `invitation.service.spec.ts` and the interleaves over real routes in
 * `test/e2e/invitation-claim-window.e2e-spec.ts`.
 *
 * @layer Service
 */

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
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
  // Each script call answers 1 ("stored") unless a case queues otherwise.
  eval: jest.fn().mockResolvedValue(1)
}

const mockOptions = {
  hmacKey: 'invitation-spec-hmac-key',
  roles: { hierarchy: { admin: ['member'], member: [] as string[] } },
  invitations: { tokenTtlSeconds: 86_400 },
  sessions: { enabled: false },
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED']
}

describe('InvitationService — the write of a new invitation', () => {
  let service: InvitationService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        InvitationService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: GUARDED_USER_REPOSITORY, useValue: mockUserRepo },
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

  beforeEach(() => {
    mockUserRepo.findById.mockResolvedValue(INVITER)
    mockRedis.get.mockResolvedValue(null)
    mockRedis.eval.mockResolvedValue(1)
    mockEmailProvider.sendInvitation.mockResolvedValue(undefined)
  })

  const invite = (): Promise<void> =>
    service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

  // Scenario: the happy path. Expected: the store receives one write, the script, and no separate
  // `set` or `del`. Why: a second command is a point where a failure leaves a record without its
  // index, or an index without its record.
  it('writes the invitation with one script and no other command', async () => {
    await invite()

    expect(mockRedis.eval).toHaveBeenCalledTimes(1)
    expect(mockRedis.set).not.toHaveBeenCalled()
    expect(mockRedis.del).not.toHaveBeenCalled()
    expect(mockEmailProvider.sendInvitation).toHaveBeenCalledTimes(1)
  })

  // Scenario: the script fails. Expected: the failure surfaces as it was and no email is sent.
  // Why: a token must not be sent for an invitation this method cannot say was stored.
  it('surfaces a failed write and sends nothing', async () => {
    const failure = new Error('connection reset')
    mockRedis.eval.mockRejectedValueOnce(failure)

    await expect(invite()).rejects.toBe(failure)

    expect(mockRedis.del).not.toHaveBeenCalled()
    expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
  })
})
