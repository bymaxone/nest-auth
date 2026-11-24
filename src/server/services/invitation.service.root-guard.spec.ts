/**
 * @fileoverview The invitation service decides whether a user may withdraw an invitation after the lookups it waits for, so it
 * checks the runtime right before it compares the two roles: a built-in replaced during a lookup must refuse the withdrawal before
 * the invitation is deleted.
 *
 * @layer Test
 */

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
import { AuthRedisService } from '../redis/auth-redis.service'

// The test's own copies: the window below replaces a built-in, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

const OPTIONS = {
  hmacKey: 'invitation-root-guard-spec-key',
  roles: { hierarchy: { admin: ['member'], member: [] as string[] } },
  invitations: { tokenTtlSeconds: 86_400 },
  sessions: { enabled: false },
  blockedStatuses: ['BANNED']
}

/** The invitation the revoker names: it grants `admin`, a role above the revoker's. */
const STORED = JSON.stringify({
  email: 'invited@example.com',
  role: 'admin',
  tenantId: 'tenant-1',
  inviterUserId: 'inviter-1',
  createdAt: '2026-01-01T00:00:00.000Z'
})

/** The service over a store whose second read of the invitation runs `during`, and the calls the store has seen. */
async function serviceWith(
  during: () => void
): Promise<{ service: InvitationService; del: jest.Mock }> {
  const get = jest
    .fn()
    .mockResolvedValueOnce('hash-of-token')
    .mockImplementationOnce(async () => {
      await Promise.resolve()
      during()
      return STORED
    })
  const del = jest.fn().mockResolvedValue(true)
  const module = await Test.createTestingModule({
    providers: [
      InvitationService,
      { provide: BYMAX_AUTH_OPTIONS, useValue: OPTIONS },
      {
        provide: GUARDED_USER_REPOSITORY,
        useValue: {
          findById: jest.fn().mockResolvedValue({
            id: 'member-1',
            role: 'member',
            status: 'active',
            tenantId: 'tenant-1'
          })
        }
      },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} },
      { provide: BYMAX_AUTH_HOOKS, useValue: null },
      { provide: PasswordService, useValue: {} },
      { provide: SessionService, useValue: {} },
      { provide: TokenManagerService, useValue: {} },
      { provide: AuthRedisService, useValue: { get, del } }
    ]
  }).compile()
  return { service: module.get(InvitationService), del }
}

describe('InvitationService.revokeInvitation while a built-in is replaced', () => {
  // Scenario: a member withdraws an invitation that grants a role above theirs, and the read of the invitation replaces
  // `Array.prototype.includes` with a function that answers true. Expected: the library's refusal and the invitation is not
  // deleted. Why: with `includes` replaced a member outranks an administrator, and the deletion is committed at once.
  it('refuses the withdrawal of an invitation above the revoker, and deletes nothing', async () => {
    let restore = (): void => undefined
    const { service, del } = await serviceWith(() => {
      const held = getOwn(Array.prototype, 'includes') as PropertyDescriptor
      define(Array.prototype, 'includes', { ...held, value: () => true })
      restore = (): void => void define(Array.prototype, 'includes', held)
    })
    let status: number | undefined
    try {
      await service.revokeInvitation('member-1', 'invited@example.com', 'tenant-1')
    } catch (error) {
      status = (error as { getStatus?: () => number }).getStatus?.()
    } finally {
      restore()
    }

    expect(status).toBe(500)
    expect(del).not.toHaveBeenCalled()
  })

  // Scenario: the same withdrawal with nothing replaced. Expected: answered `false`, as an address with no invitation is. Why: the
  // control: the rows above are the refusal of the runtime and not of the role.
  it('still answers false for an invitation above the revoker with nothing replaced', async () => {
    const { service, del } = await serviceWith(() => undefined)

    await expect(
      service.revokeInvitation('member-1', 'invited@example.com', 'tenant-1')
    ).resolves.toBe(false)
    expect(del).not.toHaveBeenCalled()
  })
})
