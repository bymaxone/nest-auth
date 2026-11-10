/**
 * @fileoverview Tests for the host's `afterInvitationAccepted` hook on the tenant invitation
 * accept: a failure of the hook, however it fails, never changes the answer.
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
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AuthRedisService } from '../redis/auth-redis.service'

const TOKEN = 'a'.repeat(64)
const RESULT = { user: { id: 'new-user-1' }, accessToken: 'access.jwt', rawRefreshToken: 'raw' }
const OPTIONS = {
  hmacKey: 'invitation-hook-spec-key',
  roles: { hierarchy: { admin: ['member'], member: [] as string[] } },
  invitations: { tokenTtlSeconds: 86_400 },
  sessions: { enabled: false },
  blockedStatuses: ['BANNED']
}

/** The service with a hook that fails the way `fail` says, and the account it creates. */
async function serviceWith(
  afterInvitationAccepted: (() => unknown) | null
): Promise<InvitationService> {
  const stored = JSON.stringify({
    email: 'invited@example.com',
    role: 'member',
    tenantId: 'tenant-1',
    inviterUserId: 'inviter-1',
    createdAt: '2026-01-01T00:00:00.000Z'
  })
  const inviter = { id: 'inviter-1', role: 'admin', status: 'active', tenantId: 'tenant-1' }
  const created = { id: 'new-user-1', email: 'invited@example.com', tenantId: 'tenant-1' }
  const module = await Test.createTestingModule({
    providers: [
      InvitationService,
      { provide: BYMAX_AUTH_OPTIONS, useValue: OPTIONS },
      {
        provide: BYMAX_AUTH_USER_REPOSITORY,
        useValue: {
          findById: jest.fn().mockResolvedValue(inviter),
          findByEmail: jest.fn().mockResolvedValue(null),
          create: jest.fn().mockResolvedValue(created)
        }
      },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} },
      {
        provide: BYMAX_AUTH_HOOKS,
        useValue: afterInvitationAccepted === null ? null : { afterInvitationAccepted }
      },
      {
        provide: PasswordService,
        useValue: {
          assertAcceptable: jest.fn().mockResolvedValue(undefined),
          hash: jest.fn().mockResolvedValue('hash')
        }
      },
      { provide: SessionService, useValue: { createSession: jest.fn() } },
      {
        provide: TokenManagerService,
        useValue: { issueTokens: jest.fn().mockResolvedValue(RESULT) }
      },
      {
        provide: AuthRedisService,
        useValue: { getdel: jest.fn().mockResolvedValue(stored), del: jest.fn() }
      }
    ]
  }).compile()
  return module.get(InvitationService)
}

describe('InvitationService afterInvitationAccepted hook', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  const accept = (service: InvitationService): Promise<unknown> =>
    service.acceptInvitation(
      { token: TOKEN, name: 'Invited User', password: 'Secure123!' },
      '1.2.3.4',
      'jest',
      {}
    )

  it('answers the acceptance when the hook throws synchronously, and logs it', async () => {
    const logged = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const service = await serviceWith(() => {
      throw new Error('hook broke')
    })

    await expect(accept(service)).resolves.toBe(RESULT)

    expect(logged).toHaveBeenCalledWith(
      expect.stringContaining('afterInvitationAccepted hook threw')
    )
  })

  it('answers the acceptance when the hook rejects, and logs it', async () => {
    const logged = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const service = await serviceWith(() => Promise.reject(new Error('hook down')))

    await expect(accept(service)).resolves.toBe(RESULT)
    await new Promise((resolve) => setImmediate(resolve))

    expect(logged).toHaveBeenCalledWith(
      expect.stringContaining('afterInvitationAccepted hook threw')
    )
  })

  it('answers the acceptance without logging a failure when there is no hooks container', async () => {
    const logged = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const service = await serviceWith(null)

    await expect(accept(service)).resolves.toBe(RESULT)

    expect(logged).not.toHaveBeenCalled()
  })
})
