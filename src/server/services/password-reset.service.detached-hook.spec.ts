/**
 * @fileoverview PasswordResetService — a host `afterPasswordReset` hook that throws synchronously.
 *
 * The hook runs after the password, the sessions and the token epoch have been written, so a throw
 * that escaped would answer a completed reset as a failure. The reset must still answer and the
 * failure must be logged by name. Kept apart from `password-reset.service.spec.ts` because that
 * file is over the size limit.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordResetService } from './password-reset.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'

const USER = {
  id: 'u1',
  email: 'user@example.com',
  name: 'User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  passwordHash: 'old'
}

/** A service whose hook throws before it returns anything. */
async function build(): Promise<PasswordResetService> {
  const module = await Test.createTestingModule({
    providers: [
      PasswordResetService,
      {
        provide: BYMAX_AUTH_OPTIONS,
        useValue: { passwordReset: { method: 'otp' }, hmacKey: 'k', previousHmacKeys: [] }
      },
      {
        provide: BYMAX_AUTH_USER_REPOSITORY,
        useValue: {
          findById: jest.fn().mockResolvedValue(USER),
          updatePassword: jest.fn().mockResolvedValue(undefined)
        }
      },
      { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: null },
      {
        provide: BYMAX_AUTH_HOOKS,
        useValue: {
          afterPasswordReset: jest.fn(() => {
            throw new Error('hook broke')
          })
        }
      },
      { provide: OtpService, useValue: {} },
      { provide: PasswordService, useValue: { hash: jest.fn().mockResolvedValue('new') } },
      {
        provide: AuthRedisService,
        useValue: {
          invalidateUserSessions: jest.fn().mockResolvedValue(undefined),
          bumpUserTokenEpoch: jest.fn().mockResolvedValue(undefined)
        }
      },
      { provide: SessionService, useValue: {} },
      { provide: BruteForceService, useValue: {} }
    ]
  }).compile()
  return module.get(PasswordResetService)
}

describe('PasswordResetService with a hook that throws synchronously', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('still completes the reset, and logs afterPasswordReset', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const service = await build()

    await expect(service['applyPasswordReset']('u1', 'tenant1', 'NewP@ssw0rd!')).resolves.toBe(
      undefined
    )

    expect(error).toHaveBeenCalledWith(expect.stringContaining('afterPasswordReset hook threw'))
  })
})
