/**
 * @fileoverview Tests for the `afterLogin` hook on a platform login that needs no second factor.
 *
 * Kept apart from `platform-auth.service.spec.ts` because that file is already over the size limit.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'

import { PlatformAuthService } from './platform-auth.service'
import { expectEvent } from '../__tests__/log-events'
import type { IAuthHooks } from '../interfaces/auth-hooks.interface'

const ADMIN = {
  id: 'admin-1',
  email: 'admin@example.com',
  name: 'Super Admin',
  passwordHash: 'scrypt:salt:hash',
  role: 'super_admin',
  status: 'active',
  mfaEnabled: false,
  mfaSecret: 'secret',
  mfaRecoveryCodes: ['code'],
  lastLoginAt: null,
  updatedAt: new Date('2026-01-01'),
  createdAt: new Date('2026-01-01')
}

const DTO = { email: ADMIN.email, password: 'SecureAdminPass123' }

/** The service for an admin with or without a second factor, over the given hooks. */
function build(hooks: IAuthHooks | null, mfaEnabled = false): PlatformAuthService {
  return new PlatformAuthService(
    {
      findByEmail: jest.fn().mockResolvedValue({ ...ADMIN, mfaEnabled }),
      updateLastLogin: jest.fn().mockResolvedValue(undefined)
    } as never,
    { compare: jest.fn().mockResolvedValue(true) } as never,
    {
      issuePlatformTokens: jest.fn().mockResolvedValue({ accessToken: 'a' }),
      issueMfaTempToken: jest.fn().mockResolvedValue('temp')
    } as never,
    {
      isLockedOut: jest.fn().mockResolvedValue(false),
      resetFailures: jest.fn().mockResolvedValue(undefined)
    } as never,
    {} as never,
    { hmacKey: 'k'.repeat(64), previousHmacKeys: [], blockedStatuses: [] } as never,
    hooks
  )
}

/** Lets a detached hook run. */
function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve))
}

describe('PlatformAuthService afterLogin', () => {
  beforeEach(() => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('tells the host of a sign-in that needs no second factor, without any credential', async () => {
    class Recording {
      readonly calls: unknown[][] = []

      afterLogin(...args: unknown[]): void {
        this.calls.push(args)
      }
    }
    const hooks = new Recording()

    await build(hooks as never).login(DTO, '1.2.3.4', 'jest')
    await flush()

    const {
      passwordHash: _passwordHash,
      mfaSecret: _mfaSecret,
      mfaRecoveryCodes: _mfaRecoveryCodes,
      updatedAt: _updatedAt,
      ...admin
    } = ADMIN
    expect(hooks.calls).toEqual([
      [
        expect.objectContaining({ id: admin.id, email: admin.email, tenantId: '' }),
        {
          plane: 'platform',
          userId: ADMIN.id,
          ip: '1.2.3.4',
          userAgent: 'jest',
          sanitizedHeaders: {}
        }
      ]
    ])
    expect(JSON.stringify(hooks.calls)).not.toMatch(/scrypt|secret|"code"/)
  })

  it('answers the login when the hook rejects, and logs it', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    const afterLogin = jest.fn().mockRejectedValue(new Error('hook down'))

    await expect(build({ afterLogin }).login(DTO, '1.2.3.4', 'jest')).resolves.toEqual({
      accessToken: 'a'
    })
    await flush()

    expectEvent(error, 'AUTH_HOOK_FAILED', { hook: 'afterLogin', how: 'rejected' }, ['hook down'])
  })

  it('does not fire before the second factor', async () => {
    const afterLogin = jest.fn()

    await build({ afterLogin }, true).login(DTO, '1.2.3.4', 'jest')
    await flush()

    expect(afterLogin).not.toHaveBeenCalled()
  })

  it.each([
    ['no hooks', null],
    ['hooks without afterLogin', {}]
  ])('signs in with %s', async (_name, hooks) => {
    await expect(build(hooks).login(DTO, '1.2.3.4', 'jest')).resolves.toEqual({ accessToken: 'a' })
  })
})
