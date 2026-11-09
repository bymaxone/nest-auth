/**
 * @fileoverview Tests for `WorkspaceCallerService`: loading the account behind a token and
 * re-proving it.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import type { ReauthenticationService } from './reauthentication.service'
import { WorkspaceCallerService } from './workspace-caller.service'

const CALLER = { sub: 'u1', tenantId: 't1' }
const USER: AuthUser = {
  id: 'u1',
  email: 'a@b.c',
  name: 'Alice',
  passwordHash: 'hash',
  role: 'MEMBER',
  status: 'ACTIVE',
  tenantId: 't1',
  emailVerified: true,
  mfaEnabled: true,
  mfaSecret: 'secret',
  mfaRecoveryCodes: ['x'],
  lastLoginAt: null,
  createdAt: new Date(0)
}

function build(found: AuthUser | null = USER): {
  service: WorkspaceCallerService
  findById: jest.Mock
  assertReauthenticated: jest.Mock
} {
  const findById = jest.fn().mockResolvedValue(found)
  const assertReauthenticated = jest.fn().mockResolvedValue(undefined)
  return {
    service: new WorkspaceCallerService(
      { findById } as Partial<IUserRepository> as IUserRepository,
      { assertReauthenticated } as Partial<ReauthenticationService> as ReauthenticationService
    ),
    findById,
    assertReauthenticated
  }
}

async function codeOf(run: Promise<unknown>): Promise<string | undefined> {
  try {
    await run
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

describe('WorkspaceCallerService', () => {
  describe('load', () => {
    it('reads the account by the token subject and tenant and strips its credentials', async () => {
      const { service, findById } = build()

      const user = await service.load(CALLER)

      expect(findById).toHaveBeenCalledWith({ id: 'u1', tenantId: 't1' })
      expect(user).toMatchObject({ id: 'u1', tenantId: 't1', email: 'a@b.c' })
      expect(user).not.toHaveProperty('passwordHash')
      expect(user).not.toHaveProperty('mfaSecret')
      expect(user).not.toHaveProperty('mfaRecoveryCodes')
    })

    it('answers an invalid token when the account no longer exists', async () => {
      const { service } = build(null)

      await expect(codeOf(service.load(CALLER))).resolves.toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })
  })

  describe('reauthenticate', () => {
    it('re-proves the dashboard account with its hash and the submitted password', async () => {
      const { service, assertReauthenticated } = build()

      await service.reauthenticate(CALLER, 'pw')

      expect(assertReauthenticated).toHaveBeenCalledWith('dashboard', 'u1', 'hash', 'pw', 't1')
    })

    it('passes an absent password through, for the re-proof to refuse', async () => {
      const { service, assertReauthenticated } = build()

      await service.reauthenticate(CALLER, undefined)

      expect(assertReauthenticated).toHaveBeenCalledWith('dashboard', 'u1', 'hash', undefined, 't1')
    })

    it('hands a passwordless account to the re-proof with a null hash', async () => {
      const { service, assertReauthenticated } = build({ ...USER, passwordHash: null })

      await service.reauthenticate(CALLER, undefined)

      expect(assertReauthenticated).toHaveBeenCalledWith('dashboard', 'u1', null, undefined, 't1')
    })

    it('answers an invalid token, and proves nothing, when the account no longer exists', async () => {
      const { service, assertReauthenticated } = build(null)

      await expect(codeOf(service.reauthenticate(CALLER, 'pw'))).resolves.toBe(
        AUTH_ERROR_CODES.TOKEN_INVALID
      )
      expect(assertReauthenticated).not.toHaveBeenCalled()
    })
  })
})
