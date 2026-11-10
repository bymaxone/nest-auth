/**
 * @fileoverview Tests for the password sign-up gate of `registration: 'invitation-only'`.
 *
 * @layer Test
 */

import type { Request } from 'express'

import { AuthService } from './auth.service'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'

const DTO = { email: 'new@example.com', password: 'SecureP@ss1', name: 'New User', tenantId: 't1' }
const REQUEST = { ip: '1.2.3.4', headers: { 'user-agent': 'jest' } } as Partial<Request> as Request

/** An `AuthService` whose every collaborator is a mock, under the given registration mode. */
function build(registration: 'open' | 'invitation-only'): {
  service: AuthService
  userRepo: { findByEmail: jest.Mock; create: jest.Mock }
  hooks: { beforeRegister: jest.Mock }
} {
  const userRepo = {
    findByEmail: jest.fn().mockResolvedValue(null),
    create: jest.fn().mockRejectedValue(new Error('reached the repository'))
  }
  const hooks = { beforeRegister: jest.fn().mockResolvedValue({ allowed: true }) }
  const service = new AuthService(
    { registration } as Partial<ResolvedOptions> as ResolvedOptions,
    userRepo as never,
    null,
    hooks as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never,
    {} as never
  )
  return { service, userRepo, hooks }
}

describe('AuthService.register under registration: invitation-only', () => {
  // The sign-up route is closed: no hook runs and nothing is looked up or written.
  it('refuses with auth.registration_closed before any hook or repository call', async () => {
    const { service, userRepo, hooks } = build('invitation-only')

    const error: unknown = await service.register(DTO, REQUEST).catch((e: unknown) => e)

    expect(error).toBeInstanceOf(AuthException)
    expect((error as AuthException).getResponse()).toMatchObject({
      error: { code: AUTH_ERROR_CODES.REGISTRATION_CLOSED }
    })
    expect(hooks.beforeRegister).not.toHaveBeenCalled()
    expect(userRepo.findByEmail).not.toHaveBeenCalled()
    expect(userRepo.create).not.toHaveBeenCalled()
  })

  // The open mode is the control: the same call reaches the hook.
  it('lets an open registration reach the hook', async () => {
    const { service, hooks } = build('open')

    await service.register(DTO, REQUEST).catch(() => undefined)

    expect(hooks.beforeRegister).toHaveBeenCalledTimes(1)
  })
})
