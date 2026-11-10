/**
 * @fileoverview AuthService — a host hook that throws synchronously after a flow has completed.
 *
 * `afterRegister`, `afterLogin` and `afterEmailVerified` run after the account, the session or the
 * flag has been written. A hook declared `void` may throw before it returns a promise, and a throw
 * that escaped would answer a finished flow as a failure, which a caller might retry. Each flow
 * must still answer, and the failure must be logged by name. Kept apart from
 * `auth.service.spec.ts` because that file is over the size limit.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import type { Request } from 'express'

import { AuthService } from './auth.service'
import type { ResolvedOptions } from '../config/resolved-options'

const USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  passwordHash: 'scrypt:salt:hash',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const RESULT = { user: { id: 'user-1' }, accessToken: 'a', rawRefreshToken: 'r' }
const REQUEST = { ip: '1.2.3.4', headers: { 'user-agent': 'jest' } } as Partial<Request> as Request

/** Every collaborator is a mock that answers the way a successful flow needs. */
function build(hooks: Record<string, jest.Mock>, existing = true): AuthService {
  const userRepo = {
    findByEmail: jest.fn().mockResolvedValue(existing ? USER : null),
    findById: jest.fn().mockResolvedValue(USER),
    create: jest.fn().mockResolvedValue(USER),
    updateLastLogin: jest.fn().mockResolvedValue(undefined),
    updateEmailVerified: jest.fn().mockResolvedValue(undefined)
  }
  const options = Object.assign({} as ResolvedOptions, {
    registration: 'open',
    emailVerification: { required: false, otpTtlSeconds: 600 },
    blockedStatuses: ['BANNED'],
    hmacKey: 'key',
    previousHmacKeys: [],
    sessions: { enabled: false }
  })
  const passwords = {
    hash: jest.fn().mockResolvedValue('hash'),
    compare: jest.fn().mockResolvedValue(true),
    compareDummy: jest.fn().mockResolvedValue(false),
    assertAcceptable: jest.fn().mockResolvedValue(undefined),
    needsRehash: jest.fn().mockReturnValue(false)
  }
  const bruteForce = {
    isLockedOut: jest.fn().mockResolvedValue(false),
    recordFailure: jest.fn(),
    resetFailures: jest.fn().mockResolvedValue(undefined),
    getRemainingLockoutSeconds: jest.fn().mockResolvedValue(0)
  }
  return new AuthService(
    options,
    userRepo as never,
    null,
    hooks as never,
    passwords as never,
    { issueTokens: jest.fn().mockResolvedValue(RESULT) } as never,
    bruteForce as never,
    { get: jest.fn(), set: jest.fn(), del: jest.fn() } as never,
    { verify: jest.fn().mockResolvedValue(undefined) } as never,
    { createSession: jest.fn() } as never,
    { invalidate: jest.fn().mockResolvedValue(undefined) } as never
  )
}

/** A hook that allows the flow where it must, and throws synchronously where it is the one under test. */
function hooksThrowing(name: string): Record<string, jest.Mock> {
  return {
    beforeRegister: jest.fn().mockResolvedValue({ allowed: true }),
    beforeLogin: jest.fn().mockResolvedValue(undefined),
    [name]: jest.fn(() => {
      throw new Error('hook broke')
    })
  }
}

describe('AuthService with a hook that throws synchronously', () => {
  let error: jest.SpyInstance

  beforeEach(() => {
    error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('still answers register, and logs afterRegister', async () => {
    const service = build(hooksThrowing('afterRegister'), false)
    const dto = { email: 'new@example.com', password: 'SecureP@ss1', name: 'New', tenantId: 't1' }

    await expect(service.register(dto, REQUEST)).resolves.toBeDefined()

    expect(error).toHaveBeenCalledWith(expect.stringContaining('afterRegister hook threw'))
  })

  it('still answers login, and logs afterLogin', async () => {
    const service = build(hooksThrowing('afterLogin'))
    const dto = { email: 'user@example.com', password: 'correct', tenantId: 'tenant-1' }

    await expect(service.login(dto, REQUEST)).resolves.toBeDefined()

    expect(error).toHaveBeenCalledWith(expect.stringContaining('afterLogin hook threw'))
  })

  it('still answers issueTokensForUserId, and logs afterLogin', async () => {
    const service = build(hooksThrowing('afterLogin'))

    await expect(
      service.issueTokensForUserId('user-1', 'tenant-1', '1.2.3.4', 'jest')
    ).resolves.toBeDefined()

    expect(error).toHaveBeenCalledWith(expect.stringContaining('afterLogin hook threw'))
  })

  it('still answers verifyEmail, and logs afterEmailVerified', async () => {
    const service = build(hooksThrowing('afterEmailVerified'))

    await expect(
      service.verifyEmail('tenant-1', 'user@example.com', '123456', REQUEST)
    ).resolves.toBeUndefined()

    expect(error).toHaveBeenCalledWith(expect.stringContaining('afterEmailVerified hook threw'))
  })
})
