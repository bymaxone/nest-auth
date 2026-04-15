/**
 * @fileoverview Tests for UserStatusGuard, which checks the authenticated user's
 * account status against a Redis cache and the user repository, throwing
 * status-specific AuthExceptions for blocked accounts.
 */

import { HttpStatus } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { UserStatusGuard } from './user-status.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const mockRedis = {
  get: jest.fn(),
  set: jest.fn()
}

const mockUserRepo = {
  findById: jest.fn()
}

const mockOptions = {
  userStatusCacheTtlSeconds: 60,
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED', 'PENDING_APPROVAL']
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeContext(user: { sub: string } | undefined) {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ user })
    })
  }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('UserStatusGuard', () => {
  let guard: UserStatusGuard

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        UserStatusGuard,
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(UserStatusGuard)
  })

  // Verifies that requests without an authenticated user (public routes) pass through without Redis calls.
  it('should return true for public routes (no user)', async () => {
    const ctx = makeContext(undefined)
    await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
    expect(mockRedis.get).not.toHaveBeenCalled()
  })

  // Verifies that a cached 'active' status results in the guard allowing the request.
  it('should return true when user has active status (from cache)', async () => {
    mockRedis.get.mockResolvedValue('active')
    const ctx = makeContext({ sub: 'user-1' })
    await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
  })

  // Verifies that a cache miss triggers a repository lookup and caches the result for the configured TTL.
  it('should fetch from repository on cache miss and cache the result', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue({ id: 'user-1', status: 'active' })
    mockRedis.set.mockResolvedValue(undefined)

    const ctx = makeContext({ sub: 'user-1' })
    await expect(guard.canActivate(ctx as never)).resolves.toBe(true)

    expect(mockUserRepo.findById).toHaveBeenCalledWith('user-1')
    expect(mockRedis.set).toHaveBeenCalledWith('us:user-1', 'active', 60)
  })

  // Verifies that a BANNED status causes a 403 ACCOUNT_BANNED AuthException.
  it('should throw ACCOUNT_BANNED for BANNED status', async () => {
    mockRedis.get.mockResolvedValue('BANNED')
    const ctx = makeContext({ sub: 'user-1' })

    await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    try {
      await guard.canActivate(ctx as never)
    } catch (e) {
      expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
    }
  })

  // Verifies that an INACTIVE status causes an AuthException to be thrown.
  it('should throw ACCOUNT_INACTIVE for INACTIVE status', async () => {
    mockRedis.get.mockResolvedValue('INACTIVE')
    const ctx = makeContext({ sub: 'user-1' })
    await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
  })

  // Verifies that a SUSPENDED status causes an AuthException to be thrown.
  it('should throw ACCOUNT_SUSPENDED for SUSPENDED status', async () => {
    mockRedis.get.mockResolvedValue('SUSPENDED')
    const ctx = makeContext({ sub: 'user-1' })
    await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
  })

  // Verifies that a PENDING_APPROVAL status causes an AuthException to be thrown.
  it('should throw PENDING_APPROVAL for PENDING_APPROVAL status', async () => {
    mockRedis.get.mockResolvedValue('PENDING_APPROVAL')
    const ctx = makeContext({ sub: 'user-1' })
    await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
  })

  // Verifies that a deleted user (null from repo on cache miss) causes TOKEN_INVALID to be thrown.
  it('should throw TOKEN_INVALID when user not found in repository on cache miss', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue(null)

    const ctx = makeContext({ sub: 'deleted-user' })
    await expect(guard.canActivate(ctx as never)).rejects.toThrow(AuthException)
  })

  // Verifies that a custom blocked status not present in STATUS_ERROR_MAP falls back to ACCOUNT_INACTIVE.
  it('should fall back to ACCOUNT_INACTIVE for a custom blocked status not in STATUS_ERROR_MAP', async () => {
    // Create a separate guard instance with a non-standard blocked status.
    const customOptions = {
      userStatusCacheTtlSeconds: 60,
      blockedStatuses: ['CUSTOM_BLOCKED']
    }

    const customModule = await Test.createTestingModule({
      providers: [
        UserStatusGuard,
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_OPTIONS, useValue: customOptions }
      ]
    }).compile()

    const customGuard = customModule.get(UserStatusGuard)

    // The cache returns 'custom_blocked', which is in blockedStatuses but not in STATUS_ERROR_MAP.
    mockRedis.get.mockResolvedValue('custom_blocked')
    const ctx = makeContext({ sub: 'user-1' })

    await expect(customGuard.canActivate(ctx as never)).rejects.toThrow(AuthException)
    try {
      await customGuard.canActivate(ctx as never)
    } catch (e) {
      // Should fall back to ACCOUNT_INACTIVE since 'custom_blocked' is not in STATUS_ERROR_MAP.
      expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
    }
  })
})
