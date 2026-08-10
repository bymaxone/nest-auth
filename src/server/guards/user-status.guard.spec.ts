/**
 * @fileoverview Tests for UserStatusGuard, which checks the authenticated user's
 * account status against a Redis cache and the user repository, throwing
 * status-specific AuthExceptions for blocked accounts.
 */

import { HttpStatus } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_USER_REPOSITORY } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { UserStatusGuard } from './user-status.guard'

/** Extracts the canonical error code from a thrown AuthException response body. */
function errorCodeOf(err: unknown): string {
  const body = (err as AuthException).getResponse() as { error: { code: string } }
  return body.error.code
}

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
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED', 'PENDING_APPROVAL'],
  // The status-only suites below run with verification enforcement OFF, so the guard reads a
  // single cache fact and the existing expectations are unchanged. The dedicated suite at the
  // bottom flips this on.
  emailVerification: { required: false }
}

/** Builds a guard instance with option overlays over {@link mockOptions}. */
async function buildGuard(overrides: Record<string, unknown>): Promise<UserStatusGuard> {
  const module = await Test.createTestingModule({
    providers: [
      UserStatusGuard,
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_OPTIONS, useValue: { ...mockOptions, ...overrides } }
    ]
  }).compile()
  return module.get(UserStatusGuard)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeContext(user: { sub: string; tenantId?: string } | undefined) {
  // Every authenticated principal carries a tenant; default one so the cache keys and the
  // repository lookup are tenant-scoped exactly as they are in production.
  const withTenant = user === undefined ? undefined : { tenantId: 'tenant-1', ...user }
  return {
    switchToHttp: () => ({
      getRequest: () => ({ user: withTenant })
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

    expect(mockUserRepo.findById).toHaveBeenCalledWith('user-1', 'tenant-1')
    expect(mockRedis.set).toHaveBeenCalledWith('us:tenant-1:user-1', 'active', 60)
    // With verification enforcement OFF, only the status is cached — the verified flag is neither
    // read nor written. Pins the `if (requireVerified)` guard: were it always-true, this miss would
    // also write the `uev:` key, so exactly one set call proves the branch is honoured.
    expect(mockRedis.set).toHaveBeenCalledTimes(1)
  })

  // A tenant or subject that contains the `:` delimiter must not shift the key boundary: each half
  // is percent-encoded, so `('x:y','a:b')` keys `us:x%3Ay:a%3Ab` and cannot collide with another
  // pair. Dropping the encoding would let two distinct pairs share a status entry across tenants.
  it('percent-encodes tenant and subject so a `:` in either cannot shift the key boundary', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue({ id: 'a:b', status: 'active' })
    mockRedis.set.mockResolvedValue(undefined)

    const ctx = makeContext({ sub: 'a:b', tenantId: 'x:y' })
    await expect(guard.canActivate(ctx as never)).resolves.toBe(true)

    expect(mockRedis.set).toHaveBeenCalledWith('us:x%3Ay:a%3Ab', 'active', 60)
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
      expect(errorCodeOf(e)).toBe(AUTH_ERROR_CODES.ACCOUNT_BANNED)
    }
  })

  // Pins the STATUS_ERROR_MAP contents: each blocked status must resolve to its
  // OWN error code, not a single shared fallback. If the map were emptied, every
  // status would collapse to the `?? ACCOUNT_INACTIVE` default — so banned,
  // suspended, and pending statuses returning their distinct codes proves the
  // map entries are populated and looked up correctly.
  it.each([
    ['banned', AUTH_ERROR_CODES.ACCOUNT_BANNED],
    ['suspended', AUTH_ERROR_CODES.ACCOUNT_SUSPENDED],
    ['pending', AUTH_ERROR_CODES.PENDING_APPROVAL],
    ['pending_approval', AUTH_ERROR_CODES.PENDING_APPROVAL]
  ])('should map blocked status "%s" to its specific error code', async (status, expectedCode) => {
    const customOptions = {
      userStatusCacheTtlSeconds: 60,
      blockedStatuses: ['banned', 'suspended', 'pending', 'pending_approval'],
      emailVerification: { required: false }
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

    mockRedis.get.mockResolvedValue(status)
    const ctx = makeContext({ sub: 'user-1' })

    await expect(customGuard.canActivate(ctx as never)).rejects.toThrow(AuthException)

    const thrown = await customGuard.canActivate(ctx as never).catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(expectedCode)
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
      blockedStatuses: ['CUSTOM_BLOCKED'],
      emailVerification: { required: false }
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

  // -------------------------------------------------------------------------
  // Email-verification enforcement (emailVerification.required = true)
  // -------------------------------------------------------------------------
  describe('email verification enforcement', () => {
    /** Routes the two cache reads by key so status and verified flag can differ. */
    function cacheReturning(status: string | null, verified: string | null): void {
      mockRedis.get.mockImplementation((key: string) =>
        Promise.resolve(key.startsWith('uev:') ? verified : status)
      )
    }

    // A verified account (flag '1' in cache) passes without a repository read.
    it('allows a verified account from cache', async () => {
      const guard = await buildGuard({ emailVerification: { required: true } })
      cacheReturning('active', '1')
      const ctx = makeContext({ sub: 'user-1' })
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(mockUserRepo.findById).not.toHaveBeenCalled()
    })

    // An unverified account (flag '0' in cache) is refused with EMAIL_NOT_VERIFIED — this is the
    // gate that stops a registration session reaching a protected route before verification.
    it('rejects an unverified account with EMAIL_NOT_VERIFIED', async () => {
      const guard = await buildGuard({ emailVerification: { required: true } })
      cacheReturning('active', '0')
      const ctx = makeContext({ sub: 'user-1' })
      const thrown = await guard.canActivate(ctx as never).catch((e: unknown) => e)
      expect(thrown).toBeInstanceOf(AuthException)
      expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    })

    // A verified-flag cache miss (status cached) resolves the flag from the repository and caches
    // it under `uev:{tenantId}:{id}` with the configured TTL.
    it('resolves and caches the verified flag on a uev cache miss', async () => {
      const guard = await buildGuard({ emailVerification: { required: true } })
      cacheReturning('active', null)
      mockUserRepo.findById.mockResolvedValue({
        id: 'user-1',
        status: 'active',
        emailVerified: true
      })
      mockRedis.set.mockResolvedValue(undefined)
      const ctx = makeContext({ sub: 'user-1' })
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(mockUserRepo.findById).toHaveBeenCalledWith('user-1', 'tenant-1')
      expect(mockRedis.set).toHaveBeenCalledWith('uev:tenant-1:user-1', '1', 60)
    })

    // Both facts miss: one repository read refreshes status and verified, and an unverified record
    // caches '0' and is refused.
    it('caches 0 and rejects when the repository reports an unverified account', async () => {
      const guard = await buildGuard({ emailVerification: { required: true } })
      cacheReturning(null, null)
      mockUserRepo.findById.mockResolvedValue({
        id: 'user-1',
        status: 'active',
        emailVerified: false
      })
      mockRedis.set.mockResolvedValue(undefined)
      const ctx = makeContext({ sub: 'user-1' })
      const thrown = await guard.canActivate(ctx as never).catch((e: unknown) => e)
      expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
      expect(mockRedis.set).toHaveBeenCalledWith('us:tenant-1:user-1', 'active', 60)
      expect(mockRedis.set).toHaveBeenCalledWith('uev:tenant-1:user-1', '0', 60)
    })

    // A blocked status is refused first: a banned, unverified account is told it is banned, not
    // that it must verify — the verification check never runs.
    it('refuses a blocked status before the verification check', async () => {
      const guard = await buildGuard({ emailVerification: { required: true } })
      cacheReturning('BANNED', '0')
      const ctx = makeContext({ sub: 'user-1' })
      const thrown = await guard.canActivate(ctx as never).catch((e: unknown) => e)
      expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.ACCOUNT_BANNED)
    })

    // With enforcement off, an unverified account passes and the verified flag is never read.
    it('does not consult the verified flag when enforcement is off', async () => {
      const guard = await buildGuard({ emailVerification: { required: false } })
      mockRedis.get.mockResolvedValue('active')
      const ctx = makeContext({ sub: 'user-1' })
      await expect(guard.canActivate(ctx as never)).resolves.toBe(true)
      expect(mockRedis.get).not.toHaveBeenCalledWith('uev:tenant-1:user-1')
    })
  })
})
