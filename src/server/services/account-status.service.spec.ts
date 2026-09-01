/**
 * @fileoverview Tests for AccountStatusService, the account lifecycle gate shared by
 * UserStatusGuard and AuthTokenVerifierService. Covers the Redis-cached dashboard path
 * (status, email verification, key shape, miss handling) and the uncached platform path.
 */

import { HttpStatus } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AccountStatusService } from './account-status.service'

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

const mockPlatformRepo = {
  findById: jest.fn()
}

const mockOptions = {
  userStatusCacheTtlSeconds: 60,
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED', 'PENDING_APPROVAL'],
  // The status-only suites run with verification enforcement OFF, so the service reads a single
  // cache fact. The dedicated suite flips this on.
  emailVerification: { required: false }
}

/**
 * Builds a service instance with option overlays over {@link mockOptions}.
 *
 * `withPlatformRepo: false` omits the optional provider entirely rather than supplying an
 * undefined value, which is the shape a deployment without `controllers.platform` produces.
 */
async function buildService(
  overrides: Record<string, unknown> = {},
  { withPlatformRepo = true }: { withPlatformRepo?: boolean } = {}
): Promise<AccountStatusService> {
  const module = await Test.createTestingModule({
    providers: [
      AccountStatusService,
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_OPTIONS, useValue: { ...mockOptions, ...overrides } },
      ...(withPlatformRepo
        ? [{ provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformRepo }]
        : [])
    ]
  }).compile()
  return module.get(AccountStatusService)
}

const REF = { userId: 'user-1', tenantId: 'tenant-1' } as const

// ---------------------------------------------------------------------------
// Dashboard plane
// ---------------------------------------------------------------------------

describe('AccountStatusService — dashboard', () => {
  let service: AccountStatusService

  beforeEach(async () => {
    jest.clearAllMocks()
    service = await buildService()
  })

  // A cached 'active' status resolves without touching the repository — the whole point of the
  // cache is that the common path costs one `get`.
  it('resolves an active account from cache without a repository read', async () => {
    mockRedis.get.mockResolvedValue('active')
    await expect(service.assertDashboardAccountUsable(REF)).resolves.toBeUndefined()
    expect(mockUserRepo.findById).not.toHaveBeenCalled()
  })

  // A cache miss reads the repository tenant-scoped and writes the result back for the configured
  // TTL. The repository call must carry the tenant: an id is unique only within one.
  it('reads the repository tenant-scoped on a miss and caches the result', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue({ id: 'user-1', status: 'active' })
    mockRedis.set.mockResolvedValue(undefined)

    await expect(service.assertDashboardAccountUsable(REF)).resolves.toBeUndefined()

    expect(mockUserRepo.findById).toHaveBeenCalledWith({ id: 'user-1', tenantId: 'tenant-1' })
    expect(mockRedis.set).toHaveBeenCalledWith('us:tenant-1:user-1', 'active', 60)
    // With verification enforcement OFF the verified flag is neither read nor written. Pins the
    // `if (requireVerified)` branch: were it always-true, this miss would also write `uev:`.
    expect(mockRedis.set).toHaveBeenCalledTimes(1)
  })

  // A tenant or subject containing the `:` delimiter must not shift the key boundary: each half is
  // percent-encoded, so `('x:y','a:b')` keys `us:x%3Ay:a%3Ab` and cannot collide with another pair.
  it('percent-encodes tenant and subject so a `:` in either cannot shift the key boundary', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue({ id: 'a:b', status: 'active' })
    mockRedis.set.mockResolvedValue(undefined)

    await expect(
      service.assertDashboardAccountUsable({ userId: 'a:b', tenantId: 'x:y' })
    ).resolves.toBeUndefined()

    expect(mockRedis.set).toHaveBeenCalledWith('us:x%3Ay:a%3Ab', 'active', 60)
  })

  // A blocked status answers 403 with the code that names it, so the client can say why.
  it('throws ACCOUNT_BANNED with 403 for a BANNED status', async () => {
    mockRedis.get.mockResolvedValue('BANNED')
    const thrown = await service.assertDashboardAccountUsable(REF).catch((e: unknown) => e)
    expect(thrown).toBeInstanceOf(AuthException)
    expect((thrown as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.ACCOUNT_BANNED)
  })

  // Pins the blocked-status → code map: each entry must resolve to its OWN code, not a shared
  // fallback. An emptied map would collapse all of these to `?? ACCOUNT_INACTIVE`.
  it.each([
    ['banned', AUTH_ERROR_CODES.ACCOUNT_BANNED],
    ['suspended', AUTH_ERROR_CODES.ACCOUNT_SUSPENDED],
    ['pending', AUTH_ERROR_CODES.PENDING_APPROVAL],
    ['pending_approval', AUTH_ERROR_CODES.PENDING_APPROVAL]
  ])('maps blocked status "%s" to its specific error code', async (status, expectedCode) => {
    const custom = await buildService({
      blockedStatuses: ['banned', 'suspended', 'pending', 'pending_approval']
    })
    mockRedis.get.mockResolvedValue(status)
    const thrown = await custom.assertDashboardAccountUsable(REF).catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(expectedCode)
  })

  // The comparison is case-insensitive on both sides: the status is application-defined data, so a
  // consumer persisting 'Suspended' against a configured 'SUSPENDED' must still be refused.
  it.each(['INACTIVE', 'SUSPENDED', 'PENDING_APPROVAL'])(
    'refuses the blocked status %s',
    async (status) => {
      mockRedis.get.mockResolvedValue(status)
      await expect(service.assertDashboardAccountUsable(REF)).rejects.toBeInstanceOf(AuthException)
    }
  )

  // A configured blocked status with no entry in the map falls back to ACCOUNT_INACTIVE rather
  // than reaching AuthException with a non-code value.
  it('falls back to ACCOUNT_INACTIVE for a custom blocked status', async () => {
    const custom = await buildService({ blockedStatuses: ['CUSTOM_BLOCKED'] })
    mockRedis.get.mockResolvedValue('custom_blocked')
    const thrown = await custom.assertDashboardAccountUsable(REF).catch((e: unknown) => e)
    expect((thrown as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.ACCOUNT_INACTIVE)
  })

  // An account deleted after its token was issued answers TOKEN_INVALID: the token outlived the
  // account, which is a token problem rather than a status one.
  it('throws TOKEN_INVALID when the repository has no such account', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue(null)
    const thrown = await service
      .assertDashboardAccountUsable({ userId: 'deleted', tenantId: 'tenant-1' })
      .catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })
})

// ---------------------------------------------------------------------------
// Email-verification enforcement
// ---------------------------------------------------------------------------

describe('AccountStatusService — email verification enforcement', () => {
  /** Routes the two cache reads by key so status and verified flag can differ. */
  function cacheReturning(status: string | null, verified: string | null): void {
    mockRedis.get.mockImplementation((key: string) =>
      Promise.resolve(key.startsWith('uev:') ? verified : status)
    )
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  // A verified account (flag '1' in cache) passes without a repository read.
  it('allows a verified account from cache', async () => {
    const service = await buildService({ emailVerification: { required: true } })
    cacheReturning('active', '1')
    await expect(service.assertDashboardAccountUsable(REF)).resolves.toBeUndefined()
    expect(mockUserRepo.findById).not.toHaveBeenCalled()
  })

  // An unverified account is refused with EMAIL_NOT_VERIFIED — the gate that stops a registration
  // session reaching a protected surface before the address is confirmed.
  it('rejects an unverified account with EMAIL_NOT_VERIFIED', async () => {
    const service = await buildService({ emailVerification: { required: true } })
    cacheReturning('active', '0')
    const thrown = await service.assertDashboardAccountUsable(REF).catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
  })

  // A verified-flag miss resolves it from the repository and caches it under `uev:` at the same TTL.
  it('resolves and caches the verified flag on a uev cache miss', async () => {
    const service = await buildService({ emailVerification: { required: true } })
    cacheReturning('active', null)
    mockUserRepo.findById.mockResolvedValue({ id: 'user-1', status: 'active', emailVerified: true })
    mockRedis.set.mockResolvedValue(undefined)
    await expect(service.assertDashboardAccountUsable(REF)).resolves.toBeUndefined()
    expect(mockUserRepo.findById).toHaveBeenCalledWith({ id: 'user-1', tenantId: 'tenant-1' })
    expect(mockRedis.set).toHaveBeenCalledWith('uev:tenant-1:user-1', '1', 60)
  })

  // Both facts miss: ONE repository read refreshes both, and an unverified record caches '0'.
  it('caches 0 and rejects when the repository reports an unverified account', async () => {
    const service = await buildService({ emailVerification: { required: true } })
    cacheReturning(null, null)
    mockUserRepo.findById.mockResolvedValue({
      id: 'user-1',
      status: 'active',
      emailVerified: false
    })
    mockRedis.set.mockResolvedValue(undefined)
    const thrown = await service.assertDashboardAccountUsable(REF).catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
    expect(mockUserRepo.findById).toHaveBeenCalledTimes(1)
    expect(mockRedis.set).toHaveBeenCalledWith('us:tenant-1:user-1', 'active', 60)
    expect(mockRedis.set).toHaveBeenCalledWith('uev:tenant-1:user-1', '0', 60)
  })

  // A blocked status is refused FIRST: a banned, unverified account is told it is banned rather
  // than that it must verify.
  it('refuses a blocked status before the verification check', async () => {
    const service = await buildService({ emailVerification: { required: true } })
    cacheReturning('BANNED', '0')
    const thrown = await service.assertDashboardAccountUsable(REF).catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.ACCOUNT_BANNED)
  })

  // With enforcement off the verified flag is never read at all.
  it('does not consult the verified flag when enforcement is off', async () => {
    const service = await buildService({ emailVerification: { required: false } })
    mockRedis.get.mockResolvedValue('active')
    await expect(service.assertDashboardAccountUsable(REF)).resolves.toBeUndefined()
    expect(mockRedis.get).not.toHaveBeenCalledWith('uev:tenant-1:user-1')
  })
})

// ---------------------------------------------------------------------------
// Platform plane
// ---------------------------------------------------------------------------

describe('AccountStatusService — platform', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  // The platform read is uncached and takes the bare id: a platform administrator is cross-tenant,
  // so there is no tenant to scope a cache key by.
  it('reads the platform repository by id and allows an active administrator', async () => {
    const service = await buildService()
    mockPlatformRepo.findById.mockResolvedValue({ id: 'admin-1', status: 'active' })
    await expect(service.assertPlatformAccountUsable('admin-1')).resolves.toBeUndefined()
    expect(mockPlatformRepo.findById).toHaveBeenCalledWith('admin-1')
    expect(mockRedis.get).not.toHaveBeenCalled()
  })

  // A blocked administrator answers the code that names the status, exactly as on the dashboard
  // plane — the two planes share `assertNotBlocked` and must not drift.
  it('throws the matching code for a blocked administrator', async () => {
    const service = await buildService()
    mockPlatformRepo.findById.mockResolvedValue({ id: 'admin-1', status: 'SUSPENDED' })
    const thrown = await service.assertPlatformAccountUsable('admin-1').catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.ACCOUNT_SUSPENDED)
  })

  // An administrator deleted after the token was issued answers TOKEN_INVALID.
  it('throws TOKEN_INVALID when no such administrator exists', async () => {
    const service = await buildService()
    mockPlatformRepo.findById.mockResolvedValue(null)
    const thrown = await service.assertPlatformAccountUsable('gone').catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
  })

  // The gate must FAIL CLOSED when the optional repository is absent. Skipping the check because
  // the collaborator is missing is how a status gate silently stops gating.
  it('refuses rather than skipping when no platform repository is registered', async () => {
    const service = await buildService({}, { withPlatformRepo: false })
    const thrown = await service.assertPlatformAccountUsable('admin-1').catch((e: unknown) => e)
    expect(errorCodeOf(thrown)).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    expect(mockPlatformRepo.findById).not.toHaveBeenCalled()
  })

  // There is no email-verification arm on this plane: a platform administrator is provisioned
  // rather than self-registered, so enabling tenant verification must not gate them.
  it('ignores emailVerification.required on the platform plane', async () => {
    const service = await buildService({ emailVerification: { required: true } })
    mockPlatformRepo.findById.mockResolvedValue({ id: 'admin-1', status: 'active' })
    await expect(service.assertPlatformAccountUsable('admin-1')).resolves.toBeUndefined()
  })
})
