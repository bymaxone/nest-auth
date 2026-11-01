/**
 * @fileoverview Tests for AccountStatusService, the account lifecycle gate shared by
 * UserStatusGuard and AuthTokenVerifierService. Covers the Redis-cached dashboard path
 * (status, email verification, key shape, miss handling) and the uncached platform path.
 */

import { createHmac } from 'node:crypto'

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

/** The library's identifier-HMAC key as the service under test is given it. */
const HMAC_KEY = 'account-status-spec-hmac-key'

/**
 * The keys an account is cached under, derived here with `node:crypto` and the contract's subject
 * grammar rather than by calling the library, so the expectations restate the contract and not the
 * implementation: the HMAC over `dashboard:{utf8ByteLength(tenantId)}:{tenantId}:{userId}`.
 */
function digestFor(tenantId: string, userId: string): string {
  const subject = `dashboard:${Buffer.byteLength(tenantId, 'utf8')}:${tenantId}:${userId}`
  return createHmac('sha256', HMAC_KEY).update(subject, 'utf8').digest('hex')
}
const statusKeyFor = (tenantId: string, userId: string): string =>
  `us:${digestFor(tenantId, userId)}`
const verifiedKeyFor = (tenantId: string, userId: string): string =>
  `uev:${digestFor(tenantId, userId)}`

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn()
}

const mockUserRepo = {
  findById: jest.fn()
}

const mockPlatformRepo = {
  findById: jest.fn()
}

const mockOptions = {
  hmacKey: HMAC_KEY,
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
    expect(mockRedis.set).toHaveBeenCalledWith(statusKeyFor('tenant-1', 'user-1'), 'active', 60)
    // With verification enforcement OFF the verified flag is neither read nor written. Pins the
    // `if (requireVerified)` branch: were it always-true, this miss would also write `uev:`.
    expect(mockRedis.set).toHaveBeenCalledTimes(1)
  })

  // A tenant or subject containing the `:` delimiter must not shift the boundary of what is
  // hashed: the subject carries a byte-length prefix, so `('x:y','a:b')` and `('x','y:a:b')` are
  // different accounts and are cached under different keys.
  it('keys two accounts whose ids differ only by where a `:` falls under different entries', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue({ id: 'a:b', status: 'active' })
    mockRedis.set.mockResolvedValue(undefined)

    await service.assertDashboardAccountUsable({ userId: 'a:b', tenantId: 'x:y' })
    await service.assertDashboardAccountUsable({ userId: 'y:a:b', tenantId: 'x' })

    expect(mockRedis.set).toHaveBeenCalledWith(statusKeyFor('x:y', 'a:b'), 'active', 60)
    expect(mockRedis.set).toHaveBeenCalledWith(statusKeyFor('x', 'y:a:b'), 'active', 60)
    expect(statusKeyFor('x:y', 'a:b')).not.toBe(statusKeyFor('x', 'y:a:b'))
  })

  // The ids are HMACed, not written into the key: the keyspace is shared and readable, and an
  // account identifier in the clear is disclosed to anyone with access to the store.
  it('writes no part of the tenant or user id into the key', async () => {
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue({ id: 'user-1', status: 'active' })
    mockRedis.set.mockResolvedValue(undefined)

    await service.assertDashboardAccountUsable(REF)

    const key = String(mockRedis.set.mock.calls[0]?.[0])
    expect(key).toMatch(/^us:[0-9a-f]{64}$/)
    expect(key).not.toContain('tenant-1')
    expect(key).not.toContain('user-1')
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
// Invalidation, and the single statement of the key format
// ---------------------------------------------------------------------------

describe('AccountStatusService — invalidate', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  // Drops BOTH cached facts. A caller changing a status should not have to know which of two
  // entries their change invalidated; the cost of the extra delete is one repository read.
  it('deletes both the status and the verified key for the account', async () => {
    const service = await buildService()
    mockRedis.del.mockResolvedValue(undefined)

    await expect(service.invalidate(REF)).resolves.toBeUndefined()

    expect(mockRedis.del).toHaveBeenCalledWith(statusKeyFor('tenant-1', 'user-1'))
    expect(mockRedis.del).toHaveBeenCalledWith(verifiedKeyFor('tenant-1', 'user-1'))
    expect(mockRedis.del).toHaveBeenCalledTimes(2)
  })

  // The tenant scopes the delete, exactly as it scopes the write. Dropping it would clear a
  // colliding id in another tenant instead — a repository id is unique only within one.
  it('scopes the delete by tenant', async () => {
    const service = await buildService()
    mockRedis.del.mockResolvedValue(undefined)

    await service.invalidate({ userId: 'user-1', tenantId: 'acme' })

    expect(mockRedis.del).toHaveBeenCalledWith(statusKeyFor('acme', 'user-1'))
    expect(mockRedis.del).not.toHaveBeenCalledWith(statusKeyFor('tenant-1', 'user-1'))
  })

  // The verified flag is dropped FIRST. If the second delete fails, the entry left behind should
  // be the one whose staleness costs a repository read rather than the one that locks a
  // just-verified account out of every protected route until it expires.
  it('drops the verified flag before the status', async () => {
    const service = await buildService()
    mockRedis.del.mockResolvedValue(undefined)

    await service.invalidate(REF)

    expect(mockRedis.del.mock.calls.map((c: unknown[]) => c[0])).toEqual([
      verifiedKeyFor('tenant-1', 'user-1'),
      statusKeyFor('tenant-1', 'user-1')
    ])
  })

  // A `:` in either id must name the same entry on the way out as on the way in, or the delete
  // names a different entry than the write created and silently misses it.
  it('deletes the entries the write created for ids that contain a `:`', async () => {
    const service = await buildService()
    mockRedis.del.mockResolvedValue(undefined)

    await service.invalidate({ userId: 'a:b', tenantId: 'x:y' })

    expect(mockRedis.del).toHaveBeenCalledWith(statusKeyFor('x:y', 'a:b'))
    expect(mockRedis.del).toHaveBeenCalledWith(verifiedKeyFor('x:y', 'a:b'))
  })
})

describe('AccountStatusService — invalidate rejects an unusable account reference', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  // An empty or blank id builds a key no read ever wrote (a subject no read ever wrote), so the delete removes
  // nothing and RESOLVES — the caller believes the suspension applied while the cached `active`
  // survives its TTL. Refused instead, because that is the silent failure this method exists to
  // eliminate, and an unset resolver value is how it arrives.
  it.each([
    ['an empty tenant', { userId: 'user-1', tenantId: '' }],
    ['a blank tenant', { userId: 'user-1', tenantId: '   ' }],
    ['an empty userId', { userId: '', tenantId: 'tenant-1' }],
    ['a blank userId', { userId: ' ', tenantId: 'tenant-1' }]
  ])('refuses %s rather than deleting nothing', async (_label, ref) => {
    const service = await buildService()

    const thrown = await service.invalidate(ref).catch((e: unknown) => e)

    expect(thrown).toBeInstanceOf(TypeError)
    expect((thrown as TypeError).message).toBe(
      'invalidate: userId and tenantId must both be non-empty'
    )
    expect(mockRedis.del).not.toHaveBeenCalled()
  })
})

describe('AccountStatusService — the reader and the invalidator name the same keys', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  // THE CROSS-CHECK, and what it does NOT prove. One derivation serves both paths, so a format
  // change moves them together and cannot make them disagree — this test cannot fail for that.
  // What it catches is a SECOND statement of the format: inline a key in either path and the two
  // stop agreeing, and the build goes red here rather than a suspension silently taking a full TTL
  // to land. Single-sourcing is what keeps that unreachable; this test is what notices if it stops
  // being true.
  it.each([
    ['plain', { userId: 'user-1', tenantId: 'tenant-1' }],
    ['delimiters in both halves', { userId: 'a:b', tenantId: 'x:y' }],
    ['unicode', { userId: 'ü/1', tenantId: 'té nant' }]
  ])('writes and deletes the same keys for %s', async (_label, ref) => {
    const service = await buildService({ emailVerification: { required: true } })

    // The WRITE path: force a full miss so both keys are set from the repository.
    mockRedis.get.mockResolvedValue(null)
    mockUserRepo.findById.mockResolvedValue({
      id: ref.userId,
      status: 'active',
      emailVerified: true
    })
    mockRedis.set.mockResolvedValue(undefined)
    await service.assertDashboardAccountUsable(ref)
    const written = mockRedis.set.mock.calls.map((c: unknown[]) => c[0]).sort()

    // The DELETE path, over the same account.
    mockRedis.del.mockResolvedValue(undefined)
    await service.invalidate(ref)
    const deleted = mockRedis.del.mock.calls.map((c: unknown[]) => c[0]).sort()

    expect(written).toHaveLength(2)
    expect(deleted).toEqual(written)
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
    expect(mockRedis.set).toHaveBeenCalledWith(verifiedKeyFor('tenant-1', 'user-1'), '1', 60)
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
    expect(mockRedis.set).toHaveBeenCalledWith(statusKeyFor('tenant-1', 'user-1'), 'active', 60)
    expect(mockRedis.set).toHaveBeenCalledWith(verifiedKeyFor('tenant-1', 'user-1'), '0', 60)
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
    expect(mockRedis.get).not.toHaveBeenCalledWith(verifiedKeyFor('tenant-1', 'user-1'))
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
