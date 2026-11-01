/**
 * @fileoverview The account-status cache, driven against the shared wire contract.
 *
 * `conformance.spec.ts` pins the prefixes and the contract's own bytes. These cases drive
 * `AccountStatusService` against the `userStatusCache` section: the key each entry is written
 * under for every pinned vector, the value forms, the TTL source, when the verified entry exists,
 * and the order the entries are deleted in. A cache whose shape drifts from the contract raises
 * nothing at runtime and merely defers a suspension or a verification by one TTL, so these are
 * the only place the drift shows.
 *
 * @layer Conformance
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { DEFAULT_OPTIONS } from './config/default-options'
import { AccountStatusService } from './services/account-status.service'

interface UserStatusCacheContract {
  redisKeyPrefixes: Record<string, string>
  userStatusCache: {
    emailVerifiedValue: { verified: string; unverified: string }
    ttl: { option: string; default: number }
    invalidateOrder: string[]
    vectors: { tenantId: string; userId: string; scope: string }[]
  }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as UserStatusCacheContract

describe('account-status cache', () => {
  const cache = contract.userStatusCache

  /** A service over a recording Redis double, so the keys it names are what is asserted. */
  function build(options: { required: boolean; ttl?: number }) {
    const calls: { op: 'get' | 'set' | 'del'; key: string; value?: string; ttl?: number }[] = []
    const store = new Map<string, string>()
    const redis = {
      get: jest.fn((key: string) => {
        calls.push({ op: 'get', key })
        return Promise.resolve(store.get(key) ?? null)
      }),
      set: jest.fn((key: string, value: string, ttl: number) => {
        calls.push({ op: 'set', key, value, ttl })
        store.set(key, value)
        return Promise.resolve()
      }),
      del: jest.fn((key: string) => {
        calls.push({ op: 'del', key })
        return Promise.resolve(store.delete(key))
      })
    }
    const record = { status: 'Active', emailVerified: true }
    const userRepo = { findById: jest.fn().mockResolvedValue(record) }
    const resolved = {
      userStatusCacheTtlSeconds: options.ttl ?? DEFAULT_OPTIONS.userStatusCacheTtlSeconds,
      emailVerification: { required: options.required },
      blockedStatuses: ['BANNED']
    }
    const service = new AccountStatusService(redis as never, userRepo as never, resolved as never)
    return { service, calls, record, userRepo, store }
  }

  // Verifies the key both entries are written under, for every pinned scope. The ids are
  // percent-encoded one at a time, so a delimiter inside either cannot move the boundary; the
  // vectors include the characters implementations most often disagree about.
  it.each(cache.vectors)(
    'names both entries by the pinned scope for $tenantId / $userId',
    async (v) => {
      const { service, calls } = build({ required: true })

      await service.assertDashboardAccountUsable({ tenantId: v.tenantId, userId: v.userId })

      expect(calls.filter((c) => c.op === 'set').map((c) => c.key)).toEqual([
        `${contract.redisKeyPrefixes.userStatus}:${v.scope}`,
        `${contract.redisKeyPrefixes.userEmailVerified}:${v.scope}`
      ])
    }
  )

  // Verifies the scope string is the contract's own composition of the two encoded halves, so a
  // vector cannot drift from the rule it illustrates.
  it.each(cache.vectors)('derives the pinned scope from the encoding rule for $scope', (v) => {
    expect(`${encodeURIComponent(v.tenantId)}:${encodeURIComponent(v.userId)}`).toBe(v.scope)
  })

  // Verifies the value forms: the status as the repository returned it, and '1' / '0' for the
  // verified flag.
  it.each([
    [true, cache.emailVerifiedValue.verified],
    [false, cache.emailVerifiedValue.unverified]
  ])('writes %s as the verified value %p', async (emailVerified, expected) => {
    const { service, calls, record } = build({ required: true })
    record.emailVerified = emailVerified

    await service
      .assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })
      .catch(() => undefined)

    const sets = calls.filter((c) => c.op === 'set')
    expect(sets[0]?.value).toBe('Active')
    expect(sets[1]?.value).toBe(expected)
  })

  // Verifies the TTL source: the option's default, applied to every entry written on a miss.
  it('applies userStatusCacheTtlSeconds, defaulting to the contract value, to each entry', async () => {
    const { service, calls } = build({ required: true })

    await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })

    expect(DEFAULT_OPTIONS.userStatusCacheTtlSeconds).toBe(cache.ttl.default)
    expect(calls.filter((c) => c.op === 'set').map((c) => c.ttl)).toEqual([
      cache.ttl.default,
      cache.ttl.default
    ])
  })

  // Verifies the option is the TTL source, not the default that happens to equal it: a
  // non-default value must reach both entries.
  it('writes each entry with the configured userStatusCacheTtlSeconds', async () => {
    const { service, calls } = build({ required: true, ttl: 17 })

    await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })

    expect(cache.ttl.option).toBe('userStatusCacheTtlSeconds')
    expect(calls.filter((c) => c.op === 'set').map((c) => c.ttl)).toEqual([17, 17])
  })

  // Verifies the verified entry exists only when verification is required.
  it('reads and writes the verified entry only when email verification is required', async () => {
    const { service, calls } = build({ required: false })

    await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })

    const prefixes = calls.map((c) => c.key.split(':')[0])
    expect(prefixes).not.toContain(contract.redisKeyPrefixes.userEmailVerified)
    expect(new Set(prefixes)).toEqual(new Set([contract.redisKeyPrefixes.userStatus]))
  })

  // Verifies a full hit reads the repository not at all: the second call is served from the two
  // entries the first one wrote.
  it('serves a second call from the cache without a repository read', async () => {
    const { service, userRepo } = build({ required: true })

    await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })
    await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })

    expect(userRepo.findById).toHaveBeenCalledTimes(1)
  })

  // Verifies the fill rule for a PARTIAL miss: with one entry present and the other gone, the next
  // call reads the repository once and writes both entries back, whichever one was missing.
  it.each([
    ['status', contract.redisKeyPrefixes.userStatus],
    ['verified', contract.redisKeyPrefixes.userEmailVerified]
  ])(
    'refills both entries from one repository read when only the %s entry is gone',
    async (_which, prefix) => {
      const { service, calls, userRepo, store } = build({ required: true })
      await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })
      store.delete(`${prefix}:t:u`)
      calls.length = 0

      await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })

      expect(userRepo.findById).toHaveBeenCalledTimes(2)
      expect(calls.filter((c) => c.op === 'set').map((c) => c.key)).toEqual([
        `${contract.redisKeyPrefixes.userStatus}:t:u`,
        `${contract.redisKeyPrefixes.userEmailVerified}:t:u`
      ])
    }
  )

  // Verifies the invalidation order the contract pins: the verified entry first, then the status.
  it('deletes the verified entry before the status entry', async () => {
    const { service, calls } = build({ required: true })

    await service.invalidate({ tenantId: 't', userId: 'u' })

    expect(calls.filter((c) => c.op === 'del').map((c) => c.key.split(':')[0])).toEqual(
      cache.invalidateOrder.map((name) => contract.redisKeyPrefixes[name])
    )
  })
})
