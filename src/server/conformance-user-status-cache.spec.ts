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

import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { DEFAULT_OPTIONS } from './config/default-options'
import { AccountStatusService } from './services/account-status.service'

interface UserStatusCacheContract {
  hmacKeyDerivation: { vectors: { derivedKeyHex: string }[] }
  redisKeyPrefixes: Record<string, string>
  userSubjectPreimages: { dashboard: string }
  userSubjectDerivedKeys: Record<string, string>
  userStatusCache: {
    emailVerifiedValue: { verified: string; unverified: string }
    ttl: { option: string; default: number }
    invalidateOrder: string[]
    vectors: { tenantId: string; userId: string; userSubject: string; digestHex: string }[]
  }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as UserStatusCacheContract

/** The identifier-HMAC key the contract pins, and the one the service under test is given. */
const HMAC_KEY = contract.hmacKeyDerivation.vectors[0]?.derivedKeyHex ?? ''

/** Renders the contract's dashboard subject template, the way the contract spells it. */
function renderSubject(tenantId: string, userId: string): string {
  return contract.userSubjectPreimages.dashboard
    .replace('{utf8ByteLength(tenantId)}', String(Buffer.byteLength(tenantId, 'utf8')))
    .replace('{tenantId}', tenantId)
    .replace('{userId}', userId)
}

/** The digest an account's entries are keyed by, computed here and not by the library. */
function digestOf(tenantId: string, userId: string): string {
  return createHmac('sha256', HMAC_KEY)
    .update(renderSubject(tenantId, userId), 'utf8')
    .digest('hex')
}

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
      hmacKey: HMAC_KEY,
      userStatusCacheTtlSeconds: options.ttl ?? DEFAULT_OPTIONS.userStatusCacheTtlSeconds,
      emailVerification: { required: options.required },
      blockedStatuses: ['BANNED']
    }
    const service = new AccountStatusService(redis as never, userRepo as never, resolved as never)
    return { service, calls, record, userRepo, store }
  }

  // Verifies the key both entries are written under, for every pinned vector: the prefix, then the
  // HMAC digest of the account's subject. The vectors include a delimiter inside either id and a
  // multi-byte tenant, so a subject that stopped carrying its byte-length prefix names another key.
  it.each(cache.vectors)(
    'names both entries by the pinned digest for $tenantId / $userId',
    async (v) => {
      const { service, calls } = build({ required: true })

      await service.assertDashboardAccountUsable({ tenantId: v.tenantId, userId: v.userId })

      expect(calls.filter((c) => c.op === 'set').map((c) => c.key)).toEqual([
        `${contract.redisKeyPrefixes.userStatus}:${v.digestHex}`,
        `${contract.redisKeyPrefixes.userEmailVerified}:${v.digestHex}`
      ])
    }
  )

  // Verifies each vector is the contract's own derivation, computed outside the library: the
  // subject rendered from the contract's grammar, and the digest of that subject under the pinned
  // key. A vector that drifted from the rule it illustrates fails here, whichever of the two moved.
  it.each(cache.vectors)('derives the pinned subject and digest for $tenantId / $userId', (v) => {
    expect(renderSubject(v.tenantId, v.userId)).toBe(v.userSubject)
    expect(digestOf(v.tenantId, v.userId)).toBe(v.digestHex)
  })

  // Verifies the vectors name distinct entries, including the two whose ids differ only by where a
  // delimiter falls: the property the subject's byte-length prefix exists for.
  it('keeps every pinned account on its own entry', () => {
    const digests = cache.vectors.map((v) => v.digestHex)

    expect(new Set(digests).size).toBe(digests.length)
  })

  // Verifies the contract lists both entries among the account-derived keys, spelled as the
  // derivation the vectors exercise.
  it.each([
    ['userStatus', contract.redisKeyPrefixes.userStatus],
    ['userEmailVerified', contract.redisKeyPrefixes.userEmailVerified]
  ])('lists %s among the subject-derived keys', (name, prefix) => {
    expect(contract.userSubjectDerivedKeys[name]).toBe(
      `${prefix}:{hmac_sha256(hmacKey, userSubject)}`
    )
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
      store.delete(`${prefix}:${digestOf('t', 'u')}`)
      calls.length = 0

      await service.assertDashboardAccountUsable({ tenantId: 't', userId: 'u' })

      expect(userRepo.findById).toHaveBeenCalledTimes(2)
      expect(calls.filter((c) => c.op === 'set').map((c) => c.key)).toEqual([
        `${contract.redisKeyPrefixes.userStatus}:${digestOf('t', 'u')}`,
        `${contract.redisKeyPrefixes.userEmailVerified}:${digestOf('t', 'u')}`
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
