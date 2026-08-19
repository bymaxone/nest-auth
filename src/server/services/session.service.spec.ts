/**
 * @fileoverview Unit tests for SessionService.
 *
 * Covers session creation, FIFO eviction, listing, revocation, bulk revocation,
 * and rotation. All Redis interactions and hook invocations are mocked — no real
 * Redis or external I/O is exercised.
 *
 * Coverage target: ≥95% branches, functions, lines, statements (security-critical).
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from './session.service'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Produces a StoredSessionDetail JSON string for a given createdAt. */
function makeDetailJson(
  createdAt: number,
  overrides: Partial<{
    device: string
    ip: string
    lastActivityAt: number
  }> = {}
): string {
  return JSON.stringify({
    device: overrides.device ?? 'Chrome on macOS',
    ip: overrides.ip ?? '127.0.0.1',
    createdAt,
    lastActivityAt: overrides.lastActivityAt ?? createdAt
  })
}

/** Extracts the error code from a thrown AuthException. */
function getErrorCode(err: unknown): string {
  if (!(err instanceof AuthException)) throw new Error('Not an AuthException')
  const body = err.getResponse() as { error: { code: string } }
  return body.error.code
}

/** Flushes the microtask queue by awaiting N Promise.resolve() ticks. */
async function flushMicrotasks(ticks = 4): Promise<void> {
  for (let i = 0; i < ticks; i++) await Promise.resolve()
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const mockRedis = {
  get: jest.fn<Promise<string | null>, [string]>(),
  set: jest.fn<Promise<void>, [string, string, number]>(),
  del: jest.fn<Promise<void>, [string]>(),
  srem: jest.fn<Promise<number>, [string, string]>(),
  smembers: jest.fn<Promise<string[]>, [string]>(),
  eval: jest.fn<Promise<unknown>, [string, string[], string[]]>(),
  pruneExpiredGraceMembers: jest.fn<Promise<number>, [string, string]>().mockResolvedValue(0),
  pruneDeadMembers: jest.fn<Promise<number>, [string, string[]]>().mockResolvedValue(0),
  bumpUserTokenEpoch: jest.fn()
}

const mockUserRepo = {
  findById: jest.fn<Promise<unknown>, [string]>()
}

const mockHooks = {
  onNewSession: jest.fn<Promise<void>, [unknown, unknown, unknown]>(),
  onSessionEvicted: jest.fn<Promise<void>, [string, string, unknown]>()
}

/** Mirrors the `hmacKey` the mock options carry, so a key can be spelled out. */
const HMAC_KEY = 'test-hmac-key'

const mockOptions = {
  hmacKey: 'test-hmac-key',
  jwt: { secret: 'test-secret', refreshExpiresInDays: 7 },
  sessions: {
    enabled: true,
    defaultMaxSessions: 5,
    evictionStrategy: 'fifo',
    maxSessionsResolver: undefined as ((user: unknown) => Promise<number>) | undefined
  }
}

// Computed TTL used by tests (mirrors production: days * 86_400)
const TTL = 7 * 86_400

// ---------------------------------------------------------------------------
// Module factory helpers
// ---------------------------------------------------------------------------

async function buildModule(hooksValue: unknown = mockHooks): Promise<SessionService> {
  const module = await Test.createTestingModule({
    providers: [
      SessionService,
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
      { provide: BYMAX_AUTH_HOOKS, useValue: hooksValue }
    ]
  }).compile()

  return module.get(SessionService)
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('SessionService', () => {
  let service: SessionService

  beforeEach(async () => {
    jest.clearAllMocks()
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    // reset per-test resolver to undefined so tests that don't set it get the default
    mockOptions.sessions.maxSessionsResolver = undefined
    service = await buildModule()
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // =========================================================================
  // createSession
  // =========================================================================

  describe('createSession', () => {
    const userId = 'user-1'
    const rawToken = 'raw-refresh-token-abc'
    const ip = '192.168.1.1'
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/123.0'

    beforeEach(() => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.smembers.mockResolvedValue([])
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.srem.mockResolvedValue(1)
      mockUserRepo.findById.mockResolvedValue({
        id: userId,
        email: 'user@example.com',
        name: 'Test User',
        passwordHash: 'secret-hash',
        mfaSecret: null,
        mfaRecoveryCodes: null,
        role: 'user',
        status: 'active',
        emailVerified: true,
        tenantId: 'tenant-1',
        createdAt: new Date(),
        updatedAt: new Date()
      })
    })

    // Verifies that stores sd:{hash} in Redis with the correct TTL.
    it('stores sd:{hash} in Redis with the correct TTL', async () => {
      const hash = sha256(rawToken)

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.set).toHaveBeenCalledWith(`sd:${hash}`, expect.any(String), TTL)
    })

    // Verifies that returns the sha256 hash of the raw refresh token.
    it('returns the sha256 hash of the raw refresh token', async () => {
      const expected = sha256(rawToken)

      const result = await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(result).toBe(expected)
    })

    // Verifies that truncates IP to 45 characters before storage.
    it('truncates IP to 45 characters before storage', async () => {
      const longIp = 'a'.repeat(60)

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: longIp,
        userAgent: userAgent
      })

      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        ip: string
      }
      expect(stored.ip).toHaveLength(45)
    })

    // Verifies that stores the parsed device string (non-empty) in the detail record.
    it('stores the parsed device string (non-empty) in the detail record', async () => {
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toBeTruthy()
    })

    // Verifies that stores createdAt and lastActivityAt as numbers in the detail record.
    it('stores createdAt and lastActivityAt as numbers in the detail record', async () => {
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        createdAt: unknown
        lastActivityAt: unknown
      }
      expect(typeof stored.createdAt).toBe('number')
      expect(typeof stored.lastActivityAt).toBe('number')
    })

    // Verifies that calls enforceSessionLimit after storing the detail (smembers called).
    it('calls enforceSessionLimit after storing the detail (smembers called)', async () => {
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.smembers).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`
      )
    })

    // Verifies that does not evict any session when count is at or below the limit.
    it('does not evict any session when count is at or below the limit', async () => {
      // Production note: by the time createSession runs, TokenManagerService.issueTokens
      // has already added rt:{newHash} to sess:{userId}, so SMEMBERS would return
      // (existing + new) members. enforceSessionLimit filters out newHash from
      // eviction candidates, leaving N existing members for comparison against limit.
      // This test mocks SMEMBERS with 4 pre-existing members (newHash absent from mock),
      // which exercises the same eviction path: 4 candidates ≤ limit(5) → no eviction.
      const existingHashes = Array.from({ length: 4 }, (_, i) => sha256(`token-${i}`))
      const existingMembers = existingHashes.map((h) => `rt:${h}`)
      mockRedis.smembers.mockResolvedValue(existingMembers)
      // Provide detail records for each existing session
      mockRedis.get.mockResolvedValue(makeDetailJson(Date.now() - 1000))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Verifies that evicts the oldest session (FIFO) when the limit is exceeded.
    it('evicts the oldest session (FIFO) when the limit is exceeded', async () => {
      const now = Date.now()
      // 6 existing rt: members → limit is 5 → 1 must be evicted (oldest)
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`existing-token-${i}`))
      const members = hashes.map((h) => `rt:${h}`)
      mockRedis.smembers.mockResolvedValue(members)

      // Return different createdAt per hash so we can identify the oldest
      const oldestHash = hashes[0]
      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        const idx = hashes.indexOf(hashPart)
        // idx 0 is oldest (createdAt = 0)
        return Promise.resolve(makeDetailJson(idx === 0 ? 0 : now - (6 - idx) * 1000))
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.del).toHaveBeenCalledWith(`rt:${oldestHash}`)
      expect(mockRedis.srem).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
        `rt:${oldestHash}`
      )
      expect(mockRedis.del).toHaveBeenCalledWith(`sd:${oldestHash}`)
    })

    // Verifies that deletes rt:, SREMs from sess:, and deletes sd: during eviction in that order.
    it('deletes rt:, SREMs from sess:, and deletes sd: during eviction in that order', async () => {
      const now = Date.now()
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`tok-order-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      const oldestHash = hashes[0]
      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        const idx = hashes.indexOf(hashPart)
        return Promise.resolve(makeDetailJson(idx === 0 ? 0 : now - idx * 500))
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      const delCalls = mockRedis.del.mock.calls.map((c) => c[0])
      const sremCalls = mockRedis.srem.mock.calls.map((c) => c[1])

      const rtDelIdx = delCalls.indexOf(`rt:${oldestHash}`)
      const sdDelIdx = delCalls.indexOf(`sd:${oldestHash}`)
      expect(rtDelIdx).toBeGreaterThanOrEqual(0)
      expect(sdDelIdx).toBeGreaterThanOrEqual(0)
      expect(sremCalls).toContain(`rt:${oldestHash}`)
    })

    // Verifies that never evicts the newly created session hash itself.
    it('never evicts the newly created session hash itself', async () => {
      const newHash = sha256(rawToken)
      const now = Date.now()
      // Put the new hash as one of the existing members with the oldest createdAt
      const otherHashes = Array.from({ length: 5 }, (_, i) => sha256(`other-${i}`))
      const allMembers = [`rt:${newHash}`, ...otherHashes.map((h) => `rt:${h}`)]
      mockRedis.smembers.mockResolvedValue(allMembers)

      // Make newHash appear oldest (createdAt = 0)
      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        if (hashPart === newHash) return Promise.resolve(makeDetailJson(0))
        return Promise.resolve(makeDetailJson(now - 1000))
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      const delCalls = mockRedis.del.mock.calls.map((c) => c[0])
      expect(delCalls).not.toContain(`rt:${newHash}`)
      expect(delCalls).not.toContain(`sd:${newHash}`)
    })

    // Verifies that logs error but does not throw when Redis fails during eviction.
    it('logs error but does not throw when Redis fails during eviction', async () => {
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`fail-tok-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockResolvedValue(makeDetailJson(0))
      mockRedis.del.mockRejectedValue(new Error('Redis connection error'))

      await expect(
        service.createSession({
          userId: userId,
          tenantId: 'tenant-1',
          rawRefreshToken: rawToken,
          ip: ip,
          userAgent: userAgent
        })
      ).resolves.not.toThrow()
      expect(Logger.prototype.error).toHaveBeenCalled()
    })

    // Verifies that fires the onNewSession hook after the session is stored.
    it('fires the onNewSession hook after the session is stored', async () => {
      mockHooks.onNewSession.mockResolvedValue(undefined)

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      // Hook is fire-and-forget — flush microtasks
      await flushMicrotasks()

      expect(mockHooks.onNewSession).toHaveBeenCalledTimes(1)
    })

    // Verifies that passes a SafeAuthUser (no credentials) to the onNewSession hook.
    it('passes a SafeAuthUser (no credentials) to the onNewSession hook', async () => {
      mockHooks.onNewSession.mockResolvedValue(undefined)

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      await flushMicrotasks()

      const calledUser = mockHooks.onNewSession.mock.calls[0]?.[0] as Record<string, unknown>
      expect(calledUser).not.toHaveProperty('passwordHash')
      expect(calledUser).not.toHaveProperty('mfaSecret')
      expect(calledUser).not.toHaveProperty('mfaRecoveryCodes')
    })

    // Verifies that passing null as the hooks value completely skips the onNewSession fire-and-forget block without throwing.
    it('does not fire onNewSession hook when hooks is null', async () => {
      const svcNoHooks = await buildModule(null)
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.smembers.mockResolvedValue([])

      await svcNoHooks.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      expect(mockHooks.onNewSession).not.toHaveBeenCalled()
    })

    // Verifies that providing a hooks object without onNewSession skips the hook block without throwing.
    it('does not fire onNewSession when hooks object has no onNewSession property', async () => {
      const svcPartialHooks = await buildModule({ onSessionEvicted: jest.fn() })
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.smembers.mockResolvedValue([])
      mockUserRepo.findById.mockResolvedValue({
        id: userId,
        email: 'user@example.com',
        name: 'Test User',
        passwordHash: 'secret-hash',
        mfaSecret: null,
        mfaRecoveryCodes: null,
        role: 'user',
        status: 'active',
        emailVerified: true,
        tenantId: 'tenant-1',
        createdAt: new Date(),
        updatedAt: new Date()
      })

      await svcPartialHooks.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      expect(mockHooks.onNewSession).not.toHaveBeenCalled()
    })

    // Verifies that logs error when onNewSession hook throws, without propagating.
    it('logs error when onNewSession hook throws, without propagating', async () => {
      mockHooks.onNewSession.mockRejectedValue(new Error('hook error'))

      await expect(
        service.createSession({
          userId: userId,
          tenantId: 'tenant-1',
          rawRefreshToken: rawToken,
          ip: ip,
          userAgent: userAgent
        })
      ).resolves.not.toThrow()

      await flushMicrotasks()

      expect(Logger.prototype.error).toHaveBeenCalled()
    })

    // Verifies that does not fire onNewSession when findById returns null.
    it('does not fire onNewSession when findById returns null', async () => {
      mockUserRepo.findById.mockResolvedValue(null)
      mockHooks.onNewSession.mockResolvedValue(undefined)

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      expect(mockHooks.onNewSession).not.toHaveBeenCalled()
    })

    // Verifies that logs error when findById throws inside onNewSession flow.
    it('logs error when findById throws inside onNewSession flow', async () => {
      mockUserRepo.findById.mockRejectedValue(new Error('db error'))

      await expect(
        service.createSession({
          userId: userId,
          tenantId: 'tenant-1',
          rawRefreshToken: rawToken,
          ip: ip,
          userAgent: userAgent
        })
      ).resolves.not.toThrow()

      await flushMicrotasks()

      expect(Logger.prototype.error).toHaveBeenCalled()
    })

    // Verifies that calls maxSessionsResolver when configured.
    it('calls maxSessionsResolver when configured', async () => {
      const resolver = jest.fn<Promise<number>, [unknown]>().mockResolvedValue(3)
      mockOptions.sessions.maxSessionsResolver = resolver
      // Rebuild service with updated options
      service = await buildModule()
      const now = Date.now()
      const hashes = Array.from({ length: 4 }, (_, i) => sha256(`resolver-tok-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockResolvedValue(makeDetailJson(now - 5000))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(resolver).toHaveBeenCalledTimes(1)
    })

    // The resolver is the host's code and its answer went straight into the eviction
    // arithmetic. `NaN` — `Number(user.plan.maxSessions)` against a missing column, say —
    // quietly disabled the cap: `length <= NaN` is false so eviction was entered,
    // `length - NaN` is `NaN`, `slice(0, NaN)` is empty, nothing was evicted, and every path
    // still reported success. Only a THROWN resolver was ever caught. A cap that silently
    // stops applying is worse than one that is merely wrong, so anything that is not a
    // positive whole number falls back to the configured default and says so.
    it.each([
      ['NaN', Number.NaN],
      ['zero', 0],
      ['a negative', -3],
      ['a fraction', 2.5],
      ['Infinity', Number.POSITIVE_INFINITY],
      ['a non-number', 'five' as unknown as number]
    ])('falls back to defaultMaxSessions when the resolver returns %s', async (_l, resolved) => {
      const errorSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
      mockOptions.sessions.maxSessionsResolver = jest
        .fn<Promise<number>, [unknown]>()
        .mockResolvedValue(resolved)
      service = await buildModule()
      // Seven members against the default of five: if the default took over, two are evicted;
      // if the resolver's answer were used, `NaN` would evict nothing at all.
      const hashes = Array.from({ length: 7 }, (_, i) => sha256(`bad-resolver-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockResolvedValue(makeDetailJson(Date.now() - 5000))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      // Two over the default of five, so the default's eviction actually runs. Under the
      // unvalidated resolver `NaN` evicted nothing and reported success.
      expect(mockRedis.del).toHaveBeenCalledWith(`rt:${hashes[0]}`)
      // The whole message, not just its first fragment: an operator who sees this needs to
      // know what the resolver returned, that the default took over, and why a cap that stops
      // applying is the worse failure — the three things the three fragments carry.
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('maxSessionsResolver'))
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('falling back to defaultMaxSessions')
      )
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('stops applying is worse than one that is merely wrong')
      )
      errorSpy.mockRestore()
    })

    // Scenario: a resolver returning a valid cap, including the smallest one it can. Expected:
    // that cap is what applies. Why: the two tests above only prove the fallback fires for bad
    // values — a validator that rejected EVERYTHING would satisfy them both, and the cap would
    // silently become `defaultMaxSessions` for every deployment that configured a resolver.
    // One is the boundary specifically: it is a legitimate policy ("one device at a time") and
    // sits exactly on the edge the check tests against.
    it.each([
      ['the smallest valid cap', 1],
      ['a cap below the default', 3]
    ])('applies %s that the resolver returns', async (_label, cap) => {
      mockOptions.sessions.maxSessionsResolver = jest
        .fn<Promise<number>, [unknown]>()
        .mockResolvedValue(cap)
      service = await buildModule()
      // Seven live sessions against the resolver's cap. Under the default of five, a different
      // number would be evicted — so the count pins WHICH limit applied.
      const hashes = Array.from({ length: 7 }, (_, i) => sha256(`good-resolver-${cap}-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockImplementation(async (key: string) => {
        const index = hashes.findIndex((h) => key === `sd:${h}`)
        return makeDetailJson(Date.now() - (7 - index) * 1000)
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      // The seven live members are evicted down to the cap, so the count of deletions names
      // WHICH limit applied: the resolver's, or the default of five.
      const evicted = mockRedis.del.mock.calls
        .map((args) => args[0])
        .filter((key) => key.startsWith('rt:'))
      expect(evicted).toHaveLength(7 - cap)
    })

    // Verifies that falls back to defaultMaxSessions when maxSessionsResolver throws.
    it('falls back to defaultMaxSessions when maxSessionsResolver throws', async () => {
      const resolver = jest
        .fn<Promise<number>, [unknown]>()
        .mockRejectedValue(new Error('resolver fail'))
      mockOptions.sessions.maxSessionsResolver = resolver
      service = await buildModule()
      // 4 members, resolver throws → falls back to defaultMaxSessions(5) → no eviction
      const hashes = Array.from({ length: 4 }, (_, i) => sha256(`fallback-tok-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockResolvedValue(makeDetailJson(Date.now()))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(Logger.prototype.error).toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Verifies that falls back to defaultMaxSessions when maxSessionsResolver user not found.
    it('falls back to defaultMaxSessions when maxSessionsResolver user not found', async () => {
      const resolver = jest.fn<Promise<number>, [unknown]>().mockResolvedValue(3)
      mockOptions.sessions.maxSessionsResolver = resolver
      // The userRepo is shared — findById is called from resolver path too
      mockUserRepo.findById.mockResolvedValue(null)
      service = await buildModule()
      // 4 members, but resolver user not found → fallback to defaultMaxSessions(5) → no eviction
      const hashes = Array.from({ length: 4 }, (_, i) => sha256(`nf-tok-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      // resolver not called because findById returned null first
      expect(resolver).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Verifies that fires onSessionEvicted hook after successful eviction.
    it('fires onSessionEvicted hook after successful eviction', async () => {
      const now = Date.now()
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`evict-hook-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        const idx = hashes.indexOf(hashPart)
        return Promise.resolve(makeDetailJson(idx === 0 ? 0 : now - idx * 500))
      })
      mockHooks.onSessionEvicted.mockResolvedValue(undefined)

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      expect(mockHooks.onSessionEvicted).toHaveBeenCalledWith(
        userId,
        hashes[0],
        expect.objectContaining({ ip, userAgent })
      )
    })

    // Verifies that does not fire onSessionEvicted when hooks is null.
    it('does not fire onSessionEvicted when hooks is null', async () => {
      const svcNoHooks = await buildModule(null)
      mockRedis.set.mockResolvedValue(undefined)
      const now = Date.now()
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`no-hook-evict-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockResolvedValue(makeDetailJson(now - 1000))
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.srem.mockResolvedValue(1)

      await svcNoHooks.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      expect(mockHooks.onSessionEvicted).not.toHaveBeenCalled()
    })

    // Verifies that treats sessions with missing detail records as oldest (createdAt = 0) for eviction ordering.
    it('treats sessions with missing detail records as oldest (createdAt = 0) for eviction ordering', async () => {
      const now = Date.now()
      // 6 sessions; first has null detail → createdAt = 0 → should be evicted
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`missing-detail-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))

      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        if (hashPart === hashes[0]) return Promise.resolve(null)
        const idx = hashes.indexOf(hashPart)
        return Promise.resolve(makeDetailJson(now - idx * 100))
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      // hashes[0] has no detail → createdAt 0 → evicted first
      expect(mockRedis.del).toHaveBeenCalledWith(`rt:${hashes[0]}`)
    })

    // Verifies that treats sessions with unparseable detail JSON as oldest (createdAt = 0).
    it('treats sessions with unparseable detail JSON as oldest (createdAt = 0)', async () => {
      const now = Date.now()
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`bad-json-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))

      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        if (hashPart === hashes[0]) return Promise.resolve('{not valid json}}}')
        const idx = hashes.indexOf(hashPart)
        return Promise.resolve(makeDetailJson(now - idx * 100))
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.del).toHaveBeenCalledWith(`rt:${hashes[0]}`)
    })

    // Verifies that a rejection from the onSessionEvicted hook is caught and logged without propagating to the caller.
    it('logs error and does not throw when onSessionEvicted hook throws', async () => {
      // Arrange: set up 6 sessions so eviction fires
      const now = Date.now()
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`evict-err-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockImplementation((key: string) => {
        const idx = hashes.indexOf(key.replace(/^sd:/, ''))
        return Promise.resolve(makeDetailJson(idx === 0 ? 0 : now - idx * 100))
      })
      mockHooks.onSessionEvicted.mockRejectedValue(new Error('hook exploded'))

      // Act
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      // Assert — error was logged, not thrown
      expect(Logger.prototype.error).toHaveBeenCalledWith('onSessionEvicted hook threw: <error>')
    })

    // Verifies that a user-agent containing Edg/ is stored with an Edge browser label.
    it('detects Edge browser from Edg/ token', async () => {
      const edgeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/123.0'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: edgeUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Edge')
    })

    // Verifies that a user-agent containing OPR/ is stored with an Opera browser label.
    it('detects Opera browser from OPR/ token', async () => {
      const operaUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 OPR/123.0'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: operaUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Opera')
    })

    // Verifies that a Safari user-agent (Version + Safari tokens, no Chrome/Edg/OPR) is stored with a Safari browser label.
    it('detects Safari browser (Safari + Version tokens, no Chrome/Edg/OPR)', async () => {
      const safariUA =
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: safariUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Safari')
    })

    // Verifies that a user-agent containing the Android token is stored with an Android OS label.
    it('detects Android OS', async () => {
      const androidUA =
        'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/112.0 Mobile Safari/537.36'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: androidUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Android')
    })

    // Verifies that a user-agent containing the iPhone token is stored with an iOS OS label.
    it('detects iOS from iPhone token', async () => {
      const iosUA =
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 Version/16.4 Mobile Safari/604.1'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: iosUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('iOS')
    })

    // Verifies that a user-agent containing the Windows NT token is stored with a Windows OS label.
    it('detects Windows OS', async () => {
      const windowsUA =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/112.0 Safari/537.36'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: windowsUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Windows')
    })

    // Verifies that a user-agent containing the Linux token (non-Android desktop) is stored with a Linux OS label.
    it('detects Linux OS', async () => {
      const linuxUA =
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/112.0 Safari/537.36'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: linuxUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Linux')
    })

    // Scenario: a clean Chrome UA (no Edg/OPR/Firefox, Safari token but no Version token).
    // Expected: device contains 'Chrome'. Why: kills the Chrome-branch mutants on line 138
    // (`else if (false)`), 138:35 (empty block), and 139 (`browser = ''`) — the Chrome browser
    // label is never asserted by the existing OS-focused tests.
    it('detects Chrome browser from Chrome/ token', async () => {
      const chromeUA =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: chromeUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Chrome')
    })

    // Scenario: a Firefox UA (no Edg/OPR/Chrome).
    // Expected: device contains 'Firefox'. Why: kills the Firefox-branch mutants on line 140
    // (`else if (false)`), 140:36 (empty block), and 141 (`browser = ''`).
    it('detects Firefox browser from Firefox/ token', async () => {
      const firefoxUA = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: firefoxUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Firefox')
    })

    // Scenario: a desktop macOS UA must yield the 'macOS' OS label.
    // Expected: device contains 'macOS'. Why: kills the macOS-branch mutants on line 155
    // (`else if (false)`), 155:45 (empty block), and 156 (`os = ''`) — the macOS label is never
    // asserted by the existing tests (which assert browser labels for Mac UAs).
    it('detects macOS from a Macintosh UA', async () => {
      const macUA =
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: macUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('macOS')
    })

    // Scenario: an unrecognised UA matches no browser and no OS pattern.
    // Expected: device === 'Unknown Browser on Unknown OS'. Why: kills the StringLiteral defaults on
    // line 132 (`'Unknown Browser'` → '') and 147 (`'Unknown OS'` → ''), the Safari `if (true)` mutant
    // on line 142 and the Linux `if (true)` mutant on line 157 — both would mislabel an unknown UA.
    it('labels an unrecognised user-agent as Unknown Browser on Unknown OS', async () => {
      const unknownUA = 'curl/7.88.1'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: unknownUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toBe('Unknown Browser on Unknown OS')
    })

    // Scenario: a UA with a Safari/ token but NO Version/ token (and no Chrome/Edg/OPR/Firefox).
    // Expected: device contains 'Unknown Browser', NOT 'Safari'. Why: kills the LogicalOperator mutant
    // on line 142 (`/Safari\//.test(ua) && /Version\//.test(ua)` → `||`) which would label this as
    // Safari despite the missing Version token.
    it('does not label a Safari-token-only UA (no Version) as Safari', async () => {
      const safariNoVersionUA = 'Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15'
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: safariNoVersionUA
      })
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Unknown Browser')
    })

    // Scenario: the onNewSession hook receives a short (8-char) sessionHash, not the full hash.
    // Expected: minimalSessionInfo.sessionHash has length 8. Why: kills the MethodExpression mutant
    // on line 265 (`hash.slice(0, 8)` → `hash`) which would leak the full 64-char hash to the hook.
    it('passes an 8-character truncated sessionHash to the onNewSession hook', async () => {
      mockHooks.onNewSession.mockResolvedValue(undefined)

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      const sessionInfo = mockHooks.onNewSession.mock.calls[0]?.[1] as { sessionHash: string }
      expect(sessionInfo.sessionHash).toHaveLength(8)
      expect(sessionInfo.sessionHash).toBe(sha256(rawToken).slice(0, 8))
    })

    // Scenario: enforceSessionLimit reads the per-user SET via the exact `sess:{userId}` key.
    // Expected: smembers called with `sess:user-1`. Why: kills the StringLiteral mutant on line 591
    // (`smembers(\`sess:${userId}\`)` → `smembers('')`).
    it('reads the session SET using the sess:{userId} key during enforcement', async () => {
      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.smembers).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`
      )
    })

    // Scenario: only `rt:` members count toward the limit — `rp:` grace pointers must be excluded.
    // Setup: exactly `limit` (5) rt: members plus extra rp: members.
    // Expected: no eviction (del not called). Why: kills the MethodExpression mutant on line 594
    // (`members.filter(...)` → `members`) and the StringLiteral on line 594:58 (`startsWith('rt:')`
    // → `startsWith('')`) — both would count the rp: pointers and trigger a spurious eviction.
    it('excludes rp: grace pointers from the concurrent-session count', async () => {
      const rtHashes = Array.from({ length: 5 }, (_, i) => sha256(`rt-count-${i}`))
      const rpHashes = Array.from({ length: 3 }, (_, i) => sha256(`rp-count-${i}`))
      mockRedis.smembers.mockResolvedValue([
        ...rtHashes.map((h) => `rt:${h}`),
        ...rpHashes.map((h) => `rp:${h}`)
      ])
      mockRedis.get.mockResolvedValue(makeDetailJson(Date.now()))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Scenario: the active session count is exactly at the limit (5 rt: members).
    // Expected: early return — no sd: lookups (redis.get) and no eviction. Why: kills the
    // EqualityOperator mutant on line 598 (`rtMembers.length <= limit` → `< limit`) which, at the
    // boundary, would not return early and would proceed to fetch sd: records before evicting zero.
    it('returns early without fetching sd: records when count equals the limit', async () => {
      const rtHashes = Array.from({ length: 5 }, (_, i) => sha256(`at-limit-${i}`))
      mockRedis.smembers.mockResolvedValue(rtHashes.map((h) => `rt:${h}`))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(mockRedis.get).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Scenario: 6 rt: members where the oldest is in the MIDDLE of the member array (createdAt=0).
    // Expected: only the true oldest is evicted; a newer session is NOT evicted; sd: is read with the
    // exact `sd:{memberHash}` key. Why: kills the sort-removal (line 629), the comparator `-`→`+`
    // (629:35), `evictCount = length - limit` → `+` (631), the `.slice(0, evictCount)` removal (632),
    // the createdAt-parse `false`/`true &&` mutants (612) and `=== 'number'` → `!==` (615), and the
    // `redis.get(\`sd:${memberHash}\`)` → `get('')` mutant (608).
    it('evicts only the true oldest session even when it is not first in member order', async () => {
      // createdAt by index (ms); index 2 is the oldest at 0.
      const createdAtByIndex = [5_000, 3_000, 0, 8_000, 6_000, 9_000]
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`mid-oldest-${i}`))
      const oldestHash = hashes[2]
      const newestHash = hashes[5]
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        const idx = hashes.indexOf(hashPart)
        return Promise.resolve(makeDetailJson(createdAtByIndex[idx]!))
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      // sd: detail must be read with the proper key shape.
      expect(mockRedis.get).toHaveBeenCalledWith(`sd:${hashes[0]}`)
      // Exactly the oldest is evicted; the newest is preserved.
      const delKeys = mockRedis.del.mock.calls.map((c) => c[0])
      expect(delKeys).toContain(`rt:${oldestHash}`)
      expect(delKeys).not.toContain(`rt:${newestHash}`)
      // length - limit = 1 → exactly one rt: deletion (kills evictCount `+` and slice removal).
      const rtDeletes = delKeys.filter((k) => typeof k === 'string' && k.startsWith('rt:'))
      expect(rtDeletes).toHaveLength(1)
    })

    // Scenario: a member whose sd: record has a NON-number createdAt (string) is treated as oldest
    // (createdAt = 0) and evicted first. Expected: that member is evicted. Why: kills the
    // `typeof (...)['createdAt'] === 'number'` → `true` mutant on line 615 — under that mutant the
    // string createdAt would be read as-is instead of defaulting to 0, changing eviction ordering.
    it('treats a non-number createdAt as oldest (createdAt = 0) during eviction', async () => {
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`nonnum-created-${i}`))
      const badHash = hashes[3]
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockImplementation((key: string) => {
        const hashPart = key.replace(/^sd:/, '')
        if (hashPart === badHash) {
          // Valid object but createdAt is a string (huge value if read literally).
          return Promise.resolve(
            JSON.stringify({
              device: 'Chrome',
              ip: '1.2.3.4',
              createdAt: '99999999999999',
              lastActivityAt: 1000
            })
          )
        }
        // All other members are clearly newer.
        return Promise.resolve(makeDetailJson(1_000_000 + hashes.indexOf(hashPart)))
      })

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      const delKeys = mockRedis.del.mock.calls.map((c) => c[0])
      expect(delKeys).toContain(`rt:${badHash}`)
    })

    // Scenario: a logged eviction-failure message must name the failing session and user.
    // Expected: logger.error called with the exact enforceSessionLimit failure message. Why: kills the
    // StringLiteral mutant on line 652 (message → '').
    it('logs the eviction failure with the session and user in the message', async () => {
      const hashes = Array.from({ length: 6 }, (_, i) => sha256(`evict-msg-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockImplementation((key: string) => {
        const idx = hashes.indexOf(key.replace(/^sd:/, ''))
        return Promise.resolve(makeDetailJson(idx === 0 ? 0 : Date.now()))
      })
      mockRedis.del.mockRejectedValue(new Error('Redis down'))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.stringContaining(
          `enforceSessionLimit: failed to evict session ${hashes[0]} for user ${userId}: `
        )
      )
    })

    // Scenario: when maxSessionsResolver throws, the failure is logged with the exact fallback message.
    // Expected: logger.error called with the resolver-fallback message. Why: kills the StringLiteral
    // mutant on line 692 (message → '').
    it('logs the exact fallback message when maxSessionsResolver throws', async () => {
      const resolver = jest
        .fn<Promise<number>, [unknown]>()
        .mockRejectedValue(new Error('resolver boom'))
      mockOptions.sessions.maxSessionsResolver = resolver
      service = await buildModule()
      const hashes = Array.from({ length: 4 }, (_, i) => sha256(`resolver-msg-${i}`))
      mockRedis.smembers.mockResolvedValue(hashes.map((h) => `rt:${h}`))
      mockRedis.get.mockResolvedValue(makeDetailJson(Date.now()))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })

      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.stringContaining(`maxSessionsResolver threw — falling back to defaultMaxSessions: `)
      )
    })

    // Scenario: the onNewSession hook rejection is logged with the exact "hook threw" message.
    // Expected: logger.error called with 'onNewSession hook threw'. Why: kills the StringLiteral mutant
    // on line 284 (message → '').
    it('logs the exact message when the onNewSession hook rejects', async () => {
      mockHooks.onNewSession.mockRejectedValue(new Error('hook boom'))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.stringContaining(`onNewSession hook threw: `)
      )
    })

    // Scenario: a findById rejection inside the onNewSession flow is logged with the exact message.
    // Expected: logger.error called with 'onNewSession hook — findById failed'. Why: kills the
    // StringLiteral mutant on line 289 (message → '').
    it('logs the exact message when findById rejects inside the onNewSession flow', async () => {
      mockUserRepo.findById.mockRejectedValue(new Error('db boom'))

      await service.createSession({
        userId: userId,
        tenantId: 'tenant-1',
        rawRefreshToken: rawToken,
        ip: ip,
        userAgent: userAgent
      })
      await flushMicrotasks()

      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.stringContaining(`onNewSession hook — findById failed: `)
      )
    })
  })

  // =========================================================================
  // listSessions
  // =========================================================================

  describe('listSessions', () => {
    const userId = 'user-list'

    // Verifies that returns an empty array when there are no rt: members.
    it('returns an empty array when there are no rt: members', async () => {
      mockRedis.smembers.mockResolvedValue([])

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toEqual([])
    })

    // Verifies that filters out rp: grace pointer members.
    it('filters out rp: grace pointer members', async () => {
      const hash = sha256('grace-token')
      mockRedis.smembers.mockResolvedValue([`rp:${hash}`])

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toEqual([])
      expect(mockRedis.get).not.toHaveBeenCalled()
    })

    // Verifies that fetches sd: detail records for each rt: member.
    it('fetches sd: detail records for each rt: member', async () => {
      const hash = sha256('real-token')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(mockRedis.get).toHaveBeenCalledWith(`sd:${hash}`)
    })

    // Verifies that returns a SessionInfo with all expected fields.
    it('returns a SessionInfo with all expected fields', async () => {
      const hash = sha256('session-token')
      const now = 1_700_000_000_000
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(
        makeDetailJson(now, {
          device: 'Chrome on macOS',
          ip: '10.0.0.1',
          lastActivityAt: now + 100
        })
      )

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(1)
      expect(result[0]).toMatchObject({
        id: hash.slice(0, 8),
        sessionHash: hash,
        device: 'Chrome on macOS',
        ip: '10.0.0.1',
        createdAt: now,
        lastActivityAt: now + 100,
        isCurrent: false
      })
    })

    // Verifies that sessionHash field is the full 64-char sha256 hash.
    it('sessionHash field is the full 64-char sha256 hash', async () => {
      const hash = sha256('full-hash-check')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result[0]!.sessionHash).toHaveLength(64)
      expect(result[0]!.sessionHash).toMatch(/^[a-f0-9]{64}$/)
    })

    // Verifies that sets isCurrent: true for the matching session hash.
    it('sets isCurrent: true for the matching session hash', async () => {
      const hash = sha256('current-token')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: hash
      })

      expect(result[0]!.isCurrent).toBe(true)
    })

    // Verifies that sets isCurrent: false when currentSessionHash is undefined.
    it('sets isCurrent: false when currentSessionHash is undefined', async () => {
      const hash = sha256('not-current')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: undefined
      })

      expect(result[0]!.isCurrent).toBe(false)
    })

    // Verifies that sets isCurrent: false when currentSessionHash is an empty string.
    it('sets isCurrent: false when currentSessionHash is an empty string', async () => {
      const hash = sha256('empty-string-check')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: ''
      })

      expect(result[0]!.isCurrent).toBe(false)
    })

    // Verifies that sets isCurrent: false for sessions that do not match currentSessionHash.
    it('sets isCurrent: false for sessions that do not match currentSessionHash', async () => {
      const hash1 = sha256('token-a')
      const hash2 = sha256('token-b')
      mockRedis.smembers.mockResolvedValue([`rt:${hash1}`, `rt:${hash2}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: hash1
      })

      const other = result.find((s) => s.sessionHash === hash2)
      expect(other?.isCurrent).toBe(false)
    })

    // Verifies that excludes stale members (redis.get returns null) from the result.
    it('excludes stale members (redis.get returns null) from the result', async () => {
      const staleHash = sha256('stale-null-token')
      const goodHash = sha256('good-token')
      mockRedis.smembers.mockResolvedValue([`rt:${staleHash}`, `rt:${goodHash}`])
      mockRedis.get.mockImplementation((key: string) => {
        if (key.includes(staleHash)) return Promise.resolve(null)
        return Promise.resolve(makeDetailJson(1000))
      })
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result.map((s) => s.sessionHash)).not.toContain(staleHash)
    })

    // Scenario: the detail record is gone, so the member looks stale. Expected: it is offered to
    // the guarded prune, never SREM'd outright. Why: a missing `sd:` is a fact about the detail
    // record, not about the session — the `rt:` key may well be alive, and dropping the member
    // while it is would hide a working session from `invalidateUserSessions`. Only
    // `pruneDeadMembers` may decide, because only it checks the key.
    it('offers a member with no detail record to the guarded prune, and never SREMs it', async () => {
      const staleHash = sha256('srem-trigger-token')
      mockRedis.smembers.mockResolvedValue([`rt:${staleHash}`])
      mockRedis.get.mockResolvedValue(null)

      await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      await flushMicrotasks()

      expect(mockRedis.pruneDeadMembers).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
        [`rt:${staleHash}`]
      )
      // The bypass this replaced: an unconditional SREM here un-indexed a session whose
      // credential was still live, and the user's own session listing was what triggered it.
      expect(mockRedis.srem).not.toHaveBeenCalled()
    })

    // A listing that found nothing stale must not ask for a prune at all — the common case on
    // every healthy account.
    it('asks for no prune when every member has its detail record', async () => {
      mockRedis.smembers.mockResolvedValue([`rt:${sha256('healthy-token')}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      await flushMicrotasks()

      expect(mockRedis.pruneDeadMembers).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
        []
      )
    })

    // Verifies that excludes stale member when JSON is valid but all required fields are absent.
    it('excludes stale member when JSON is valid but all required fields are absent', async () => {
      const badHash = sha256('bad-json-session')
      mockRedis.smembers.mockResolvedValue([`rt:${badHash}`])
      mockRedis.get.mockResolvedValue(JSON.stringify({ foo: 'bar' }))
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(0)
    })

    // Verifies that excludes stale members when JSON is completely malformed.
    it('excludes stale members when JSON is completely malformed', async () => {
      const badHash = sha256('malformed-json')
      mockRedis.smembers.mockResolvedValue([`rt:${badHash}`])
      mockRedis.get.mockResolvedValue('{{{invalid')
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(0)
    })

    // Verifies that excludes stale members when redis.get throws.
    it('excludes stale members when redis.get throws', async () => {
      const throwHash = sha256('throw-token')
      const goodHash = sha256('good-token-2')
      mockRedis.smembers.mockResolvedValue([`rt:${throwHash}`, `rt:${goodHash}`])
      mockRedis.get.mockImplementation((key: string) => {
        if (key.includes(throwHash)) return Promise.reject(new Error('Redis error'))
        return Promise.resolve(makeDetailJson(1000))
      })
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result.map((s) => s.sessionHash)).not.toContain(throwHash)
    })

    // The sharpest case for the guard: a transient Redis fault on the detail read says nothing
    // at all about the session, yet it lands the member in the same candidate list. Before the
    // guard, one failed GET during an outage un-indexed a live session permanently.
    it('offers a member whose detail read threw to the guarded prune, and says the read failed', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      const throwHash = sha256('throw-srem-token')
      mockRedis.smembers.mockResolvedValue([`rt:${throwHash}`])
      mockRedis.get.mockRejectedValue(new Error('Redis connection lost'))

      await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      await flushMicrotasks()

      expect(mockRedis.pruneDeadMembers).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
        [`rt:${throwHash}`]
      )
      expect(mockRedis.srem).not.toHaveBeenCalled()
      // A failed read and a genuinely stale member are pruned alike — both leave the index —
      // so without this line a Redis outage reads as a tidy-up, and the sessions it silently
      // dropped never come back.
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('session detail read failed'))
      // Truncated: the full hash is the session's identifier in Redis, and a log line is the
      // wrong place to put one. Eight characters is enough to correlate, not enough to use.
      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain(throwHash.slice(0, 8))
      expect(warned).not.toContain(throwHash)
      warnSpy.mockRestore()
    })

    // A prune that fails is a tidy-up that did not happen, not a listing that should fail — but
    // it must be visible, because the index keeps growing until it succeeds.
    it('logs when the guarded prune itself fails, and still returns the listing', async () => {
      const staleHash = sha256('srem-fail-token')
      mockRedis.smembers.mockResolvedValue([`rt:${staleHash}`])
      mockRedis.get.mockResolvedValue(null)
      mockRedis.pruneDeadMembers.mockRejectedValueOnce(new Error('prune failed'))

      await expect(service.listSessions({ userId: userId, tenantId: 'tenant-1' })).resolves.toEqual(
        []
      )

      await flushMicrotasks()

      // Counted, not named: an operator seeing a run of these needs the scale, and a log line is
      // the wrong place for a session identifier.
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        expect.stringContaining(`listSessions: failed to prune 1 dead member(s): `)
      )
    })

    // Verifies that sorts results newest-first (descending createdAt).
    it('sorts results newest-first (descending createdAt)', async () => {
      const hash1 = sha256('oldest-session')
      const hash2 = sha256('newest-session')
      const hash3 = sha256('middle-session')
      mockRedis.smembers.mockResolvedValue([`rt:${hash1}`, `rt:${hash2}`, `rt:${hash3}`])
      mockRedis.get.mockImplementation((key: string) => {
        if (key.includes(hash1)) return Promise.resolve(makeDetailJson(100))
        if (key.includes(hash2)) return Promise.resolve(makeDetailJson(300))
        return Promise.resolve(makeDetailJson(200))
      })

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result[0]!.sessionHash).toBe(hash2)
      expect(result[1]!.sessionHash).toBe(hash3)
      expect(result[2]!.sessionHash).toBe(hash1)
    })

    // Verifies that correctly carries the ip field from the stored detail record.
    it('correctly carries the ip field from the stored detail record', async () => {
      const hash = sha256('ip-carry-token')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000, { ip: '203.0.113.42' }))

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result[0]!.ip).toBe('203.0.113.42')
    })

    // Verifies that excludes stale member when JSON is valid but missing required fields.
    it('excludes stale member when JSON is valid but missing required fields', async () => {
      const hash = sha256('partial-json')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      // Valid JSON but missing 'lastActivityAt'
      mockRedis.get.mockResolvedValue(
        JSON.stringify({ device: 'Chrome', ip: '1.2.3.4', createdAt: 1000 })
      )
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(0)
    })

    // Verifies that handles a mix of rt: and rp: members correctly.
    it('handles a mix of rt: and rp: members correctly', async () => {
      const rtHash = sha256('mixed-rt-token')
      const rpHash = sha256('mixed-rp-token')
      mockRedis.smembers.mockResolvedValue([`rt:${rtHash}`, `rp:${rpHash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(1)
      expect(result[0]!.sessionHash).toBe(rtHash)
    })

    // Scenario: listSessions reads the per-user SET via the exact `sess:{userId}` key.
    // Expected: smembers called with `sess:user-list`. Why: kills the StringLiteral mutant on line
    // 313 (`smembers(\`sess:${userId}\`)` → `smembers('')`).
    it('reads the session SET using the sess:{userId} key', async () => {
      mockRedis.smembers.mockResolvedValue([])

      await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(mockRedis.smembers).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`
      )
    })

    // Scenario: sd: detail with a non-string device is invalid and excluded.
    // Expected: result length 0. Why: kills the `typeof p['device'] !== 'string'` → false mutant
    // (line 344) — without that clause a record with a numeric device would be wrongly included.
    it('excludes a session whose detail has a non-string device', async () => {
      const hash = sha256('bad-device-type')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(
        JSON.stringify({ device: 123, ip: '1.2.3.4', createdAt: 1000, lastActivityAt: 1000 })
      )
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(0)
    })

    // Scenario: sd: detail with a non-string ip is invalid and excluded.
    // Expected: result length 0. Why: kills the `typeof p['ip'] !== 'string'` → false mutant (line 345).
    it('excludes a session whose detail has a non-string ip', async () => {
      const hash = sha256('bad-ip-type')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(
        JSON.stringify({ device: 'Chrome', ip: 42, createdAt: 1000, lastActivityAt: 1000 })
      )
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(0)
    })

    // Scenario: sd: detail with a non-number createdAt is invalid and excluded.
    // Expected: result length 0. Why: kills the `typeof p['createdAt'] !== 'number'` → false mutant
    // (line 346).
    it('excludes a session whose detail has a non-number createdAt', async () => {
      const hash = sha256('bad-createdat-type')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(
        JSON.stringify({ device: 'Chrome', ip: '1.2.3.4', createdAt: 'nope', lastActivityAt: 1000 })
      )
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions({ userId: userId, tenantId: 'tenant-1' })

      expect(result).toHaveLength(0)
    })
  })

  // =========================================================================
  // revokeSession
  // =========================================================================

  describe('revokeSession', () => {
    const userId = 'user-revoke'

    // Verifies that throws VALIDATION for a hash shorter than 64 chars.
    it('throws VALIDATION for a hash shorter than 64 chars', async () => {
      let thrownShort: unknown
      try {
        await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: 'abc123' })
      } catch (e) {
        thrownShort = e
      }
      expect(getErrorCode(thrownShort)).toBe(AUTH_ERROR_CODES.VALIDATION)
    })

    // Verifies that throws VALIDATION for a hash longer than 64 chars.
    it('throws VALIDATION for a hash longer than 64 chars', async () => {
      const longHash = 'a'.repeat(65)
      let thrownLong: unknown
      try {
        await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: longHash })
      } catch (e) {
        thrownLong = e
      }
      expect(getErrorCode(thrownLong)).toBe(AUTH_ERROR_CODES.VALIDATION)
    })

    // Scenario: a valid 64-hex hash with a junk character PREPENDED (length 65, valid tail).
    // Expected: throws SESSION_NOT_FOUND. Why: kills the `^`-anchor removal on line 29
    // (`/^[a-f0-9]{64}$/` → `/[a-f0-9]{64}$/`); without the start anchor the regex matches the valid
    // 64-hex suffix and would wrongly accept this input.
    it('throws VALIDATION for a valid hash with an invalid leading character', async () => {
      const prefixed = `z${sha256('anchor-prefix-token')}`
      let thrown: unknown
      try {
        await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: prefixed })
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.VALIDATION)
      // The format guard must reject BEFORE any Redis round-trip. Without this
      // assertion the `^`-anchor mutant survives: it passes the (loosened) regex,
      // reaches eval, finds no session, and throws the same SESSION_NOT_FOUND.
      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // Scenario: a valid 64-hex hash with a junk character APPENDED (length 65, valid head).
    // Expected: throws SESSION_NOT_FOUND. Why: kills the `$`-anchor removal on line 29
    // (`/^[a-f0-9]{64}$/` → `/^[a-f0-9]{64}/`); without the end anchor the regex matches the valid
    // 64-hex prefix and would wrongly accept this input.
    it('throws VALIDATION for a valid hash with an invalid trailing character', async () => {
      const suffixed = `${sha256('anchor-suffix-token')}z`
      let thrown: unknown
      try {
        await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: suffixed })
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.VALIDATION)
      // The format guard must reject BEFORE any Redis round-trip. Without this
      // assertion the `$`-anchor mutant survives: it passes the (loosened) regex,
      // reaches eval, finds no session, and throws the same SESSION_NOT_FOUND.
      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // Verifies that throws VALIDATION for a hash containing uppercase hex characters.
    it('throws VALIDATION for a hash containing uppercase hex characters', async () => {
      const upperHash = 'A'.repeat(64)
      let thrownUpper: unknown
      try {
        await service.revokeSession({
          userId: userId,
          tenantId: 'tenant-1',
          sessionHash: upperHash
        })
      } catch (e) {
        thrownUpper = e
      }
      expect(getErrorCode(thrownUpper)).toBe(AUTH_ERROR_CODES.VALIDATION)
    })

    // Verifies that throws VALIDATION for a hash containing non-hex characters.
    it('throws VALIDATION for a hash containing non-hex characters', async () => {
      const invalidHash = 'g'.repeat(64)
      let thrownInvalid: unknown
      try {
        await service.revokeSession({
          userId: userId,
          tenantId: 'tenant-1',
          sessionHash: invalidHash
        })
      } catch (e) {
        thrownInvalid = e
      }
      expect(getErrorCode(thrownInvalid)).toBe(AUTH_ERROR_CODES.VALIDATION)
    })

    // Verifies that calls redis.eval with correct KEYS and ARGV.
    it('calls redis.eval with correct KEYS and ARGV', async () => {
      const hash = sha256('revoke-token')
      mockRedis.eval.mockResolvedValue(1)

      await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: hash })

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        [
          `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
          `rt:${hash}`,
          `sd:${hash}`
        ],
        [`rt:${hash}`]
      )
    })

    // Scenario: the revocation Lua must perform the atomic membership check and deletions.
    // Expected: the script passed to eval contains SISMEMBER, SREM, and DEL calls. Why: kills the
    // StringLiteral mutant on line 45 (REVOKE_SESSION_LUA → empty string), which would send an empty
    // script and silently revoke nothing.
    it('evaluates a Lua script containing SISMEMBER, SREM, and DEL', async () => {
      const hash = sha256('revoke-script-token')
      mockRedis.eval.mockResolvedValue(1)

      await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: hash })

      const script = (mockRedis.eval.mock.calls[0] as [string, string[], string[]])[0]
      expect(script).toContain('SISMEMBER')
      expect(script).toContain('SREM')
      expect(script).toContain('DEL')
    })

    // Verifies that throws SESSION_NOT_FOUND when Lua returns 0 (not a member).
    it('throws SESSION_NOT_FOUND when Lua returns 0 (not a member)', async () => {
      const hash = sha256('not-member-token')
      mockRedis.eval.mockResolvedValue(0)

      let thrownLuaZero: unknown
      try {
        await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: hash })
      } catch (e) {
        thrownLuaZero = e
      }
      expect(getErrorCode(thrownLuaZero)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that resolves without throwing when Lua returns 1 (success).
    it('resolves without throwing when Lua returns 1 (success)', async () => {
      const hash = sha256('success-revoke-token')
      mockRedis.eval.mockResolvedValue(1)

      await expect(
        service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: hash })
      ).resolves.toBeUndefined()
    })

    // Verifies that treats non-number Lua return values as 0 (SESSION_NOT_FOUND).
    it('treats non-number Lua return values as 0 (SESSION_NOT_FOUND)', async () => {
      const hash = sha256('non-number-lua')
      mockRedis.eval.mockResolvedValue(null)

      let thrown: unknown
      try {
        await service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: hash })
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that throws SESSION_NOT_FOUND when a valid hash belongs to a different user (BOLA).
    it('throws SESSION_NOT_FOUND when a valid hash belongs to a different user (BOLA)', async () => {
      const victimHash = sha256('victim-refresh-token')
      // Lua SISMEMBER returns 0 because sess:attacker-user does not contain victim's hash
      mockRedis.eval.mockResolvedValue(0)

      let thrownBola: unknown
      try {
        await service.revokeSession({
          userId: 'attacker-user',
          tenantId: 'tenant-1',
          sessionHash: victimHash
        })
      } catch (e) {
        thrownBola = e
      }
      expect(getErrorCode(thrownBola)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that propagates Redis errors thrown by redis.eval.
    it('propagates Redis errors thrown by redis.eval', async () => {
      const hash = sha256('redis-crash-token')
      mockRedis.eval.mockRejectedValue(new Error('ECONNRESET'))

      await expect(
        service.revokeSession({ userId: userId, tenantId: 'tenant-1', sessionHash: hash })
      ).rejects.toThrow('ECONNRESET')
    })
  })

  // =========================================================================
  // revokeAllExceptCurrent
  // =========================================================================

  describe('revokeOtherSession', () => {
    // Deleting the refresh session stops rotation but says nothing about the stateless access
    // token its holder already carries — that token kept working for up to its full lifetime.
    // Someone who opens their session list and revokes a device does so because they think it
    // is compromised, which is a decision about right now.
    it('bumps the token epoch so the revoked device loses its access token too', async () => {
      mockRedis.eval.mockResolvedValue(1)

      await service.revokeOtherSession({
        userId: 'user-1',
        tenantId: 'tenant-1',
        sessionHash: 'a'.repeat(64)
      })

      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith('user-1', 'tenant-1', 'dashboard')
    })

    // After the revoke, never before: a failure in the revoke must leave the epoch untouched
    // and the operation visibly incomplete, rather than signing every device out of its access
    // token for a session that is in fact still alive.
    it('does not bump when the session was not revoked', async () => {
      mockRedis.eval.mockResolvedValue(0)

      await expect(
        service.revokeOtherSession({
          userId: 'user-1',
          tenantId: 'tenant-1',
          sessionHash: 'a'.repeat(64)
        })
      ).rejects.toThrow(AuthException)

      expect(mockRedis.bumpUserTokenEpoch).not.toHaveBeenCalled()
    })
  })

  describe('revokeAllExceptCurrent', () => {
    const userId = 'user-revoke-all'

    // Verifies that throws VALIDATION for invalid currentSessionHash format.
    it('throws VALIDATION for invalid currentSessionHash format', async () => {
      let thrown: unknown
      try {
        await service.revokeAllExceptCurrent({
          userId: userId,
          tenantId: 'tenant-1',
          currentSessionHash: 'not-valid'
        })
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.VALIDATION)
    })

    // Scenario: the index holds the caller's own live session beside a grace pointer.
    // Expected: only the pointer is deleted. Why: this loop exists to kill grace pointers, and
    // the members it walks are the whole index — `rt:` entries included. Without the prefix
    // filter it deletes the CURRENT session's refresh key, so "sign out my other devices"
    // signs out the device that asked, which is the one thing the method promises not to do.
    it('deletes the grace pointers and leaves the current session alone', async () => {
      const currentHash = sha256('rae-keeps-current')
      const otherHash = sha256('rae-other-session')
      mockRedis.smembers.mockResolvedValue([
        `rt:${currentHash}`,
        `rt:${otherHash}`,
        `rp:${otherHash}`
      ])
      mockUserRepo.findById.mockResolvedValue({ id: userId })
      // Set explicitly: another case in this file leaves `srem` rejecting, and a shared mock
      // that carries a rejection across tests turns an unrelated assertion into a failure.
      mockRedis.srem.mockResolvedValue(1)
      mockRedis.del.mockResolvedValue(undefined)

      await service.revokeAllExceptCurrent({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: currentHash
      })

      const deleted = mockRedis.del.mock.calls.map((args) => args[0])
      expect(deleted).toContain(`rp:${otherHash}`)
      expect(deleted).not.toContain(`rt:${currentHash}`)
      // …and the member is dropped from the index too, or a revoke-all still has it to walk.
      expect(mockRedis.srem).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
        `rp:${otherHash}`
      )
      expect(mockRedis.srem).not.toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
        `rt:${currentHash}`
      )
    })

    // Scenario: revokeAllExceptCurrent reads the per-user SET via the exact `sess:{userId}` key.
    // Expected: smembers called with `sess:user-revoke-all`. Why: kills the StringLiteral mutant on
    // line 428 (`smembers(\`sess:${userId}\`)` → `smembers('')`).
    it('reads the session SET using the sess:{userId} key', async () => {
      const currentHash = sha256('rae-smembers-key')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`])

      await service.revokeAllExceptCurrent({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: currentHash
      })

      expect(mockRedis.smembers).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`
      )
    })

    // Verifies that revokes all sessions except the current one.
    it('revokes all sessions except the current one', async () => {
      const currentHash = sha256('current-session')
      const otherHash1 = sha256('other-1')
      const otherHash2 = sha256('other-2')
      mockRedis.smembers.mockResolvedValue([
        `rt:${currentHash}`,
        `rt:${otherHash1}`,
        `rt:${otherHash2}`
      ])
      mockRedis.eval.mockResolvedValue(1)

      await service.revokeAllExceptCurrent({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: currentHash
      })

      const evalCalls = mockRedis.eval.mock.calls
      const revokedHashes = evalCalls.map((c) => {
        const keys = c[1] as string[]
        return (keys[1] ?? '').replace(/^rt:/, '')
      })
      expect(revokedHashes).toContain(otherHash1)
      expect(revokedHashes).toContain(otherHash2)
      expect(revokedHashes).not.toContain(currentHash)
    })

    // Verifies that skips the current session using timing-safe comparison.
    it('skips the current session using timing-safe comparison', async () => {
      const currentHash = sha256('timing-safe-current')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`])

      await service.revokeAllExceptCurrent({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: currentHash
      })

      // eval should NOT have been called (current session skipped)
      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // Verifies that swallows SESSION_NOT_FOUND errors for individual sessions (concurrent revocation).
    it('swallows SESSION_NOT_FOUND errors for individual sessions (concurrent revocation)', async () => {
      const currentHash = sha256('current-swallow')
      const otherHash = sha256('already-gone')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rt:${otherHash}`])
      // Lua returns 0 for otherHash → revokeSession throws SESSION_NOT_FOUND
      mockRedis.eval.mockResolvedValue(0)

      await expect(
        service.revokeAllExceptCurrent({
          userId: userId,
          tenantId: 'tenant-1',
          currentSessionHash: currentHash
        })
      ).resolves.toBeUndefined()
    })

    // Verifies that re-throws non-SESSION_NOT_FOUND errors.
    it('re-throws non-SESSION_NOT_FOUND errors', async () => {
      const currentHash = sha256('current-rethrow')
      const otherHash = sha256('redis-fail')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rt:${otherHash}`])
      mockRedis.eval.mockRejectedValue(new Error('Unexpected Redis failure'))

      await expect(
        service.revokeAllExceptCurrent({
          userId: userId,
          tenantId: 'tenant-1',
          currentSessionHash: currentHash
        })
      ).rejects.toThrow('Unexpected Redis failure')
    })

    // Verifies that re-throws AuthException with a code other than SESSION_NOT_FOUND.
    it('re-throws AuthException with a code other than SESSION_NOT_FOUND', async () => {
      const currentHash = sha256('current-other-auth-err')
      const otherHash = sha256('other-auth-err')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rt:${otherHash}`])

      // Simulate revokeSession throwing a different AuthException
      // We do that by making the hash invalid — but revokeAllExceptCurrent validates currentHash
      // and calls revokeSession with member hashes. Let's use a spy instead.
      const revokeSpy = jest
        .spyOn(service, 'revokeSession')
        .mockRejectedValue(new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID))

      await expect(
        service.revokeAllExceptCurrent({
          userId: userId,
          tenantId: 'tenant-1',
          currentSessionHash: currentHash
        })
      ).rejects.toBeInstanceOf(AuthException)

      revokeSpy.mockRestore()
    })

    // Verifies that correctly handles an empty session list.
    it('correctly handles an empty session list', async () => {
      const currentHash = sha256('current-empty')
      mockRedis.smembers.mockResolvedValue([])

      await expect(
        service.revokeAllExceptCurrent({
          userId: userId,
          tenantId: 'tenant-1',
          currentSessionHash: currentHash
        })
      ).resolves.toBeUndefined()
      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // `rp:` members are not refresh sessions, so the revocation loop must not try to revoke
    // them through the Lua path — but they must not survive either.
    //
    // A grace pointer names a successor session that a predecessor token may still recover.
    // For every session this call revokes that is harmless, since the grace branch requires the
    // successor's `rt:` key and it is gone. The gap is the session deliberately KEPT: its
    // predecessor's pointer names a hash that is still alive, so whoever holds that predecessor
    // token could take the grace branch and mint a brand-new full-lifetime session for the rest
    // of the window — after the user asked to sign out their other devices. The epoch bump does
    // not close it: a recovered session signs its access token from the current epoch.
    it('deletes every rp: grace pointer instead of merely skipping it', async () => {
      const currentHash = sha256('current-rp-filter')
      const rpHash = sha256('grace-pointer')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rp:${rpHash}`])
      mockRedis.del.mockResolvedValue(undefined)
      mockRedis.srem.mockResolvedValue(1)

      await service.revokeAllExceptCurrent({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: currentHash
      })

      // Not routed through the session-revocation Lua — it is not a session.
      expect(mockRedis.eval).not.toHaveBeenCalled()
      // …but the key is gone, and so is its entry in the per-user index.
      expect(mockRedis.del).toHaveBeenCalledWith(`rp:${rpHash}`)
      expect(mockRedis.srem).toHaveBeenCalledWith(
        `sess:${hmacSha256(`dashboard:8:tenant-1:${userId}`, HMAC_KEY)}`,
        `rp:${rpHash}`
      )
    })

    // Verifies that silently skips sessions that fail the ownership check (BOLA resistance via Lua).
    it('silently skips sessions that fail the ownership check (BOLA resistance via Lua)', async () => {
      const currentHash = sha256('attacker-current')
      const victimHash = sha256('victim-session')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rt:${victimHash}`])
      // Lua returns 0 — victim session is not in sess:attacker SET
      mockRedis.eval.mockResolvedValue(0)

      // Should resolve (not throw) because SESSION_NOT_FOUND is swallowed
      await expect(
        service.revokeAllExceptCurrent({
          userId: 'attacker',
          tenantId: 'tenant-1',
          currentSessionHash: currentHash
        })
      ).resolves.toBeUndefined()
    })

    // Scenario: the user signs out their other devices. Expected: the token epoch advances.
    // Why: deleting a refresh session stops that device ROTATING, but its already-issued access
    // token is stateless and keeps verifying for the rest of its lifetime — up to
    // `jwt.accessExpiresIn` of continued access on a device the user just revoked. Someone who
    // clicks this because they think a device is compromised means now.
    it('should advance the token epoch so the revocation is immediate', async () => {
      mockRedis.smembers.mockResolvedValue([`rt:${'a'.repeat(64)}`, `rt:${'b'.repeat(64)}`])
      mockRedis.eval.mockResolvedValue(1)

      await service.revokeAllExceptCurrent({
        userId: userId,
        tenantId: 'tenant-1',
        currentSessionHash: 'a'.repeat(64)
      })

      expect(mockRedis.bumpUserTokenEpoch).toHaveBeenCalledWith(userId, 'tenant-1', 'dashboard')
    })

    // Scenario: a revocation in the loop fails with something other than SESSION_NOT_FOUND.
    // Expected: the error propagates and the epoch is NOT advanced. Why: bumping would sign the
    // caller out of a device the loop never managed to revoke — the worst of both outcomes, and
    // it would report success by leaving no trace of the failure.
    it('should not advance the epoch when a revocation fails', async () => {
      mockRedis.smembers.mockResolvedValue([`rt:${'b'.repeat(64)}`])
      mockRedis.eval.mockRejectedValue(new Error('redis down'))

      await expect(
        service.revokeAllExceptCurrent({
          userId: userId,
          tenantId: 'tenant-1',
          currentSessionHash: 'a'.repeat(64)
        })
      ).rejects.toThrow('redis down')
      expect(mockRedis.bumpUserTokenEpoch).not.toHaveBeenCalled()
    })
  })

  // =========================================================================
  // rotateSession
  // =========================================================================

  describe('rotateSession', () => {
    const userId = 'user-rotate'
    const ip = '10.10.10.10'
    const userAgent = 'Mozilla/5.0 Firefox/120.0'

    // Verifies that throws VALIDATION for invalid oldHash format.
    it('throws VALIDATION for invalid oldHash format', async () => {
      const newHash = sha256('new-token')
      let thrown: unknown
      try {
        await service.rotateSession('invalid', newHash, ip, userAgent)
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.VALIDATION)
    })

    // Verifies that throws VALIDATION for invalid newHash format.
    it('throws VALIDATION for invalid newHash format', async () => {
      const oldHash = sha256('old-token')
      let thrown: unknown
      try {
        await service.rotateSession(oldHash, 'invalid', ip, userAgent)
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.VALIDATION)
    })

    // Verifies that returns immediately (no Redis call) when oldHash === newHash.
    it('returns immediately (no Redis call) when oldHash === newHash', async () => {
      const hash = sha256('same-hash-token')

      await service.rotateSession(hash, hash, ip, userAgent)

      expect(mockRedis.get).not.toHaveBeenCalled()
      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // Verifies that reads the old sd: record to preserve createdAt.
    it('reads the old sd: record to preserve createdAt', async () => {
      const oldHash = sha256('old-rotate-token')
      const newHash = sha256('new-rotate-token')
      const storedCreatedAt = 1_600_000_000_000
      mockRedis.get.mockResolvedValue(makeDetailJson(storedCreatedAt))
      mockRedis.eval.mockResolvedValue(1)

      await service.rotateSession(oldHash, newHash, ip, userAgent)

      expect(mockRedis.get).toHaveBeenCalledWith(`sd:${oldHash}`)
    })

    // Verifies that preserves the original createdAt from the old record.
    it('preserves the original createdAt from the old record', async () => {
      const oldHash = sha256('preserve-created-at-old')
      const newHash = sha256('preserve-created-at-new')
      const originalCreatedAt = 1_500_000_000_000
      mockRedis.get.mockResolvedValue(makeDetailJson(originalCreatedAt))
      mockRedis.eval.mockResolvedValue(1)

      await service.rotateSession(oldHash, newHash, ip, userAgent)

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const evalCall = mockRedis.eval.mock.calls[0]!
      const storedJson = (evalCall as [string, string[], string[]])[2][0] as string
      const stored = JSON.parse(storedJson) as { createdAt: number }
      expect(stored.createdAt).toBe(originalCreatedAt)
    })

    // Verifies that falls back to Date.now() when old sd: record is missing (get returns null).
    it('falls back to Date.now() when old sd: record is missing (get returns null)', async () => {
      const oldHash = sha256('missing-old-detail-old')
      const newHash = sha256('missing-old-detail-new')
      mockRedis.get.mockResolvedValue(null)
      mockRedis.eval.mockResolvedValue(1)

      const before = Date.now()
      await service.rotateSession(oldHash, newHash, ip, userAgent)
      const after = Date.now()

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const evalCall = mockRedis.eval.mock.calls[0]!
      const storedJson = (evalCall as [string, string[], string[]])[2][0] as string
      const stored = JSON.parse(storedJson) as { createdAt: number }
      expect(stored.createdAt).toBeGreaterThanOrEqual(before)
      expect(stored.createdAt).toBeLessThanOrEqual(after)
    })

    // Verifies that falls back to Date.now() when old sd: record has unparseable JSON.
    it('falls back to Date.now() when old sd: record has unparseable JSON', async () => {
      const oldHash = sha256('bad-json-old-rotate')
      const newHash = sha256('bad-json-new-rotate')
      mockRedis.get.mockResolvedValue('{invalid json}}}')
      mockRedis.eval.mockResolvedValue(1)

      const before = Date.now()
      await service.rotateSession(oldHash, newHash, ip, userAgent)
      const after = Date.now()

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const evalCall = mockRedis.eval.mock.calls[0]!
      const storedJson = (evalCall as [string, string[], string[]])[2][0] as string
      const stored = JSON.parse(storedJson) as { createdAt: number }
      expect(stored.createdAt).toBeGreaterThanOrEqual(before)
      expect(stored.createdAt).toBeLessThanOrEqual(after)
    })

    // Verifies that calls redis.eval with ROTATE_SESSION_DETAIL_LUA and correct keys/args.
    it('calls redis.eval with ROTATE_SESSION_DETAIL_LUA and correct keys/args', async () => {
      const oldHash = sha256('lua-keys-old')
      const newHash = sha256('lua-keys-new')
      const storedCreatedAt = 1_200_000_000_000
      mockRedis.get.mockResolvedValue(makeDetailJson(storedCreatedAt))
      mockRedis.eval.mockResolvedValue(1)

      await service.rotateSession(oldHash, newHash, ip, userAgent)

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        [`sd:${oldHash}`, `sd:${newHash}`],
        [expect.any(String), String(TTL)]
      )
    })

    // Scenario: the rotation Lua must atomically DEL the old detail and SET the new one.
    // Expected: the script passed to eval contains DEL and SET calls. Why: kills the StringLiteral
    // mutant on line 70 (ROTATE_SESSION_DETAIL_LUA → empty string), which would send an empty script
    // and silently fail to move the detail record.
    it('evaluates a rotation Lua script containing DEL and SET', async () => {
      const oldHash = sha256('rotate-script-old')
      const newHash = sha256('rotate-script-new')
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))
      mockRedis.eval.mockResolvedValue(1)

      await service.rotateSession(oldHash, newHash, ip, userAgent)

      const script = (mockRedis.eval.mock.calls[0] as [string, string[], string[]])[0]
      expect(script).toContain('DEL')
      expect(script).toContain('SET')
    })

    // Verifies that writes refreshed ip in the new sd: record.
    it('writes refreshed ip in the new sd: record', async () => {
      const oldHash = sha256('ip-refresh-old')
      const newHash = sha256('ip-refresh-new')
      mockRedis.get.mockResolvedValue(makeDetailJson(1000, { ip: '1.2.3.4' }))
      mockRedis.eval.mockResolvedValue(1)

      await service.rotateSession(oldHash, newHash, '99.99.99.99', userAgent)

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const evalCall = mockRedis.eval.mock.calls[0]!
      const storedJson = (evalCall as [string, string[], string[]])[2][0] as string
      const stored = JSON.parse(storedJson) as { ip: string }
      expect(stored.ip).toBe('99.99.99.99')
    })

    // Verifies that truncates long IP to 45 chars in the new sd: record.
    it('truncates long IP to 45 chars in the new sd: record', async () => {
      const oldHash = sha256('ip-truncate-old')
      const newHash = sha256('ip-truncate-new')
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))
      mockRedis.eval.mockResolvedValue(1)

      await service.rotateSession(oldHash, newHash, 'b'.repeat(60), userAgent)

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const evalCall = mockRedis.eval.mock.calls[0]!
      const storedJson = (evalCall as [string, string[], string[]])[2][0] as string
      const stored = JSON.parse(storedJson) as { ip: string }
      expect(stored.ip).toHaveLength(45)
    })

    // Verifies that updates lastActivityAt to the current time in the new sd: record.
    it('updates lastActivityAt to the current time in the new sd: record', async () => {
      const oldHash = sha256('last-activity-old')
      const newHash = sha256('last-activity-new')
      mockRedis.get.mockResolvedValue(makeDetailJson(1000, { lastActivityAt: 500 }))
      mockRedis.eval.mockResolvedValue(1)

      const before = Date.now()
      await service.rotateSession(oldHash, newHash, ip, userAgent)
      const after = Date.now()

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const evalCall = mockRedis.eval.mock.calls[0]!
      const storedJson = (evalCall as [string, string[], string[]])[2][0] as string
      const stored = JSON.parse(storedJson) as { lastActivityAt: number }
      expect(stored.lastActivityAt).toBeGreaterThanOrEqual(before)
      expect(stored.lastActivityAt).toBeLessThanOrEqual(after)
    })

    // Verifies that falls back to Date.now() when old sd: record has valid JSON but no createdAt number.
    it('falls back to Date.now() when old sd: record has valid JSON but no createdAt number', async () => {
      const oldHash = sha256('no-created-at-old')
      const newHash = sha256('no-created-at-new')
      // Valid JSON object but createdAt is a string, not a number
      mockRedis.get.mockResolvedValue(
        JSON.stringify({
          device: 'Chrome',
          ip: '1.2.3.4',
          createdAt: 'not-a-number',
          lastActivityAt: 1000
        })
      )
      mockRedis.eval.mockResolvedValue(1)

      const before = Date.now()
      await service.rotateSession(oldHash, newHash, ip, userAgent)
      const after = Date.now()

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      const evalCall = mockRedis.eval.mock.calls[0]!
      const storedJson = (evalCall as [string, string[], string[]])[2][0] as string
      const stored = JSON.parse(storedJson) as { createdAt: number }
      expect(stored.createdAt).toBeGreaterThanOrEqual(before)
      expect(stored.createdAt).toBeLessThanOrEqual(after)
    })
  })
  // ---------------------------------------------------------------------------
  // Grace-pointer accumulation in the session index
  // ---------------------------------------------------------------------------

  describe('grace-pointer pruning', () => {
    // Scenario: the index a login and a listing walk. Expected: both ask for the dead grace
    // members to be dropped first. Why: a rotation removes `rt:{old}` and adds TWO members —
    // `rt:{new}` and `rp:{old}` — and only a full revoke-all ever removed the second. The
    // `rp:` KEY expires with the 30-second grace window; the MEMBER did not, and the rotation
    // re-arms the set's own TTL each time, so the index grew by one permanent entry per
    // refresh and never aged out while the account was in use.
    //
    // It is a growth defect with an amplifier attached: every reader is linear in the set's
    // size. `listSessions` ships the whole thing, `revokeAllExceptCurrent` issues two
    // sequential round trips per grace member, and `invalidateUserSessions` iterates it inside
    // a Lua script that blocks the single-threaded store. One stolen refresh token rotated at
    // the route limit adds ~14k members a day, with no ceiling.
    it('prunes dead grace members before enforcing the session limit', async () => {
      mockRedis.smembers.mockResolvedValue([])
      mockUserRepo.findById.mockResolvedValue({ id: 'user-1' })

      await service.createSession({
        userId: 'user-1',
        tenantId: 'tenant-1',
        rawRefreshToken: 'raw-token',
        ip: '1.2.3.4',
        userAgent: 'Chrome'
      })

      expect(mockRedis.pruneExpiredGraceMembers).toHaveBeenCalledWith(
        `sess:${hmacSha256('dashboard:8:tenant-1:user-1', HMAC_KEY)}`,
        'rp:'
      )
    })

    it('prunes dead grace members when listing sessions', async () => {
      mockRedis.smembers.mockResolvedValue([])

      await service.listSessions({ userId: 'user-1', tenantId: 'tenant-1' })

      expect(mockRedis.pruneExpiredGraceMembers).toHaveBeenCalledWith(
        `sess:${hmacSha256('dashboard:8:tenant-1:user-1', HMAC_KEY)}`,
        'rp:'
      )
    })

    // A prune that throws is a tidy-up that did not happen, not a listing that should fail —
    // the caller asked for their sessions, and the index is still readable.
    it('still lists sessions when the prune fails', async () => {
      mockRedis.pruneExpiredGraceMembers.mockRejectedValueOnce(new Error('redis down'))
      mockRedis.smembers.mockResolvedValue([])
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => {})

      try {
        await expect(
          service.listSessions({ userId: 'user-1', tenantId: 'tenant-1' })
        ).resolves.toEqual([])
        // Let the fire-and-forget rejection settle before asserting on the log.
        await Promise.resolve()
        // Named, not merely counted: an operator seeing a run of these needs to know the prune
        // is what failed, not the listing — the two have different remedies.
        expect(warn).toHaveBeenCalledWith('listSessions: grace-pointer prune failed: <error>')
      } finally {
        warn.mockRestore()
      }
    })
  })
  // The public boundary refuses a tenant that names nothing. Every method here takes the tenant
  // positionally beside a `string` user id and all of them are exported, so `''` is a shape a
  // caller can produce — and it derived `dashboard:0::{userId}`, an index nobody writes. Each of
  // these swept, listed or revoked against that key and RETURNED NORMALLY: work reported as done
  // while every session it named stayed live.
  //
  // The check cannot live in `userSubject`: the rotation scripts must be called with the empty
  // placeholder identity to discover a grace pointer, so that builder has to stay total, and an
  // empty entry in a script's KEYS array is not "no key" — the eval wrapper prefixes it into a
  // real key named `auth:`.
  describe('blank tenant at the public boundary', () => {
    it.each([
      [
        'createSession',
        (s: SessionService) =>
          s.createSession({
            userId: 'user-1',
            tenantId: '',
            rawRefreshToken: 'raw',
            ip: '1.2.3.4',
            userAgent: 'UA'
          })
      ],
      ['listSessions', (s: SessionService) => s.listSessions({ userId: 'user-1', tenantId: '' })],
      [
        'revokeSession',
        (s: SessionService) =>
          s.revokeSession({ userId: 'user-1', tenantId: '', sessionHash: 'a'.repeat(64) })
      ],
      [
        'revokeOtherSession',
        (s: SessionService) =>
          s.revokeOtherSession({ userId: 'user-1', tenantId: '', sessionHash: 'a'.repeat(64) })
      ],
      [
        'revokeAllExceptCurrent',
        (s: SessionService) =>
          s.revokeAllExceptCurrent({
            userId: 'user-1',
            tenantId: '',
            currentSessionHash: 'a'.repeat(64)
          })
      ]
    ])('%s refuses it', async (_label, call) => {
      // The DETAILS, not merely the exception type. `rejects.toThrow(AuthException)` passes for a
      // throw that names no field and carries no message — and a validation error whose payload is
      // empty tells the caller nothing about what to fix, which is the same defect one level down
      // from the one being guarded here.
      await expect(call(service)).rejects.toMatchObject({
        response: {
          error: {
            code: AUTH_ERROR_CODES.VALIDATION,
            details: [
              { field: 'tenantId', message: 'tenantId is required to name a session index' }
            ]
          }
        }
      })
    })
  })
})
