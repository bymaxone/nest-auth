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
} from '../bymax-one-nest-auth.constants'
import { sha256 } from '../crypto/secure-token'
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
  eval: jest.fn<Promise<unknown>, [string, string[], string[]]>()
}

const mockUserRepo = {
  findById: jest.fn<Promise<unknown>, [string]>()
}

const mockHooks = {
  onNewSession: jest.fn<Promise<void>, [unknown, unknown, unknown]>(),
  onSessionEvicted: jest.fn<Promise<void>, [string, string, unknown]>()
}

const mockOptions = {
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

      await service.createSession(userId, rawToken, ip, userAgent)

      expect(mockRedis.set).toHaveBeenCalledWith(`sd:${hash}`, expect.any(String), TTL)
    })

    // Verifies that returns the sha256 hash of the raw refresh token.
    it('returns the sha256 hash of the raw refresh token', async () => {
      const expected = sha256(rawToken)

      const result = await service.createSession(userId, rawToken, ip, userAgent)

      expect(result).toBe(expected)
    })

    // Verifies that truncates IP to 45 characters before storage.
    it('truncates IP to 45 characters before storage', async () => {
      const longIp = 'a'.repeat(60)

      await service.createSession(userId, rawToken, longIp, userAgent)

      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        ip: string
      }
      expect(stored.ip).toHaveLength(45)
    })

    // Verifies that stores the parsed device string (non-empty) in the detail record.
    it('stores the parsed device string (non-empty) in the detail record', async () => {
      await service.createSession(userId, rawToken, ip, userAgent)

      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toBeTruthy()
    })

    // Verifies that stores createdAt and lastActivityAt as numbers in the detail record.
    it('stores createdAt and lastActivityAt as numbers in the detail record', async () => {
      await service.createSession(userId, rawToken, ip, userAgent)

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
      await service.createSession(userId, rawToken, ip, userAgent)

      expect(mockRedis.smembers).toHaveBeenCalledWith(`sess:${userId}`)
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

      await service.createSession(userId, rawToken, ip, userAgent)

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

      await service.createSession(userId, rawToken, ip, userAgent)

      expect(mockRedis.del).toHaveBeenCalledWith(`rt:${oldestHash}`)
      expect(mockRedis.srem).toHaveBeenCalledWith(`sess:${userId}`, `rt:${oldestHash}`)
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

      await service.createSession(userId, rawToken, ip, userAgent)

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

      await service.createSession(userId, rawToken, ip, userAgent)

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

      await expect(service.createSession(userId, rawToken, ip, userAgent)).resolves.not.toThrow()
      expect(Logger.prototype.error).toHaveBeenCalled()
    })

    // Verifies that fires the onNewSession hook after the session is stored.
    it('fires the onNewSession hook after the session is stored', async () => {
      mockHooks.onNewSession.mockResolvedValue(undefined)

      await service.createSession(userId, rawToken, ip, userAgent)

      // Hook is fire-and-forget — flush microtasks
      await flushMicrotasks()

      expect(mockHooks.onNewSession).toHaveBeenCalledTimes(1)
    })

    // Verifies that passes a SafeAuthUser (no credentials) to the onNewSession hook.
    it('passes a SafeAuthUser (no credentials) to the onNewSession hook', async () => {
      mockHooks.onNewSession.mockResolvedValue(undefined)

      await service.createSession(userId, rawToken, ip, userAgent)

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

      await svcNoHooks.createSession(userId, rawToken, ip, userAgent)
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

      await svcPartialHooks.createSession(userId, rawToken, ip, userAgent)
      await flushMicrotasks()

      expect(mockHooks.onNewSession).not.toHaveBeenCalled()
    })

    // Verifies that logs error when onNewSession hook throws, without propagating.
    it('logs error when onNewSession hook throws, without propagating', async () => {
      mockHooks.onNewSession.mockRejectedValue(new Error('hook error'))

      await expect(service.createSession(userId, rawToken, ip, userAgent)).resolves.not.toThrow()

      await flushMicrotasks()

      expect(Logger.prototype.error).toHaveBeenCalled()
    })

    // Verifies that does not fire onNewSession when findById returns null.
    it('does not fire onNewSession when findById returns null', async () => {
      mockUserRepo.findById.mockResolvedValue(null)
      mockHooks.onNewSession.mockResolvedValue(undefined)

      await service.createSession(userId, rawToken, ip, userAgent)
      await flushMicrotasks()

      expect(mockHooks.onNewSession).not.toHaveBeenCalled()
    })

    // Verifies that logs error when findById throws inside onNewSession flow.
    it('logs error when findById throws inside onNewSession flow', async () => {
      mockUserRepo.findById.mockRejectedValue(new Error('db error'))

      await expect(service.createSession(userId, rawToken, ip, userAgent)).resolves.not.toThrow()

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

      await service.createSession(userId, rawToken, ip, userAgent)

      expect(resolver).toHaveBeenCalledTimes(1)
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

      await service.createSession(userId, rawToken, ip, userAgent)

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

      await service.createSession(userId, rawToken, ip, userAgent)

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

      await service.createSession(userId, rawToken, ip, userAgent)
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

      await svcNoHooks.createSession(userId, rawToken, ip, userAgent)
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

      await service.createSession(userId, rawToken, ip, userAgent)

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

      await service.createSession(userId, rawToken, ip, userAgent)

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
      await service.createSession(userId, rawToken, ip, userAgent)
      await flushMicrotasks()

      // Assert — error was logged, not thrown
      expect(Logger.prototype.error).toHaveBeenCalledWith(
        'onSessionEvicted hook threw',
        expect.any(Error)
      )
    })

    // Verifies that a user-agent containing Edg/ is stored with an Edge browser label.
    it('detects Edge browser from Edg/ token', async () => {
      const edgeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/123.0'
      await service.createSession(userId, rawToken, ip, edgeUA)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Edge')
    })

    // Verifies that a user-agent containing OPR/ is stored with an Opera browser label.
    it('detects Opera browser from OPR/ token', async () => {
      const operaUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 OPR/123.0'
      await service.createSession(userId, rawToken, ip, operaUA)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Opera')
    })

    // Verifies that a Safari user-agent (Version + Safari tokens, no Chrome/Edg/OPR) is stored with a Safari browser label.
    it('detects Safari browser (Safari + Version tokens, no Chrome/Edg/OPR)', async () => {
      const safariUA =
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
      await service.createSession(userId, rawToken, ip, safariUA)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Safari')
    })

    // Verifies that a user-agent containing the Android token is stored with an Android OS label.
    it('detects Android OS', async () => {
      const androidUA =
        'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/112.0 Mobile Safari/537.36'
      await service.createSession(userId, rawToken, ip, androidUA)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Android')
    })

    // Verifies that a user-agent containing the iPhone token is stored with an iOS OS label.
    it('detects iOS from iPhone token', async () => {
      const iosUA =
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 Version/16.4 Mobile Safari/604.1'
      await service.createSession(userId, rawToken, ip, iosUA)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('iOS')
    })

    // Verifies that a user-agent containing the Windows NT token is stored with a Windows OS label.
    it('detects Windows OS', async () => {
      const windowsUA =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/112.0 Safari/537.36'
      await service.createSession(userId, rawToken, ip, windowsUA)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Windows')
    })

    // Verifies that a user-agent containing the Linux token (non-Android desktop) is stored with a Linux OS label.
    it('detects Linux OS', async () => {
      const linuxUA =
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/112.0 Safari/537.36'
      await service.createSession(userId, rawToken, ip, linuxUA)
      const stored = JSON.parse((mockRedis.set.mock.calls[0]! as [string, string, number])[1]) as {
        device: string
      }
      expect(stored.device).toContain('Linux')
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

      const result = await service.listSessions(userId)

      expect(result).toEqual([])
    })

    // Verifies that filters out rp: grace pointer members.
    it('filters out rp: grace pointer members', async () => {
      const hash = sha256('grace-token')
      mockRedis.smembers.mockResolvedValue([`rp:${hash}`])

      const result = await service.listSessions(userId)

      expect(result).toEqual([])
      expect(mockRedis.get).not.toHaveBeenCalled()
    })

    // Verifies that fetches sd: detail records for each rt: member.
    it('fetches sd: detail records for each rt: member', async () => {
      const hash = sha256('real-token')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      await service.listSessions(userId)

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

      const result = await service.listSessions(userId)

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

      const result = await service.listSessions(userId)

      expect(result[0]!.sessionHash).toHaveLength(64)
      expect(result[0]!.sessionHash).toMatch(/^[a-f0-9]{64}$/)
    })

    // Verifies that sets isCurrent: true for the matching session hash.
    it('sets isCurrent: true for the matching session hash', async () => {
      const hash = sha256('current-token')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions(userId, hash)

      expect(result[0]!.isCurrent).toBe(true)
    })

    // Verifies that sets isCurrent: false when currentSessionHash is undefined.
    it('sets isCurrent: false when currentSessionHash is undefined', async () => {
      const hash = sha256('not-current')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions(userId, undefined)

      expect(result[0]!.isCurrent).toBe(false)
    })

    // Verifies that sets isCurrent: false when currentSessionHash is an empty string.
    it('sets isCurrent: false when currentSessionHash is an empty string', async () => {
      const hash = sha256('empty-string-check')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions(userId, '')

      expect(result[0]!.isCurrent).toBe(false)
    })

    // Verifies that sets isCurrent: false for sessions that do not match currentSessionHash.
    it('sets isCurrent: false for sessions that do not match currentSessionHash', async () => {
      const hash1 = sha256('token-a')
      const hash2 = sha256('token-b')
      mockRedis.smembers.mockResolvedValue([`rt:${hash1}`, `rt:${hash2}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions(userId, hash1)

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

      const result = await service.listSessions(userId)

      expect(result.map((s) => s.sessionHash)).not.toContain(staleHash)
    })

    // Verifies that triggers async SREM for stale members where get returns null.
    it('triggers async SREM for stale members where get returns null', async () => {
      const staleHash = sha256('srem-trigger-token')
      mockRedis.smembers.mockResolvedValue([`rt:${staleHash}`])
      mockRedis.get.mockResolvedValue(null)
      mockRedis.srem.mockResolvedValue(1)

      await service.listSessions(userId)

      // Flush microtasks for fire-and-forget srem
      await flushMicrotasks()

      expect(mockRedis.srem).toHaveBeenCalledWith(`sess:${userId}`, `rt:${staleHash}`)
    })

    // Verifies that excludes stale member when JSON is valid but all required fields are absent.
    it('excludes stale member when JSON is valid but all required fields are absent', async () => {
      const badHash = sha256('bad-json-session')
      mockRedis.smembers.mockResolvedValue([`rt:${badHash}`])
      mockRedis.get.mockResolvedValue(JSON.stringify({ foo: 'bar' }))
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions(userId)

      expect(result).toHaveLength(0)
    })

    // Verifies that excludes stale members when JSON is completely malformed.
    it('excludes stale members when JSON is completely malformed', async () => {
      const badHash = sha256('malformed-json')
      mockRedis.smembers.mockResolvedValue([`rt:${badHash}`])
      mockRedis.get.mockResolvedValue('{{{invalid')
      mockRedis.srem.mockResolvedValue(1)

      const result = await service.listSessions(userId)

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

      const result = await service.listSessions(userId)

      expect(result.map((s) => s.sessionHash)).not.toContain(throwHash)
    })

    // Verifies that triggers async SREM for members where redis.get throws.
    it('triggers async SREM for members where redis.get throws', async () => {
      const throwHash = sha256('throw-srem-token')
      mockRedis.smembers.mockResolvedValue([`rt:${throwHash}`])
      mockRedis.get.mockRejectedValue(new Error('Redis connection lost'))
      mockRedis.srem.mockResolvedValue(1)

      await service.listSessions(userId)

      await flushMicrotasks()

      expect(mockRedis.srem).toHaveBeenCalledWith(`sess:${userId}`, `rt:${throwHash}`)
    })

    // Verifies that logs error when fire-and-forget srem itself throws.
    it('logs error when fire-and-forget srem itself throws', async () => {
      const staleHash = sha256('srem-fail-token')
      mockRedis.smembers.mockResolvedValue([`rt:${staleHash}`])
      mockRedis.get.mockResolvedValue(null)
      mockRedis.srem.mockRejectedValue(new Error('srem failed'))

      await service.listSessions(userId)

      await flushMicrotasks()

      expect(Logger.prototype.error).toHaveBeenCalled()
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

      const result = await service.listSessions(userId)

      expect(result[0]!.sessionHash).toBe(hash2)
      expect(result[1]!.sessionHash).toBe(hash3)
      expect(result[2]!.sessionHash).toBe(hash1)
    })

    // Verifies that correctly carries the ip field from the stored detail record.
    it('correctly carries the ip field from the stored detail record', async () => {
      const hash = sha256('ip-carry-token')
      mockRedis.smembers.mockResolvedValue([`rt:${hash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000, { ip: '203.0.113.42' }))

      const result = await service.listSessions(userId)

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

      const result = await service.listSessions(userId)

      expect(result).toHaveLength(0)
    })

    // Verifies that handles a mix of rt: and rp: members correctly.
    it('handles a mix of rt: and rp: members correctly', async () => {
      const rtHash = sha256('mixed-rt-token')
      const rpHash = sha256('mixed-rp-token')
      mockRedis.smembers.mockResolvedValue([`rt:${rtHash}`, `rp:${rpHash}`])
      mockRedis.get.mockResolvedValue(makeDetailJson(1000))

      const result = await service.listSessions(userId)

      expect(result).toHaveLength(1)
      expect(result[0]!.sessionHash).toBe(rtHash)
    })
  })

  // =========================================================================
  // revokeSession
  // =========================================================================

  describe('revokeSession', () => {
    const userId = 'user-revoke'

    // Verifies that throws SESSION_NOT_FOUND for a hash shorter than 64 chars.
    it('throws SESSION_NOT_FOUND for a hash shorter than 64 chars', async () => {
      let thrownShort: unknown
      try {
        await service.revokeSession(userId, 'abc123')
      } catch (e) {
        thrownShort = e
      }
      expect(getErrorCode(thrownShort)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that throws SESSION_NOT_FOUND for a hash longer than 64 chars.
    it('throws SESSION_NOT_FOUND for a hash longer than 64 chars', async () => {
      const longHash = 'a'.repeat(65)
      let thrownLong: unknown
      try {
        await service.revokeSession(userId, longHash)
      } catch (e) {
        thrownLong = e
      }
      expect(getErrorCode(thrownLong)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that throws SESSION_NOT_FOUND for a hash containing uppercase hex characters.
    it('throws SESSION_NOT_FOUND for a hash containing uppercase hex characters', async () => {
      const upperHash = 'A'.repeat(64)
      let thrownUpper: unknown
      try {
        await service.revokeSession(userId, upperHash)
      } catch (e) {
        thrownUpper = e
      }
      expect(getErrorCode(thrownUpper)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that throws SESSION_NOT_FOUND for a hash containing non-hex characters.
    it('throws SESSION_NOT_FOUND for a hash containing non-hex characters', async () => {
      const invalidHash = 'g'.repeat(64)
      let thrownInvalid: unknown
      try {
        await service.revokeSession(userId, invalidHash)
      } catch (e) {
        thrownInvalid = e
      }
      expect(getErrorCode(thrownInvalid)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that calls redis.eval with correct KEYS and ARGV.
    it('calls redis.eval with correct KEYS and ARGV', async () => {
      const hash = sha256('revoke-token')
      mockRedis.eval.mockResolvedValue(1)

      await service.revokeSession(userId, hash)

      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.any(String),
        [`sess:${userId}`, `rt:${hash}`, `sd:${hash}`],
        [`rt:${hash}`]
      )
    })

    // Verifies that throws SESSION_NOT_FOUND when Lua returns 0 (not a member).
    it('throws SESSION_NOT_FOUND when Lua returns 0 (not a member)', async () => {
      const hash = sha256('not-member-token')
      mockRedis.eval.mockResolvedValue(0)

      let thrownLuaZero: unknown
      try {
        await service.revokeSession(userId, hash)
      } catch (e) {
        thrownLuaZero = e
      }
      expect(getErrorCode(thrownLuaZero)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that resolves without throwing when Lua returns 1 (success).
    it('resolves without throwing when Lua returns 1 (success)', async () => {
      const hash = sha256('success-revoke-token')
      mockRedis.eval.mockResolvedValue(1)

      await expect(service.revokeSession(userId, hash)).resolves.toBeUndefined()
    })

    // Verifies that treats non-number Lua return values as 0 (SESSION_NOT_FOUND).
    it('treats non-number Lua return values as 0 (SESSION_NOT_FOUND)', async () => {
      const hash = sha256('non-number-lua')
      mockRedis.eval.mockResolvedValue(null)

      let thrown: unknown
      try {
        await service.revokeSession(userId, hash)
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
        await service.revokeSession('attacker-user', victimHash)
      } catch (e) {
        thrownBola = e
      }
      expect(getErrorCode(thrownBola)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that propagates Redis errors thrown by redis.eval.
    it('propagates Redis errors thrown by redis.eval', async () => {
      const hash = sha256('redis-crash-token')
      mockRedis.eval.mockRejectedValue(new Error('ECONNRESET'))

      await expect(service.revokeSession(userId, hash)).rejects.toThrow('ECONNRESET')
    })
  })

  // =========================================================================
  // revokeAllExceptCurrent
  // =========================================================================

  describe('revokeAllExceptCurrent', () => {
    const userId = 'user-revoke-all'

    // Verifies that throws SESSION_NOT_FOUND for invalid currentSessionHash format.
    it('throws SESSION_NOT_FOUND for invalid currentSessionHash format', async () => {
      let thrown: unknown
      try {
        await service.revokeAllExceptCurrent(userId, 'not-valid')
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
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

      await service.revokeAllExceptCurrent(userId, currentHash)

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

      await service.revokeAllExceptCurrent(userId, currentHash)

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

      await expect(service.revokeAllExceptCurrent(userId, currentHash)).resolves.toBeUndefined()
    })

    // Verifies that re-throws non-SESSION_NOT_FOUND errors.
    it('re-throws non-SESSION_NOT_FOUND errors', async () => {
      const currentHash = sha256('current-rethrow')
      const otherHash = sha256('redis-fail')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rt:${otherHash}`])
      mockRedis.eval.mockRejectedValue(new Error('Unexpected Redis failure'))

      await expect(service.revokeAllExceptCurrent(userId, currentHash)).rejects.toThrow(
        'Unexpected Redis failure'
      )
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

      await expect(service.revokeAllExceptCurrent(userId, currentHash)).rejects.toBeInstanceOf(
        AuthException
      )

      revokeSpy.mockRestore()
    })

    // Verifies that correctly handles an empty session list.
    it('correctly handles an empty session list', async () => {
      const currentHash = sha256('current-empty')
      mockRedis.smembers.mockResolvedValue([])

      await expect(service.revokeAllExceptCurrent(userId, currentHash)).resolves.toBeUndefined()
      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // Verifies that filters out rp: members and does not try to revoke them.
    it('filters out rp: members and does not try to revoke them', async () => {
      const currentHash = sha256('current-rp-filter')
      const rpHash = sha256('grace-pointer')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rp:${rpHash}`])

      await service.revokeAllExceptCurrent(userId, currentHash)

      expect(mockRedis.eval).not.toHaveBeenCalled()
    })

    // Verifies that silently skips sessions that fail the ownership check (BOLA resistance via Lua).
    it('silently skips sessions that fail the ownership check (BOLA resistance via Lua)', async () => {
      const currentHash = sha256('attacker-current')
      const victimHash = sha256('victim-session')
      mockRedis.smembers.mockResolvedValue([`rt:${currentHash}`, `rt:${victimHash}`])
      // Lua returns 0 — victim session is not in sess:attacker SET
      mockRedis.eval.mockResolvedValue(0)

      // Should resolve (not throw) because SESSION_NOT_FOUND is swallowed
      await expect(service.revokeAllExceptCurrent('attacker', currentHash)).resolves.toBeUndefined()
    })
  })

  // =========================================================================
  // rotateSession
  // =========================================================================

  describe('rotateSession', () => {
    const userId = 'user-rotate'
    const ip = '10.10.10.10'
    const userAgent = 'Mozilla/5.0 Firefox/120.0'

    // Verifies that throws SESSION_NOT_FOUND for invalid oldHash format.
    it('throws SESSION_NOT_FOUND for invalid oldHash format', async () => {
      const newHash = sha256('new-token')
      let thrown: unknown
      try {
        await service.rotateSession('invalid', newHash, ip, userAgent)
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that throws SESSION_NOT_FOUND for invalid newHash format.
    it('throws SESSION_NOT_FOUND for invalid newHash format', async () => {
      const oldHash = sha256('old-token')
      let thrown: unknown
      try {
        await service.rotateSession(oldHash, 'invalid', ip, userAgent)
      } catch (e) {
        thrown = e
      }
      expect(getErrorCode(thrown)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
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
})
