/**
 * @fileoverview SessionService.resolveLiveSession — the session a presented hash stands for, directly or
 * through the grace pointer of a token that rotated away. Kept apart from `session.service.spec.ts`
 * because that file is already over the size limit.
 *
 * @layer Test
 */

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from './session.service'

const mockRedis = {
  get: jest.fn<Promise<string | null>, [string]>(),
  del: jest.fn<Promise<void>, [string]>(),
  srem: jest.fn<Promise<number>, [string, string]>(),
  smembers: jest.fn<Promise<string[]>, [string]>(),
  eval: jest.fn<Promise<unknown>, [string, string[], string[]]>(),
  pruneExpiredGraceMembers: jest.fn<Promise<number>, [string, string]>().mockResolvedValue(0),
  pruneDeadMembers: jest.fn<Promise<number>, [string, string[]]>().mockResolvedValue(0),
  bumpUserTokenEpoch: jest.fn()
}

const mockOptions = {
  hmacKey: 'test-hmac-key',
  jwt: { secret: 'test-secret', refreshExpiresInDays: 7 },
  sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

let service: SessionService

beforeEach(async () => {
  jest.clearAllMocks()
  const module = await Test.createTestingModule({
    providers: [
      SessionService,
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
      { provide: GUARDED_USER_REPOSITORY, useValue: {} },
      { provide: BYMAX_AUTH_HOOKS, useValue: {} }
    ]
  }).compile()
  service = module.get(SessionService)
})

describe('SessionService.resolveLiveSession', () => {
  const userId = 'user-resolve'
  const presented = 'a'.repeat(64)
  const successor = 'b'.repeat(64)
  const params = { userId, tenantId: 'tenant-1', sessionHash: presented }

  beforeEach(() => {
    mockRedis.get.mockResolvedValue(null)
  })

  // Scenario: the hash is itself a live session. Expected: it is the session to keep, and the
  // grace pointer is not consulted.
  it('names the presented hash when it is a live session', async () => {
    mockRedis.smembers.mockResolvedValue([`rt:${presented}`])

    await expect(service.resolveLiveSession(params)).resolves.toBe(presented)
    expect(mockRedis.get).not.toHaveBeenCalled()
  })

  // Scenario: the token rotated a moment ago, so the index holds a grace pointer for it and the
  // session the rotation produced. Expected: that successor is the session to keep.
  it('names the live successor of a token that rotated away', async () => {
    mockRedis.smembers.mockResolvedValue([`rp:${presented}`, `rt:${successor}`])
    mockRedis.get.mockResolvedValue(`${successor}:{"userId":"u"}`)

    await expect(service.resolveLiveSession(params)).resolves.toBe(successor)
    expect(mockRedis.get).toHaveBeenCalledWith(`rp:${presented}`)
  })

  // Scenario: resolving through a pointer. Expected: nothing is written or deleted, so the grace
  // window the pointer sits in is neither consumed nor extended and the rotation script can still
  // honour the pointer for the retry it exists for.
  it('only reads the grace pointer', async () => {
    mockRedis.smembers.mockResolvedValue([`rp:${presented}`, `rt:${successor}`])
    mockRedis.get.mockResolvedValue(`${successor}:{}`)

    await service.resolveLiveSession(params)

    expect(mockRedis.get).toHaveBeenCalledTimes(1)
    expect(mockRedis.del).not.toHaveBeenCalled()
    expect(mockRedis.eval).not.toHaveBeenCalled()
  })

  // Scenario: the presented token's pointer names a session that is itself no longer live, and
  // that session has a pointer of its own naming a live one. Expected: refused. Resolution stops
  // at one hop, so a chain of rotations never lets an old token stand for a distant session.
  it('does not follow a successor through its own pointer', async () => {
    const further = 'd'.repeat(64)
    mockRedis.smembers.mockResolvedValue([`rp:${presented}`, `rp:${successor}`, `rt:${further}`])
    mockRedis.get.mockImplementation(async (key: string) =>
      key === `rp:${presented}` ? `${successor}:{}` : `${further}:{}`
    )

    await expect(service.resolveLiveSession(params)).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.SESSION_NOT_FOUND } }
    })
    expect(mockRedis.get).toHaveBeenCalledTimes(1)
  })

  // Scenario: the pointer names a successor the index no longer holds, one that was revoked, or
  // there is no pointer at all, or its value is not `{hash}:{record}`. Expected: nothing is live,
  // so the call is refused as not found. Why: a pointer outlives its successor and must not
  // resurrect a session the user ended; a value that does not parse names no session.
  it.each([
    ['a successor that is not in the index', [`rp:${presented}`], `${successor}:{}`],
    ['no pointer', [`rp:${presented}`, `rt:${successor}`], null],
    ['a pointer with no separator', [`rt:${successor}`], successor],
    ['a pointer with no separator after a full hash', [`rt:${successor}`], `${successor}c`],
    ['a pointer whose successor is not a session hash', [`rt:${successor}`], 'nothex:{}'],
    ['a pointer whose hash is not hex', [`rt:${'z'.repeat(64)}`], `${'z'.repeat(64)}:{}`]
  ])('refuses %s', async (_label, members, pointer) => {
    mockRedis.smembers.mockResolvedValue(members)
    mockRedis.get.mockResolvedValue(pointer)

    await expect(service.resolveLiveSession(params)).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.SESSION_NOT_FOUND } }
    })
  })

  // The same input checks as assertLiveSession, before anything is read.
  it('refuses a blank tenant and a malformed hash before reading the index', async () => {
    await expect(service.resolveLiveSession({ ...params, tenantId: '' })).rejects.toBeInstanceOf(
      AuthException
    )
    await expect(
      service.resolveLiveSession({ ...params, sessionHash: 'not-a-hash' })
    ).rejects.toBeInstanceOf(AuthException)
    expect(mockRedis.smembers).not.toHaveBeenCalled()
  })

  // Scenario: revoke-all with a token that rotated away. Expected: the successor is the session
  // kept and every other session is revoked, the predecessor's pointer included.
  it('keeps the successor in revokeAllExceptCurrent', async () => {
    const other = 'c'.repeat(64)
    mockRedis.smembers.mockResolvedValue([`rp:${presented}`, `rt:${successor}`, `rt:${other}`])
    mockRedis.get.mockResolvedValue(`${successor}:{}`)
    const revoke = jest.spyOn(service, 'revokeSession').mockResolvedValue(undefined)

    await service.revokeAllExceptCurrent({
      userId,
      tenantId: 'tenant-1',
      currentSessionHash: presented
    })

    expect(revoke).toHaveBeenCalledTimes(1)
    expect(revoke).toHaveBeenCalledWith({
      userId,
      tenantId: 'tenant-1',
      sessionHash: other
    })
  })
})
