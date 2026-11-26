/**
 * @fileoverview Which listed session is the caller's: by the refresh token when one is presented,
 * otherwise by the session identifier of the access token.
 */

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from './session.service'
import type { ListSessionsParams } from './session.service'

const MINE = '11111111-1111-4111-8111-111111111111'
const OTHER = '22222222-2222-4222-8222-222222222222'
const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)

const detail = JSON.stringify({ device: 'd', ip: 'i', createdAt: 1, lastActivityAt: 1 })
const record = (familyId?: string): string => JSON.stringify({ userId: 'u1', familyId })

describe('SessionService.listSessions, the current session', () => {
  let service: SessionService
  let records: Map<string, string>
  const redis = {
    smembers: jest.fn(),
    get: jest.fn(),
    pruneExpiredGraceMembers: jest.fn(),
    pruneDeadMembers: jest.fn()
  }

  beforeEach(async () => {
    jest.resetAllMocks()
    records = new Map([
      [`rt:${A}`, record(MINE)],
      [`rt:${B}`, record(OTHER)],
      [`rt:${C}`, record(MINE)]
    ])
    redis.smembers.mockResolvedValue([`rt:${A}`, `rt:${B}`, `rt:${C}`])
    redis.get.mockImplementation(async (key: string) =>
      key.startsWith('sd:') ? detail : (records.get(key) ?? null)
    )
    redis.pruneExpiredGraceMembers.mockResolvedValue(0)
    redis.pruneDeadMembers.mockResolvedValue(0)
    const moduleRef = await Test.createTestingModule({
      providers: [
        SessionService,
        { provide: AuthRedisService, useValue: redis },
        { provide: BYMAX_AUTH_OPTIONS, useValue: { hmacKey: 'test-hmac-key' } },
        { provide: GUARDED_USER_REPOSITORY, useValue: {} },
        { provide: BYMAX_AUTH_HOOKS, useValue: null }
      ]
    }).compile()
    service = moduleRef.get(SessionService)
  })

  /** The hashes a listing marks as current. */
  async function marked(
    by: Pick<ListSessionsParams, 'currentSessionHash' | 'currentSessionId'>
  ): Promise<string[]> {
    const listed = await service.listSessions({ userId: 'u1', tenantId: 't1', ...by })
    return listed.filter((s) => s.isCurrent).map((s) => s.sessionHash)
  }

  /** The refresh records the listing read. */
  const recordReads = (): string[] =>
    redis.get.mock.calls.map(([key]) => key as string).filter((key) => key.startsWith('rt:'))

  it('marks every listed session of the family the identifier names', async () => {
    await expect(marked({ currentSessionId: MINE })).resolves.toEqual([A, C])
  })

  it('reads one refresh record per listed session for that', async () => {
    await marked({ currentSessionId: MINE })

    expect(recordReads()).toEqual([`rt:${A}`, `rt:${B}`, `rt:${C}`])
  })

  it('lets the refresh token decide, and reads no refresh record', async () => {
    await expect(marked({ currentSessionHash: B, currentSessionId: MINE })).resolves.toEqual([B])
    expect(recordReads()).toEqual([])
  })

  it('marks nothing for a refresh token that names no listed session', async () => {
    const unknown = { currentSessionHash: 'f'.repeat(64), currentSessionId: MINE }

    await expect(marked(unknown)).resolves.toEqual([])
  })

  it.each([
    ['no identifier', undefined],
    ['an empty identifier', ''],
    ['a value that is not an identifier', 'not-a-session-id']
  ])('marks nothing and reads no refresh record for %s', async (_name, currentSessionId) => {
    await expect(marked({ currentSessionId })).resolves.toEqual([])
    expect(recordReads()).toEqual([])
  })

  it.each([
    ['carries no family', record()],
    ['is not JSON', '{'],
    ['is JSON null', 'null']
  ])('does not mark a session whose refresh record %s', async (_name, stored) => {
    records.set(`rt:${A}`, stored)

    await expect(marked({ currentSessionId: MINE })).resolves.toEqual([C])
  })

  it('does not mark a session whose refresh record is gone', async () => {
    records.delete(`rt:${A}`)

    await expect(marked({ currentSessionId: MINE })).resolves.toEqual([C])
  })

  it('rejects the listing when a refresh record cannot be read', async () => {
    const fault = new Error('read failed')
    redis.get.mockImplementation(async (key: string) => {
      if (key === `rt:${B}`) throw fault
      return key.startsWith('sd:') ? detail : record(MINE)
    })

    await expect(marked({ currentSessionId: MINE })).rejects.toBe(fault)
  })
})
