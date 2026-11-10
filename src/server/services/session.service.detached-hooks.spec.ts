/**
 * @fileoverview SessionService — a host hook that throws synchronously during session creation.
 *
 * `onNewSession` and `onSessionEvicted` run while a session is being created. The session is
 * already written, so a throw that escaped (from the eviction loop) would fail a login that
 * succeeded, and one swallowed by an unrelated handler (inside the account read) would be logged as
 * a repository failure. Each hook's failure must be logged under its own name and creation must
 * still answer. Kept apart from `session.service.spec.ts` because that file is over the size limit.
 *
 * @layer Test
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'

import { SessionService } from './session.service'
import type { ResolvedOptions } from '../config/resolved-options'

const USER = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const PARAMS = {
  userId: 'user-1',
  tenantId: 'tenant-1',
  rawRefreshToken: 'raw-refresh',
  ip: '1.2.3.4',
  userAgent: 'jest'
}

/** A service over mocks; `members` are the refresh sessions the index already holds. */
function build(hooks: Record<string, jest.Mock>, members: string[]): SessionService {
  const options = Object.assign({} as ResolvedOptions, {
    jwt: { refreshExpiresInDays: 7 },
    hmacKey: 'test-hmac-key',
    previousHmacKeys: [],
    sessions: { enabled: true, defaultMaxSessions: 1 }
  })
  const redis = {
    set: jest.fn().mockResolvedValue(undefined),
    pruneExpiredGraceMembers: jest.fn().mockResolvedValue(undefined),
    smembers: jest.fn().mockResolvedValue(members),
    get: jest.fn().mockResolvedValue(null),
    del: jest.fn().mockResolvedValue(true),
    srem: jest.fn().mockResolvedValue(1)
  }
  const userRepo = { findById: jest.fn().mockResolvedValue(USER) }
  return new SessionService(options, userRepo as never, hooks as never, redis as never)
}

/** Lets the detached tasks run. */
async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve))
}

describe('SessionService with a hook that throws synchronously', () => {
  let error: jest.SpyInstance

  beforeEach(() => {
    error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('still creates the session, and logs onNewSession under its own name', async () => {
    const hooks = {
      onNewSession: jest.fn(() => {
        throw new Error('hook broke')
      })
    }
    const service = build(hooks, [])

    await expect(service.createSession(PARAMS)).resolves.toEqual(expect.any(String))
    await flush()

    expect(error).toHaveBeenCalledWith(expect.stringContaining('onNewSession hook threw'))
    expect(error).not.toHaveBeenCalledWith(expect.stringContaining('findById failed'))
  })

  it('still creates the session, and logs onSessionEvicted', async () => {
    const hooks = {
      onSessionEvicted: jest.fn(() => {
        throw new Error('hook broke')
      })
    }
    const created = `rt:${createHash('sha256').update(PARAMS.rawRefreshToken, 'utf8').digest('hex')}`
    const service = build(hooks, ['rt:old-session', created])

    await expect(service.createSession(PARAMS)).resolves.toEqual(expect.any(String))
    await flush()

    expect(error).toHaveBeenCalledWith(expect.stringContaining('onSessionEvicted hook threw'))
  })
})
