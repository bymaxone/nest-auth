/**
 * AuthService.logout — what a refused revocation write does.
 *
 * Logout is a promise that the caller's credentials stop working. It writes three things that keep
 * that promise: the access-token blacklist entry, the refresh session and its rotation grace
 * pointer. When the store refuses one of them, answering success would claim a revocation that did
 * not happen, so every write is attempted and the first failure is raised after the rest have run.
 * Kept apart from `auth.service.spec.ts` because it is a separate responsibility and that file is
 * already over the size limit.
 */

import { createHash } from 'node:crypto'

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AccountStatusService } from './account-status.service'
import { AuthService } from './auth.service'
import { BruteForceService } from './brute-force.service'
import { OtpService } from './otp.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const RAW_REFRESH = 'raw-refresh-token'
const HASH = createHash('sha256').update(RAW_REFRESH).digest('hex')
const JTI = 'jti-under-test'

const mockRedis = { readSessionOwner: jest.fn(), set: jest.fn(), del: jest.fn() }
const mockTokenManager = { verifyIgnoringExpiry: jest.fn() }
const mockSessionService = { revokeSession: jest.fn() }
const mockHooks = { afterLogout: jest.fn() }

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: [],
  sessions: { enabled: true, defaultMaxSessions: 5, evictionStrategy: 'fifo' }
}

/** What a store under memory pressure answers to a write it refuses. */
const STORE_REFUSED = new Error('OOM command not allowed when used memory > maxmemory')
const OTHER_REFUSAL = new Error('READONLY You can not write against a read only replica')

/** Lets a fire-and-forget hook settle before the assertion reads it. */
async function flushMicrotasks(ticks = 4): Promise<void> {
  for (let i = 0; i < ticks; i += 1) await Promise.resolve()
}

describe('AuthService.logout — refused revocation writes', () => {
  let service: AuthService

  beforeEach(async () => {
    jest.resetAllMocks()
    mockRedis.readSessionOwner.mockResolvedValue({ userId: 'user-1', tenantId: 'tenant-1' })
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(undefined)
    mockSessionService.revokeSession.mockResolvedValue(undefined)
    mockHooks.afterLogout.mockResolvedValue(undefined)
    mockTokenManager.verifyIgnoringExpiry.mockReturnValue({
      jti: JTI,
      sub: 'user-1',
      exp: Math.floor(Date.now() / 1000) + 900
    })

    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
        { provide: PasswordService, useValue: {} },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: {} },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: OtpService, useValue: {} },
        { provide: SessionService, useValue: mockSessionService },
        { provide: AccountStatusService, useValue: {} }
      ]
    }).compile()
    service = module.get(AuthService)
  })

  // Scenario: the store refuses the blacklist write but serves everything else. Expected: logout
  // rejects with that refusal, and the refresh key, its grace pointer and the session index entry
  // are still removed. Why: answering success would tell the caller their access token no longer
  // works while it does, and stopping at the first failure would leave the long-lived refresh
  // session alive as well.
  it('should reject with the refusal and still remove the refresh session when the blacklist write is refused', async () => {
    mockRedis.set.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.del).toHaveBeenCalledWith(`rt:${HASH}`)
    expect(mockRedis.del).toHaveBeenCalledWith(`rp:${HASH}`)
    expect(mockSessionService.revokeSession).toHaveBeenCalledTimes(1)
  })

  // Scenario: the store refuses the refresh-key delete. Expected: logout rejects, and the
  // blacklist entry and the grace pointer were still attempted.
  it('should reject and still attempt the other writes when the refresh key delete is refused', async () => {
    mockRedis.del.mockImplementation((key: string) =>
      key === `rt:${HASH}` ? Promise.reject(STORE_REFUSED) : Promise.resolve(undefined)
    )

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.set).toHaveBeenCalledWith(`rv:${JTI}`, '1', expect.any(Number))
    expect(mockRedis.del).toHaveBeenCalledWith(`rp:${HASH}`)
  })

  // Scenario: the store refuses the rotation grace pointer delete. Expected: logout rejects. Why:
  // a pointer left behind lets a rotated-away token mint a fresh session.
  it('should reject when the rotation grace pointer delete is refused', async () => {
    mockRedis.del.mockImplementation((key: string) =>
      key === `rp:${HASH}` ? Promise.reject(STORE_REFUSED) : Promise.resolve(undefined)
    )

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.del).toHaveBeenCalledWith(`rt:${HASH}`)
  })

  // Scenario: more than one write is refused. Expected: the FIRST refusal is the one raised, in the
  // order the writes are made (blacklist, refresh key, grace pointer), so the error does not depend
  // on which of several failures happened to settle last.
  it('should raise the first refusal when several writes are refused', async () => {
    mockRedis.set.mockRejectedValue(STORE_REFUSED)
    mockRedis.del.mockRejectedValue(OTHER_REFUSAL)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.del).toHaveBeenCalledTimes(2)
  })

  // Scenario: a refused logout. Expected: the logout hook does not fire. Why: the hook announces a
  // completed logout, and this one did not complete.
  it('should not announce a logout that did not complete', async () => {
    mockRedis.set.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)
    await flushMicrotasks()

    expect(mockHooks.afterLogout).not.toHaveBeenCalled()
  })

  // Scenario: the same logout again once the store accepts writes. Expected: it completes and
  // writes the blacklist entry. Why: a client that was told the logout failed has to be able to
  // retry it, and a retry is idempotent: deleting absent keys and re-setting the entry is harmless.
  it('should complete a retried logout once the store accepts writes again', async () => {
    mockRedis.set.mockRejectedValueOnce(STORE_REFUSED)
    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('user-1')

    const blacklistWrites = mockRedis.set.mock.calls.filter(([key]) =>
      String(key).startsWith('rv:')
    )
    expect(blacklistWrites).toHaveLength(2)
    expect(mockRedis.set).toHaveBeenLastCalledWith(`rv:${JTI}`, '1', expect.any(Number))
  })

  /**
   * Makes the owner lookup answer by key: the live session `rt:` record and the retry marker `lp:`
   * are different keys, and a retry finds the first gone and the second present.
   */
  function ownerKnownBy(
    sessionOwner: { userId: string; tenantId: string | undefined },
    markerOwner: { userId: string; tenantId: string | undefined }
  ): void {
    mockRedis.readSessionOwner.mockImplementation(async (key: string) =>
      key.startsWith('rt:') ? sessionOwner : markerOwner
    )
  }

  const NO_OWNER = { userId: '', tenantId: undefined }
  const OWNER = { userId: 'user-1', tenantId: 'tenant-1' }

  // Scenario: the blacklist write is refused on the first attempt, which still deletes the refresh
  // session, and the retry finds no session to name an owner. Expected: the failed attempt fires no
  // hook and writes a marker naming the owner and tenant, under the plane's key and with a
  // lifetime of at least five minutes; the retry reads the marker, completes, removes it and fires
  // the hook once for that owner. Why: the retry completed the logout, and only the marker still
  // says whose it was.
  it('should announce the logout on the retry that completes it, for the owner the marker names', async () => {
    mockRedis.set.mockRejectedValueOnce(STORE_REFUSED)
    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)
    await flushMicrotasks()

    expect(mockHooks.afterLogout).not.toHaveBeenCalled()
    expect(mockRedis.set).toHaveBeenCalledWith(
      `lp:${HASH}`,
      JSON.stringify({ userId: 'user-1', tenantId: 'tenant-1' }),
      300
    )

    ownerKnownBy(NO_OWNER, OWNER)
    mockRedis.del.mockResolvedValue(true)
    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('user-1')
    await flushMicrotasks()

    expect(mockRedis.del).toHaveBeenCalledWith(`lp:${HASH}`)
    expect(mockHooks.afterLogout).toHaveBeenCalledTimes(1)
    expect(mockHooks.afterLogout).toHaveBeenCalledWith(
      'user-1',
      expect.objectContaining({ plane: 'dashboard', userId: 'user-1', tenantId: 'tenant-1' })
    )
  })

  // Scenario: a retry that finds the marker already removed, because another retry claimed it.
  // Expected: it completes and answers the owner, and fires nothing. Why: the removal is the claim,
  // and only the caller that removed the marker announces the logout.
  it('should not announce a logout whose marker another retry already claimed', async () => {
    ownerKnownBy(NO_OWNER, OWNER)
    mockRedis.del.mockResolvedValue(false)

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('user-1')
    await flushMicrotasks()

    expect(mockHooks.afterLogout).not.toHaveBeenCalled()
  })

  // Scenario: no session and no marker, a logout nothing had started. Expected: it completes,
  // answers the empty owner, fires nothing and does not touch the marker key. Why: nobody to name.
  it('should stay silent, and leave the marker key alone, when nothing names an owner', async () => {
    ownerKnownBy(NO_OWNER, NO_OWNER)

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('')
    await flushMicrotasks()

    expect(mockHooks.afterLogout).not.toHaveBeenCalled()
    expect(mockRedis.del).not.toHaveBeenCalledWith(`lp:${HASH}`)
  })

  // Scenario: a logout that needed no retry. Expected: no marker is written on the success path, the
  // hook fires once, and a marker left by an earlier failed attempt is removed. Why: the session
  // still existed (the earlier attempt could not delete it), so the owner came from the session and
  // the stale marker must not announce a second time later.
  it('should announce once from the session and clear any stale marker', async () => {
    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('user-1')
    await flushMicrotasks()

    expect(mockRedis.set).not.toHaveBeenCalledWith(
      `lp:${HASH}`,
      expect.anything(),
      expect.anything()
    )
    expect(mockRedis.del).toHaveBeenCalledWith(`lp:${HASH}`)
    expect(mockHooks.afterLogout).toHaveBeenCalledTimes(1)
  })

  // Scenario: the marker cannot be written while the logout is already failing. Expected: the caller
  // still gets the original refusal, not the marker's. Why: the marker is best effort; it must not
  // replace the error the client acts on.
  it('should raise the original refusal when the marker cannot be written', async () => {
    mockRedis.set.mockImplementation(async (key: string) => {
      if (key.startsWith('rv:')) throw STORE_REFUSED
      throw OTHER_REFUSAL
    })

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)
  })

  // Scenario: the marker cannot be removed once the logout has completed. Expected: from the session
  // the logout still announces; from the marker it does not. Why: a refused removal never turns a
  // completed logout into a failure, and with no removal there is no claim.
  it.each([
    ['the session', OWNER, NO_OWNER, 1],
    ['the marker', NO_OWNER, OWNER, 0]
  ])(
    'should complete when the marker cannot be removed and the owner came from %s',
    async (_name, session, marker, announced) => {
      ownerKnownBy(session, marker)
      mockRedis.del.mockImplementation(async (key: string) => {
        if (key.startsWith('lp:')) throw STORE_REFUSED
        return true
      })

      await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('user-1')
      await flushMicrotasks()

      expect(mockHooks.afterLogout).toHaveBeenCalledTimes(announced)
    }
  )

  // Scenario: a marker kept for a retry that fails again. Expected: it is not written a second time
  // from the marker path. Why: the marker is written from the session record only; a retry that has
  // only the marker leaves the existing one to expire.
  it('should not rewrite the marker when a retry that found only the marker fails again', async () => {
    ownerKnownBy(NO_OWNER, OWNER)
    mockRedis.set.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.set).not.toHaveBeenCalledWith(
      `lp:${HASH}`,
      expect.anything(),
      expect.anything()
    )
  })

  // Scenario: the access token cannot be verified (absent, malformed, signed by another secret).
  // Expected: no blacklist write is attempted and logout still completes. Why: that is not a store
  // failure; there is nothing to blacklist, and the refresh session is revoked either way.
  it('should still complete when the access token cannot be verified', async () => {
    mockTokenManager.verifyIgnoringExpiry.mockImplementation(() => {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    await expect(service.logout('garbage', RAW_REFRESH)).resolves.toBe('user-1')

    expect(mockRedis.set).not.toHaveBeenCalled()
    expect(mockRedis.del).toHaveBeenCalledWith(`rt:${HASH}`)
    expect(mockRedis.del).toHaveBeenCalledWith(`rp:${HASH}`)
  })

  // Scenario: the store cannot answer the read that names the session's owner. Expected: logout
  // rejects before any write. Why: with no owner there is nothing safe to revoke, and reads stay
  // fail-closed.
  it('should reject before any write when the owner cannot be read', async () => {
    mockRedis.readSessionOwner.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.set).not.toHaveBeenCalled()
    expect(mockRedis.del).not.toHaveBeenCalled()
  })

  // Scenario: every revocation write succeeds but the session-index cleanup is refused. Expected:
  // logout completes and warns. Why: the credentials are already dead; the index only feeds the
  // sessions list, and that behaviour is unchanged.
  it('should still complete when only the session index cleanup is refused', async () => {
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    mockSessionService.revokeSession.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('user-1')

    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })
})
