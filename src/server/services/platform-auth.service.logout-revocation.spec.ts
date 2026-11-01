/**
 * PlatformAuthService.logout — what a refused revocation write does.
 *
 * Logout is a promise that the administrator's credentials stop working. It writes the access-token
 * blacklist entry, the refresh session and its rotation grace pointer, and prunes the session index.
 * When the store refuses a write, answering success would claim a revocation that did not happen,
 * so every write is attempted and the first failure is raised after the rest have run. Kept apart
 * from `platform-auth.service.spec.ts` because it is a separate responsibility.
 */

import { createHash } from 'node:crypto'

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { BruteForceService } from './brute-force.service'
import { PasswordService } from './password.service'
import { PlatformAuthService } from './platform-auth.service'
import { TokenManagerService } from './token-manager.service'

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const RAW_REFRESH = 'raw-platform-refresh-token'
const HASH = createHash('sha256').update(RAW_REFRESH).digest('hex')
const JTI = 'platform-jti-under-test'
const ADMIN_ID = 'admin-1'

const mockRedis = { readSessionOwner: jest.fn(), set: jest.fn(), del: jest.fn(), srem: jest.fn() }
const mockTokenManager = { verifyPlatformIgnoringExpiry: jest.fn() }
const mockHooks = { afterPlatformLogout: jest.fn() }

const mockOptions = {
  jwt: { secret: JWT_SECRET },
  hmacKey: HMAC_KEY,
  previousHmacKeys: []
}

/** What a store under memory pressure answers to a write it refuses. */
const STORE_REFUSED = new Error('OOM command not allowed when used memory > maxmemory')
const OTHER_REFUSAL = new Error('READONLY You can not write against a read only replica')

/** Lets a fire-and-forget hook settle before the assertion reads it. */
async function flushMicrotasks(ticks = 4): Promise<void> {
  for (let i = 0; i < ticks; i += 1) await Promise.resolve()
}

describe('PlatformAuthService.logout — refused revocation writes', () => {
  let service: PlatformAuthService

  beforeEach(async () => {
    jest.resetAllMocks()
    mockRedis.readSessionOwner.mockResolvedValue({ userId: ADMIN_ID, tenantId: undefined })
    mockRedis.set.mockResolvedValue(undefined)
    mockRedis.del.mockResolvedValue(undefined)
    mockRedis.srem.mockResolvedValue(1)
    mockHooks.afterPlatformLogout.mockResolvedValue(undefined)
    mockTokenManager.verifyPlatformIgnoringExpiry.mockReturnValue({
      jti: JTI,
      sub: ADMIN_ID,
      exp: Math.floor(Date.now() / 1000) + 900
    })

    const module = await Test.createTestingModule({
      providers: [
        PlatformAuthService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: {} },
        { provide: PasswordService, useValue: {} },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: BruteForceService, useValue: {} },
        { provide: AuthRedisService, useValue: mockRedis },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks }
      ]
    }).compile()
    service = module.get(PlatformAuthService)
  })

  // Scenario: the store refuses the blacklist write but serves everything else. Expected: logout
  // rejects with that refusal, and the refresh key, its grace pointer, the index entries and the
  // session detail are still removed. Why: answering success would tell the administrator their
  // access token no longer works while it does, and stopping at the first failure would leave the
  // seven-day refresh session of the highest-privilege identity alive as well.
  it('should reject with the refusal and still remove the refresh session when the blacklist write is refused', async () => {
    mockRedis.set.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.del).toHaveBeenCalledWith(`prt:${HASH}`)
    expect(mockRedis.del).toHaveBeenCalledWith(`prp:${HASH}`)
    expect(mockRedis.del).toHaveBeenCalledWith(`psd:${HASH}`)
    expect(mockRedis.srem).toHaveBeenCalledTimes(2)
  })

  // Scenario: the store refuses the refresh-key delete. Expected: logout rejects, the blacklist
  // entry and the grace pointer were still attempted, and nothing that points at the refresh key is
  // pruned: its index member stays and its session detail stays. Why: the credential is still live,
  // and the revoke-all sweep ends only the sessions the index names, so a member dropped while its
  // credential survives is a session "sign out everywhere" can no longer reach.
  it('should reject, attempt the other credential writes, and keep the index member of the refresh key it could not delete', async () => {
    mockRedis.del.mockImplementation((key: string) =>
      key === `prt:${HASH}` ? Promise.reject(STORE_REFUSED) : Promise.resolve(undefined)
    )

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.set).toHaveBeenCalledWith(`rv:${JTI}`, '1', expect.any(Number))
    expect(mockRedis.del).toHaveBeenCalledWith(`prp:${HASH}`)
    expect(mockRedis.srem).not.toHaveBeenCalledWith(expect.any(String), `prt:${HASH}`)
    expect(mockRedis.del).not.toHaveBeenCalledWith(`psd:${HASH}`)
    expect(mockRedis.srem).toHaveBeenCalledWith(expect.any(String), `prp:${HASH}`)
  })

  // Scenario: the store refuses the rotation grace pointer delete. Expected: logout rejects, the
  // grace pointer's index member stays (it is still live, and a grace hit mints a fresh session), and
  // the refresh key's own delete, prune and session detail still run.
  it('should reject and keep the index member of the grace pointer it could not delete', async () => {
    mockRedis.del.mockImplementation((key: string) =>
      key === `prp:${HASH}` ? Promise.reject(STORE_REFUSED) : Promise.resolve(undefined)
    )

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.srem).not.toHaveBeenCalledWith(expect.any(String), `prp:${HASH}`)
    expect(mockRedis.del).toHaveBeenCalledWith(`prt:${HASH}`)
    expect(mockRedis.srem).toHaveBeenCalledWith(expect.any(String), `prt:${HASH}`)
    expect(mockRedis.del).toHaveBeenCalledWith(`psd:${HASH}`)
  })

  // Scenario: the store refuses an index prune. Expected: logout rejects after attempting the rest.
  it('should reject and still attempt the session detail delete when an index prune is refused', async () => {
    mockRedis.srem.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.srem).toHaveBeenCalledTimes(2)
    expect(mockRedis.del).toHaveBeenCalledWith(`psd:${HASH}`)
  })

  // Scenario: more than one write is refused. Expected: the FIRST refusal is the one raised, in the
  // order the writes are made, so the error does not depend on which failure settled last.
  it('should raise the first refusal when several writes are refused', async () => {
    mockRedis.set.mockRejectedValue(STORE_REFUSED)
    mockRedis.del.mockRejectedValue(OTHER_REFUSAL)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    // The refresh key and the grace pointer; with both refused, nothing that follows from them runs.
    expect(mockRedis.del).toHaveBeenCalledTimes(2)
  })

  // Scenario: a refused logout. Expected: the logout hook does not fire, because that logout did
  // not complete.
  it('should not announce a logout that did not complete', async () => {
    mockRedis.set.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)
    await flushMicrotasks()

    expect(mockHooks.afterPlatformLogout).not.toHaveBeenCalled()
  })

  // Scenario: the same logout again once the store accepts writes. Expected: it completes and
  // writes the blacklist entry; a retry is idempotent.
  it('should complete a retried logout once the store accepts writes again', async () => {
    mockRedis.set.mockRejectedValueOnce(STORE_REFUSED)
    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe(ADMIN_ID)

    expect(mockRedis.set).toHaveBeenCalledTimes(2)
    expect(mockRedis.set).toHaveBeenLastCalledWith(`rv:${JTI}`, '1', expect.any(Number))
  })

  // Scenario: the blacklist write is refused on the first attempt, which still deletes the refresh
  // session, and the retry then finds no session to name an owner. Expected: neither call fires the
  // logout hook. Why: the hook is fired by the call that names the owner; this pins the documented
  // gap so it cannot change unnoticed.
  it('should deliver the logout hook on neither the failed attempt nor the retry that completes it', async () => {
    mockRedis.set.mockRejectedValueOnce(STORE_REFUSED)
    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)
    mockRedis.readSessionOwner.mockResolvedValue({ userId: '', tenantId: undefined })

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('')
    await flushMicrotasks()

    expect(mockHooks.afterPlatformLogout).not.toHaveBeenCalled()
  })

  // Scenario: the access token cannot be verified. Expected: no blacklist write, and logout still
  // completes. Why: that is not a store failure, and the refresh session is revoked either way.
  it('should still complete when the access token cannot be verified', async () => {
    mockTokenManager.verifyPlatformIgnoringExpiry.mockImplementation(() => {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    await expect(service.logout('garbage', RAW_REFRESH)).resolves.toBe(ADMIN_ID)

    expect(mockRedis.set).not.toHaveBeenCalled()
    expect(mockRedis.del).toHaveBeenCalledWith(`prt:${HASH}`)
  })

  // Scenario: the store cannot answer the read that names the session's owner. Expected: logout
  // rejects before any write; reads stay fail-closed.
  it('should reject before any write when the owner cannot be read', async () => {
    mockRedis.readSessionOwner.mockRejectedValue(STORE_REFUSED)

    await expect(service.logout('access.jwt', RAW_REFRESH)).rejects.toBe(STORE_REFUSED)

    expect(mockRedis.set).not.toHaveBeenCalled()
    expect(mockRedis.del).not.toHaveBeenCalled()
    expect(mockRedis.srem).not.toHaveBeenCalled()
  })

  // Scenario: a session that is already gone (no owner on record). Expected: logout completes and
  // prunes no index, as before.
  it('should complete without pruning an index when no session names an owner', async () => {
    mockRedis.readSessionOwner.mockResolvedValue({ userId: '', tenantId: undefined })

    await expect(service.logout('access.jwt', RAW_REFRESH)).resolves.toBe('')

    expect(mockRedis.srem).not.toHaveBeenCalled()
  })
})
