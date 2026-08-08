/**
 * Unit tests for AuthRevocationService.
 *
 * Layer: unit.
 * Goal: prove the one revocation check the three JWT guards delegate to, and that a consumer can
 * inject — a token is revoked when it is on the per-token blacklist, or when its stamped epoch
 * predates the user's current one, across both the dashboard and platform planes. The two channels
 * are independent, so each is proven to revoke on its own.
 * Mocks: a hand-built AuthRedisService exposing only the two reads this service performs.
 */
import { AuthRevocationService } from './auth-revocation.service'
import type { RevocableTokenPayload } from './auth-revocation.service'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** A verified dashboard token payload the check reads. */
const PAYLOAD: RevocableTokenPayload = { jti: 'jti-1', sub: 'user-1', epoch: 3 }

/** Builds the service over a redis stub with the two reads it uses, defaulted to "not revoked". */
function buildService(overrides?: { blacklist?: string | null; epoch?: number }): {
  service: AuthRevocationService
  get: jest.Mock
  getUserTokenEpoch: jest.Mock
} {
  const get = jest.fn().mockResolvedValue(overrides?.blacklist ?? null)
  const getUserTokenEpoch = jest.fn().mockResolvedValue(overrides?.epoch ?? 0)
  const redis = { get, getUserTokenEpoch } as unknown as AuthRedisService
  return { service: new AuthRevocationService(redis), get, getUserTokenEpoch }
}

describe('AuthRevocationService', () => {
  /**
   * Not-revoked baseline.
   * Rule: an empty blacklist and a user epoch at or below the token's stamp is not revoked.
   */
  it('reports a token that neither channel revokes as valid', async () => {
    const { service } = buildService({ blacklist: null, epoch: 3 })

    await expect(service.isAccessTokenRevoked(PAYLOAD)).resolves.toBe(false)
  })

  /**
   * Per-token blacklist.
   * Rule: a hit on `rv:{jti}` revokes, and short-circuits before the epoch lookup — a logged-out
   * token is revoked whatever the user's epoch is.
   */
  it('revokes a token present on the blacklist without consulting the epoch', async () => {
    const { service, get, getUserTokenEpoch } = buildService({ blacklist: '1' })

    await expect(service.isAccessTokenRevoked(PAYLOAD)).resolves.toBe(true)
    expect(get).toHaveBeenCalledWith('rv:jti-1')
    expect(getUserTokenEpoch).not.toHaveBeenCalled()
  })

  /**
   * Bulk epoch channel.
   * Rule: a token stamped below the user's current epoch is revoked, so one bump invalidates every
   * outstanding access token even with an empty blacklist.
   */
  it('revokes a token stamped below the current user epoch', async () => {
    const { service } = buildService({ blacklist: null, epoch: 4 })

    await expect(service.isAccessTokenRevoked({ ...PAYLOAD, epoch: 3 })).resolves.toBe(true)
  })

  /**
   * Epoch boundary.
   * Rule: a token stamped exactly at the current epoch is not revoked — only a strictly older
   * stamp is, so the bump does not sign out the very tokens issued at the new epoch.
   */
  it('does not revoke a token stamped exactly at the current epoch', async () => {
    const { service } = buildService({ blacklist: null, epoch: 3 })

    await expect(service.isAccessTokenRevoked({ ...PAYLOAD, epoch: 3 })).resolves.toBe(false)
  })

  /**
   * Plane selection.
   * Rule: the `kind` argument chooses the epoch namespace, so a platform token is compared against
   * the platform epoch. The blacklist read is shared across planes.
   */
  it('reads the epoch of the plane named by kind', async () => {
    const { service, getUserTokenEpoch } = buildService({ blacklist: null, epoch: 0 })

    await service.isAccessTokenRevoked(PAYLOAD, 'platform')

    expect(getUserTokenEpoch).toHaveBeenCalledWith('user-1', 'platform')
  })

  /**
   * Default plane.
   * Rule: with no kind given, the dashboard epoch is read — the plane an ordinary user token uses.
   */
  it('defaults to the dashboard plane', async () => {
    const { service, getUserTokenEpoch } = buildService({ blacklist: null, epoch: 0 })

    await service.isAccessTokenRevoked(PAYLOAD)

    expect(getUserTokenEpoch).toHaveBeenCalledWith('user-1', 'dashboard')
  })
})
