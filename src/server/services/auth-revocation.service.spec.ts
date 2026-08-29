/**
 * Unit tests for AuthRevocationService.
 *
 * Layer: unit.
 * Goal: prove the one revocation check the three JWT guards delegate to, and that a consumer can
 * inject — a token is revoked when it is on the per-token blacklist, or when its stamped epoch
 * predates the user's current one, across both the dashboard and platform planes. The two channels
 * are independent, so each is proven to revoke on its own. A dashboard payload with no tenant is
 * a third path: it fails closed without reading the store, and says so in the log.
 * Mocks: a hand-built AuthRedisService exposing only the two reads this service performs, and a
 * spy over the Nest logger.
 */
import { Logger } from '@nestjs/common'

import { AuthRevocationService } from './auth-revocation.service'
import type { RevocableTokenPayload } from './auth-revocation.service'
import type { AuthRedisService } from '../redis/auth-redis.service'

/** A verified dashboard token payload the check reads. */
const PAYLOAD: RevocableTokenPayload = {
  jti: 'jti-1',
  sub: 'user-1',
  tenantId: 'tenant-1',
  epoch: 3
}

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
  /** Silences the Nest logger and captures the one warn this service emits. */
  let warn: jest.SpyInstance

  beforeEach(() => {
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    warn.mockRestore()
  })

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

    expect(getUserTokenEpoch).toHaveBeenCalledWith('user-1', 'tenant-1', 'platform')
  })

  /**
   * Default plane.
   * Rule: with no kind given, the dashboard epoch is read — the plane an ordinary user token uses.
   */
  it('defaults to the dashboard plane', async () => {
    const { service, getUserTokenEpoch } = buildService({ blacklist: null, epoch: 0 })

    await service.isAccessTokenRevoked(PAYLOAD)

    expect(getUserTokenEpoch).toHaveBeenCalledWith('user-1', 'tenant-1', 'dashboard')
  })

  /**
   * Fail-closed on a dashboard payload with no tenant.
   * Rule: the epoch key is derived from the tenant-scoped subject, and an absent tenant
   * interpolates as the literal `undefined` — a keyspace belonging to no tenant, where nothing has
   * ever been bumped. Reading it answers 0, `stamped < 0` is false for every token, and a
   * bulk-revoked token would be reported VALID. This service is exported for callers that never
   * pass a guard, and `tenantId` is optional in its public payload type, so the omission is a
   * shape a caller can actually produce.
   */
  it.each([
    ['undefined', undefined],
    ['empty', '']
  ])('treats a dashboard token with a %s tenant as revoked', async (_label, tenantId) => {
    const { service, get, getUserTokenEpoch } = buildService({ blacklist: null, epoch: 0 })

    await expect(service.isAccessTokenRevoked({ ...PAYLOAD, tenantId }, 'dashboard')).resolves.toBe(
      true
    )

    // And it never reaches the store: there is no key worth reading for a subject it cannot name,
    // and the check runs ahead of the blacklist read rather than behind it — which is what makes
    // "without a store read" true of this path and the warn fire for every such call, blacklisted
    // or not.
    expect(getUserTokenEpoch).not.toHaveBeenCalled()
    expect(get).not.toHaveBeenCalled()
  })

  /**
   * The fail-closed refusal is announced.
   * Rule: this branch answers the same `true` a genuinely revoked token answers, throws nothing
   * and reads nothing, so without a log it is indistinguishable from a working revocation — the
   * shape that cost a consumer's realtime bridge twenty minutes of bisecting behind a green
   * type-check and a green unit suite. Every part is asserted because a message carrying only
   * some of them sends the reader back to the transport: what happened, which field is missing,
   * what the caller must do, and that the refusal is deliberate rather than a library bug.
   */
  it.each([
    ['undefined', undefined],
    ['empty', '']
  ])(
    'warns naming the missing tenant when a dashboard token has a %s one',
    async (_l, tenantId) => {
      const { service } = buildService({ blacklist: null, epoch: 0 })

      await service.isAccessTokenRevoked({ ...PAYLOAD, tenantId }, 'dashboard')

      expect(warn).toHaveBeenCalledTimes(1)
      const message = String(warn.mock.calls[0]?.[0])

      expect(message).toContain('dashboard token refused')
      expect(message).toContain('no tenantId')
      expect(message).toContain('Forward the tenant')
      expect(message).toContain('fails closed by design')

      // No identifier reaches the log: `sub` names an account and `jti` a live token.
      expect(message).not.toContain(PAYLOAD.sub)
      expect(message).not.toContain(PAYLOAD.jti)
    }
  )

  /**
   * The warn does not depend on the token's luck.
   * Rule: the missing tenant is a caller bug whether or not that particular token happens to sit
   * on the blacklist. Behind the blacklist read, a bridge calling this wrongly on every request
   * would be heard only for the tokens nobody had logged out — the diagnostic would come and go
   * with unrelated state.
   */
  it('warns for a tenantless dashboard token that is also blacklisted', async () => {
    const { service, get } = buildService({ blacklist: '1' })

    await expect(
      service.isAccessTokenRevoked({ ...PAYLOAD, tenantId: undefined }, 'dashboard')
    ).resolves.toBe(true)

    expect(warn).toHaveBeenCalledTimes(1)
    expect(get).not.toHaveBeenCalled()
  })

  /**
   * The warn is scoped to the malformed input.
   * Rule: a token revoked through either real channel is the mechanism working, not a caller bug.
   * Warning there would put a line in the log on every logout and every bulk revocation, which
   * is how a diagnostic becomes noise nobody reads.
   */
  it.each([
    ['the blacklist', { blacklist: '1', epoch: 0 }],
    ['the epoch channel', { blacklist: null, epoch: 9 }]
  ])('stays silent for a token revoked through %s', async (_label, overrides) => {
    const { service } = buildService(overrides)

    await expect(service.isAccessTokenRevoked(PAYLOAD)).resolves.toBe(true)
    expect(warn).not.toHaveBeenCalled()
  })

  /**
   * The platform plane is unaffected.
   * Rule: platform admins are cross-tenant and their subject carries no tenant segment, so an
   * absent tenant there is the normal shape rather than a malformed one. Guarding both planes
   * with one rule would refuse every platform check.
   */
  it('still reads the epoch for a platform token with no tenant', async () => {
    const { service, getUserTokenEpoch } = buildService({ blacklist: null, epoch: 0 })

    await expect(
      service.isAccessTokenRevoked({ ...PAYLOAD, tenantId: undefined }, 'platform')
    ).resolves.toBe(false)

    expect(getUserTokenEpoch).toHaveBeenCalledWith('user-1', undefined, 'platform')
  })
})
