/**
 * @fileoverview Unit tests for the entry that ends one session's access tokens.
 *
 * @layer Test
 */

import {
  logoutAccessWrites,
  revokeSessionAccess,
  sessionRevocationTtlSeconds
} from './session-access'

const familyId = '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b'

describe('revokeSessionAccess', () => {
  // Scenario: each plane. Expected: its own key, value 1, a lifetime past the access token's.
  it.each([
    ['dashboard' as const, 'rvs'],
    ['platform' as const, 'prvs']
  ])('writes the %s entry', async (plane, prefix) => {
    const set = jest.fn(async () => undefined)

    await revokeSessionAccess({ set }, plane, familyId, '1h')

    expect(set.mock.calls).toEqual([[`${prefix}:${familyId}`, '1', 3660]])
  })

  // Scenario: a record with no family, or one no token could carry. Expected: nothing written.
  it.each([undefined, '', 'family:1', 7])('writes nothing for %p', async (value) => {
    const set = jest.fn(async () => undefined)

    await revokeSessionAccess({ set }, 'dashboard', value, '15m')

    expect(set).not.toHaveBeenCalled()
  })
})

describe('sessionRevocationTtlSeconds', () => {
  // Scenario: a span with a fraction of a second. Expected: rounded up, plus the margin.
  it('rounds the access lifetime up and adds a minute', () => {
    expect([sessionRevocationTtlSeconds('900s'), sessionRevocationTtlSeconds('1500ms')]).toEqual([
      960, 62
    ])
  })

  // Scenario: a span the converter cannot read. Expected: the margin alone. The module refuses such
  // a configuration at startup.
  it('answers the margin for a span it cannot read', () => {
    expect(sessionRevocationTtlSeconds('soon')).toBe(60)
  })
})

describe('logoutAccessWrites', () => {
  const ended = { plane: 'dashboard' as const, familyId, accessExpiresIn: '5m' }
  const now = (): number => Math.floor(Date.now() / 1000)

  /** The writes made when `verify` answers as given. */
  async function written(verify: () => { jti: string; exp: number }): Promise<unknown[]> {
    const set = jest.fn(async () => undefined)
    for (const write of logoutAccessWrites({ set }, ended, verify)) await write()
    return set.mock.calls
  }

  beforeEach(() => jest.useFakeTimers({ now: 1_000_000_000 }))
  afterEach(() => jest.useRealTimers())

  // Scenario: a live token. Expected: its blacklist entry first, then the session's entry.
  it('blacklists a live token and ends its session', async () => {
    await expect(written(() => ({ jti: 'j', exp: now() + 1 }))).resolves.toEqual([
      ['rv:j', '1', 1],
      [`rvs:${familyId}`, '1', 360]
    ])
  })

  // Scenario: a token at its expiry, and one that does not verify. Expected: the session still ends.
  it.each([
    ['expired', () => ({ jti: 'j', exp: now() })],
    [
      'unverifiable',
      (): never => {
        throw new Error('bad signature')
      }
    ]
  ])('ends the session when the token is %s', async (_case, verify) => {
    await expect(written(verify)).resolves.toEqual([[`rvs:${familyId}`, '1', 360]])
  })
})
