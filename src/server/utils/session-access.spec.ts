/**
 * @fileoverview Unit tests for the entry that ends one session's access tokens.
 *
 * @layer Test
 */

import {
  endSignIn,
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

/** What `revokeFamily` answers for a family naming these sessions. */
const family = (sessionHashes: string[]) => ({
  removed: sessionHashes.length,
  sessionHashes,
  ownerId: 'u1',
  tenantId: 't1'
})

describe('endSignIn', () => {
  // Scenario: a family on each plane. Expected: its sessions removed first, then the entry written,
  // and the sessions it named answered.
  it.each([
    ['dashboard' as const, 'rvs'],
    ['platform' as const, 'prvs']
  ])('removes the %s sessions before writing the entry', async (plane, prefix) => {
    const set = jest.fn(async () => undefined)
    const revokeFamily = jest.fn(async () => family(['a', 'b']))

    const removed = jest.fn()

    await endSignIn({ set, revokeFamily }, plane, familyId, '5m', removed)

    expect(removed.mock.calls).toEqual([[['a', 'b']]])

    expect(revokeFamily.mock.calls).toEqual([[familyId, plane]])
    expect(set.mock.calls).toEqual([[`${prefix}:${familyId}`, '1', 360]])
    expect(revokeFamily.mock.invocationCallOrder[0]).toBeLessThan(
      set.mock.invocationCallOrder[0] ?? 0
    )
  })

  // Scenario: a record with no family a token could carry. Expected: nothing removed or written.
  it.each([undefined, '', 'family:1', 7])('does nothing for %p', async (value) => {
    const set = jest.fn(async () => undefined)
    const revokeFamily = jest.fn(async () => family(['a']))
    const removed = jest.fn()

    await endSignIn({ set, revokeFamily }, 'dashboard', value, '5m', removed)

    expect([revokeFamily.mock.calls, set.mock.calls, removed.mock.calls]).toEqual([[], [], []])
  })
})

describe('logoutAccessWrites', () => {
  // Scenario: the sessions are removed and the entry refused. Expected: still told what was removed,
  // then the refusal raised.
  it('tells what was removed when the entry is refused', async () => {
    const set = jest.fn(async (): Promise<void> => Promise.reject(new Error('READONLY')))
    const revokeFamily = jest.fn(async () => family(['h', 'sibling']))
    const told = jest.fn()
    const writes = logoutAccessWrites(
      { set, revokeFamily },
      { plane: 'dashboard', familyId, accessExpiresIn: '5m', ended: told },
      () => {
        throw new Error('bad signature')
      }
    )

    await expect(writes[0]?.()).rejects.toThrow('READONLY')

    expect(told.mock.calls).toEqual([[['h', 'sibling']]])
  })

  const ended = { plane: 'dashboard' as const, familyId, accessExpiresIn: '5m' }
  const now = (): number => Math.floor(Date.now() / 1000)

  /** The writes made when `verify` answers as given. */
  async function written(verify: () => { jti: string; exp: number }): Promise<unknown[]> {
    const set = jest.fn(async () => undefined)
    const revokeFamily = jest.fn(async () => family(['h']))
    const told = jest.fn()
    const session = { ...ended, ended: told }
    for (const write of logoutAccessWrites({ set, revokeFamily }, session, verify)) await write()
    expect(told.mock.calls).toEqual([[['h']]])
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
