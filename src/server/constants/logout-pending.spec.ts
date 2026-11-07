/**
 * @fileoverview Tests for the retry marker's key and lifetime rule.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  LOGOUT_PENDING_MIN_TTL_SECONDS,
  logoutPendingKey,
  logoutPendingTtlSeconds
} from './logout-pending'

describe('logoutPendingKey', () => {
  const hash = 'a'.repeat(64)

  // The two planes keep separate keyspaces, because their ids come from different repositories.
  it('names the dashboard marker lp:{hash} and the platform marker plp:{hash}', () => {
    expect(logoutPendingKey('dashboard', hash)).toBe(`lp:${hash}`)
    expect(logoutPendingKey('platform', hash)).toBe(`plp:${hash}`)
  })
})

describe('logoutPendingTtlSeconds', () => {
  // The marker lives as long as a retry still has an access token to revoke, and never less than
  // the five-minute floor.
  it.each([
    ['a lifetime above the floor', '15m', 900],
    ['an hour', '1h', 3600],
    ['seconds', '900s', 900],
    ['a fractional span, rounded up', '1.5h', 5400],
    ['a lifetime below the floor', '1m', LOGOUT_PENDING_MIN_TTL_SECONDS],
    ['exactly the floor', '300s', LOGOUT_PENDING_MIN_TTL_SECONDS]
  ])('is %s: %s gives %i seconds', (_name, lifetime, expected) => {
    expect(logoutPendingTtlSeconds(lifetime)).toBe(expected)
  })

  it('falls back to the floor when no lifetime is configured or it cannot be read', () => {
    expect(logoutPendingTtlSeconds(undefined)).toBe(LOGOUT_PENDING_MIN_TTL_SECONDS)
    expect(logoutPendingTtlSeconds('soon')).toBe(LOGOUT_PENDING_MIN_TTL_SECONDS)
  })

  // A lifetime that is not a whole number of seconds is rounded up, never down: the marker must
  // outlive the access token it was written for.
  it('rounds a lifetime up to a whole second', () => {
    expect(logoutPendingTtlSeconds('7.0001m')).toBe(421)
  })
})

describe('the shared wire contract', () => {
  const contract = JSON.parse(
    readFileSync(join(__dirname, '../../../conformance/wire-contract.json'), 'utf8')
  ) as {
    redisKeyPrefixes: Record<string, string>
    recordEncodings: Record<string, { fields: string[]; ttl: string }>
  }

  // The prefixes and the lifetime floor the contract names are the ones the code writes, so the
  // two libraries that read the same marker cannot drift apart on either.
  it('names the marker prefixes and the lifetime floor the code uses', () => {
    const hash = 'b'.repeat(64)

    expect(`${contract.redisKeyPrefixes['dashboardLogoutPending']}:${hash}`).toBe(
      logoutPendingKey('dashboard', hash)
    )
    expect(`${contract.redisKeyPrefixes['platformLogoutPending']}:${hash}`).toBe(
      logoutPendingKey('platform', hash)
    )
    expect(contract.recordEncodings['logoutPending']?.fields).toEqual(['userId', 'tenantId'])
    expect(contract.recordEncodings['logoutPending']?.ttl).toContain(
      `never less than ${LOGOUT_PENDING_MIN_TTL_SECONDS}`
    )
  })
})
