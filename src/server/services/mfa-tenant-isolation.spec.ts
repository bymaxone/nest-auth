/**
 * @fileoverview Two tenants may hold the same user id, so every MFA state a user id keys must be
 * keyed by the tenant as well: the transition lock, the TOTP replay marker and the failure counters
 * of the `challenge`, `disable` and `reauth` flows. These cases run the real services over a fake
 * store that keeps state, so a key shared by two tenants shows up as one tenant affecting the other.
 *
 * @layer Test
 */

import { MfaFlowLockoutService, type MfaFlow } from './mfa-flow-lockout.service'
import { MfaRecordService } from './mfa-record.service'
import { generateHotp, generateTotpSecret } from '../crypto/totp'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

const KEY = 'k'.repeat(48)
const OPTIONS = { hmacKey: KEY, blockedStatuses: [] } as const
const FLOWS: readonly MfaFlow[] = ['challenge', 'disable', 'reauth']
const THRESHOLD = 5

/** A brute-force counter store that keeps state: failures per identifier and the lockout at 5. */
class CounterStore {
  readonly counts = new Map<string, number>()

  isLockedOut = (id: string): Promise<boolean> =>
    Promise.resolve((this.counts.get(id) ?? 0) >= THRESHOLD)

  recordFailure = (id: string): Promise<void> => {
    this.counts.set(id, (this.counts.get(id) ?? 0) + 1)
    return Promise.resolve()
  }

  resetFailures = (id: string): Promise<void> => {
    this.counts.delete(id)
    return Promise.resolve()
  }
}

describe('the MFA failure counters across tenants', () => {
  /** The lockout service over a fresh counter store. */
  function lockout(): MfaFlowLockoutService {
    const store = new CounterStore()
    return new MfaFlowLockoutService(OPTIONS as never, store as never)
  }

  // Scenario: user `1` of tenant B fails a flow five times. Expected: user `1` of tenant A is not
  // locked out of that flow, because a tenant-less counter would be one budget for both accounts and
  // let a caller in one tenant lock out an account in another with no credential.
  it.each(FLOWS)(
    'does not lock tenant A out of %s after tenant B fails it five times',
    async (flow) => {
      const service = lockout()

      for (let attempt = 0; attempt < THRESHOLD; attempt += 1) {
        await service.recordFailure(flow, 'dashboard', '1', 'tenant-b')
      }

      await expect(service.isLockedOut(flow, 'dashboard', '1', 'tenant-b')).resolves.toBe(true)
      await expect(service.isLockedOut(flow, 'dashboard', '1', 'tenant-a')).resolves.toBe(false)
    }
  )

  // Scenario: tenant B's user succeeds after tenant A's user has failed. Expected: tenant A's count
  // stands, so a success in one tenant cannot clear the other's failures.
  it.each(FLOWS)('keeps tenant A’s %s failures when tenant B resets its own', async (flow) => {
    const service = lockout()
    for (let attempt = 0; attempt < THRESHOLD; attempt += 1) {
      await service.recordFailure(flow, 'dashboard', '1', 'tenant-a')
    }

    await service.reset(flow, 'dashboard', '1', 'tenant-b')

    await expect(service.isLockedOut(flow, 'dashboard', '1', 'tenant-a')).resolves.toBe(true)
  })

  // Scenario: the three flows of one account. Expected: separate budgets, so a failure in one flow never spends another's.
  it('keeps the three flows of one account apart', async () => {
    const service = lockout()
    for (let attempt = 0; attempt < THRESHOLD; attempt += 1) {
      await service.recordFailure('challenge', 'dashboard', '1', 'tenant-a')
    }

    await expect(service.isLockedOut('disable', 'dashboard', '1', 'tenant-a')).resolves.toBe(false)
    await expect(service.isLockedOut('reauth', 'dashboard', '1', 'tenant-a')).resolves.toBe(false)
  })

  // Scenario: the platform plane, which has no tenant. Expected: its own counter per flow, counted
  // once per failure, so five failures lock it and four do not.
  it.each(FLOWS)('counts each %s failure once on the platform plane', async (flow) => {
    const service = lockout()
    for (let attempt = 0; attempt < THRESHOLD - 1; attempt += 1) {
      await service.recordFailure(flow, 'platform', 'a1', undefined)
    }
    await expect(service.isLockedOut(flow, 'platform', 'a1', undefined)).resolves.toBe(false)

    await service.recordFailure(flow, 'platform', 'a1', undefined)

    await expect(service.isLockedOut(flow, 'platform', 'a1', undefined)).resolves.toBe(true)
  })
})

describe('the MFA transition lock and the TOTP replay marker across tenants', () => {
  /** A store that keeps state: the keys set with set-if-absent and the markers set with setnx. */
  function redisStore() {
    const held = new Map<string, string>()
    const attempted: string[] = []
    return {
      held,
      attempted,
      setIfAbsent: (key: string, value: string): Promise<boolean> => {
        attempted.push(key)
        if (held.has(key)) return Promise.resolve(false)
        held.set(key, value)
        return Promise.resolve(true)
      },
      setnx: (key: string): Promise<boolean> => {
        if (held.has(key)) return Promise.resolve(false)
        held.set(key, '1')
        return Promise.resolve(true)
      },
      eval: (_script: string, keys: string[], args: string[]): Promise<number> => {
        const [key] = keys
        if (key !== undefined && held.get(key) === args[0]) held.delete(key)
        return Promise.resolve(1)
      }
    }
  }

  /** The record service over a store and a repository that knows user `1` in both tenants. */
  function recordService(store: ReturnType<typeof redisStore>) {
    const users = {
      findById: ({ id, tenantId }: { id: string; tenantId: string }) =>
        Promise.resolve({ id, tenantId, status: 'active', mfaEnabled: true }),
      updateMfa: () => Promise.resolve()
    }
    return new MfaRecordService(OPTIONS as never, users as never, null, store as never)
  }

  // Scenario: a transition is in flight for user `1` of tenant B (its lock held). Expected: the same
  // transition for user `1` of tenant A goes through, instead of `MFA_STATE_CONFLICT`.
  it('does not refuse tenant A while tenant B holds its own transition lock', async () => {
    const store = redisStore()
    const service = recordService(store)
    await service.transition('dashboard', '1', 'tenant-b', () => null)
    // Every lock tenant B takes, learned by taking them once, is now held as if its transition were
    // still running.
    for (const key of store.attempted) store.held.set(key, 'tenant-b-nonce')

    await expect(service.transition('dashboard', '1', 'tenant-a', () => null)).resolves.toBe(false)
  })

  // Scenario: the lock key of two tenants' user `1`. Expected: different keys, so neither can hold
  // the other's, and the same tenant's second transition IS refused while the first holds.
  it('keys the lock by tenant and still serializes one account', async () => {
    const store = redisStore()
    const service = recordService(store)
    await service.transition('dashboard', '1', 'tenant-a', () => null)
    await service.transition('dashboard', '1', 'tenant-b', () => null)

    const seen = store.attempted
    expect(seen).toHaveLength(2)
    expect(seen[0]).not.toBe(seen[1])

    // The same account, lock already held: refused.
    store.held.set(seen[0] as string, 'someone-else')
    await expect(
      service.transition('dashboard', '1', 'tenant-a', () => null)
    ).rejects.toMatchObject({
      response: { error: { code: AUTH_ERROR_CODES.MFA_STATE_CONFLICT } }
    })
  })

  // Scenario: the same TOTP code accepted for user `1` of tenant A and then of tenant B in one
  // window. Expected: both accepted, since they are two accounts with their own secrets, and a
  // replay for the same account is still refused.
  it('keeps the replay marker per tenant and still refuses a replay', async () => {
    const store = redisStore()
    const service = recordService(store)
    const { base32 } = generateTotpSecret()
    const code = generateHotp(base32, Math.floor(Date.now() / 1000 / 30))

    await expect(
      service.verifyTotpWithAntiReplay('dashboard', '1', base32, code, 1, 'tenant-a')
    ).resolves.toBe(true)
    await expect(
      service.verifyTotpWithAntiReplay('dashboard', '1', base32, code, 1, 'tenant-b')
    ).resolves.toBe(true)
    await expect(
      service.verifyTotpWithAntiReplay('dashboard', '1', base32, code, 1, 'tenant-a')
    ).resolves.toBe(false)
  })
})
