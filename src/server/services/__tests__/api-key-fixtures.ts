/**
 * @fileoverview Shared fixtures for the service-key specs: an in-memory repository, a movable
 * clock and a resolved-options stand-in. Test-only; excluded from coverage and from the build.
 */

import type { ResolvedOptions } from '../../config/resolved-options'
import { apiKeyDigest, formatApiKey } from '../../crypto/api-key'
import type { AuthApiKey, IApiKeyRepository } from '../../interfaces/api-key-repository.interface'
import type { ApiKeyClock } from '../api-key-clock'

/** The pepper every fixture digest is computed under; long and varied enough to pass option validation. */
export const PEPPER = 'pepper-for-tests-0123456789abcdefABCDEF!'
/** The row id of the fixture key: a canonical lowercase UUID. */
export const KEY_ID = '0b8f3c1e-5d2a-4c7e-9a14-6f3e8d2b7a90'
/** A distinctive 43-character secret: a leak anywhere is findable by substring. */
export const SENTINEL_SECRET = 'SENTINELsecretSENTINELsecretSENTINELsecret_'
/** The plaintext key for {@link SENTINEL_SECRET}: a leak anywhere is findable by substring. */
export const SENTINEL_KEY = formatApiKey('bak', KEY_ID, SENTINEL_SECRET)
/** The instant every {@link FakeClock} starts at. */
export const NOW = new Date('2026-06-01T12:00:00.000Z')

/** A clock the test moves by hand. */
export class FakeClock implements ApiKeyClock {
  constructor(public current: Date = NOW) {}
  now(): Date {
    return new Date(this.current.getTime())
  }
}

/** A stored row for {@link SENTINEL_SECRET}, overridable per field. */
export function makeRow(overrides: Partial<AuthApiKey> = {}): AuthApiKey {
  return {
    id: KEY_ID,
    label: 'automation',
    digest: apiKeyDigest(SENTINEL_SECRET, PEPPER),
    scopes: ['read', 'operate'],
    createdAt: new Date('2026-05-01T00:00:00.000Z'),
    expiresAt: null,
    revokedAt: null,
    lastUsedAt: null,
    ...overrides
  }
}

/** Resolved options carrying only what the service-key code reads. */
export function makeOptions(overrides: Partial<ResolvedOptions['apiKeys']> = {}): ResolvedOptions {
  return {
    apiKeys: {
      enabled: true,
      pepper: PEPPER,
      scopes: ['read', 'operate', 'publish-claim', 'admin'],
      header: 'x-api-key',
      prefix: 'bak',
      lastUsedFlushSeconds: 60,
      auditMode: 'best-effort',
      ...overrides
    }
  } as ResolvedOptions
}

/** In-memory repository; every method can be made to throw, and every call is recorded. */
export class MemoryApiKeyRepository implements IApiKeyRepository {
  rows = new Map<string, AuthApiKey>()
  calls: string[] = []
  failWith: Error | null = null

  constructor(rows: AuthApiKey[] = []) {
    for (const row of rows) this.rows.set(row.id, row)
  }

  private enter(name: string): void {
    this.calls.push(name)
    if (this.failWith !== null) throw this.failWith
  }

  async findById(id: string): Promise<AuthApiKey | null> {
    this.enter('findById')
    return this.rows.get(id) ?? null
  }

  async create(row: Parameters<IApiKeyRepository['create']>[0]): Promise<AuthApiKey> {
    this.enter('create')
    const stored: AuthApiKey = { ...row, revokedAt: null, lastUsedAt: null }
    this.rows.set(row.id, stored)
    return stored
  }

  async markRevoked(id: string, at: Date): Promise<boolean> {
    this.enter('markRevoked')
    const row = this.rows.get(id)
    if (row === undefined) return false
    row.revokedAt = at
    return true
  }

  async setExpiry(id: string, at: Date): Promise<boolean> {
    this.enter('setExpiry')
    const row = this.rows.get(id)
    if (row === undefined) return false
    row.expiresAt = at
    return true
  }

  async touchLastUsed(entries: ReadonlyArray<{ id: string; at: Date }>): Promise<void> {
    this.enter('touchLastUsed')
    for (const { id, at } of entries) {
      const row = this.rows.get(id)
      if (row !== undefined && (row.lastUsedAt === null || row.lastUsedAt < at)) row.lastUsedAt = at
    }
  }

  async listByLabel(label: string): Promise<AuthApiKey[]> {
    this.enter('listByLabel')
    return [...this.rows.values()].filter((row) => row.label === label)
  }
}
