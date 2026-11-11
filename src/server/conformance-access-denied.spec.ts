/**
 * @fileoverview The `access.denied` limiter's keys, driven against the shared wire contract.
 *
 * A key that drifts from the contract raises nothing at runtime: the budget of an account would
 * simply be counted where the sibling library does not look. These cases drive
 * `WorkspaceDeniedEventsService` for every pinned account and compare the keys it writes with the
 * contract's own derivation, computed here and not by the library.
 *
 * @layer Conformance
 */

import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { WorkspaceDeniedEventsService } from './services/workspace-denied-events.service'
import type { WorkspaceEventsService } from './services/workspace-events.service'
import { AUTH_ERROR_CODES } from './errors/auth-error-codes'
import { AuthException } from './errors/auth-exception'
import { WorkspaceAccessRefusal } from './errors/workspace-access-refusal'

interface AccessDeniedContract {
  hmacKeyDerivation: { vectors: { derivedKeyHex: string }[] }
  redisKeyPrefixes: Record<string, string>
  userSubjectPreimages: { dashboard: string }
  userSubjectDerivedKeys: Record<string, string>
  workspaceRealtime: {
    accessDeniedVectors: {
      tenantId: string
      userId: string
      userSubject: string
      digestHex: string
      windowKey: string
      suppressedKey: string
    }[]
  }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as AccessDeniedContract

const HMAC_KEY = contract.hmacKeyDerivation.vectors[0]?.derivedKeyHex ?? ''
const VECTORS = contract.workspaceRealtime.accessDeniedVectors

/** Renders the contract's dashboard subject template, the way the contract spells it. */
function renderSubject(tenantId: string, userId: string): string {
  return contract.userSubjectPreimages.dashboard
    .replace('{utf8ByteLength(tenantId)}', String(Buffer.byteLength(tenantId, 'utf8')))
    .replace('{tenantId}', tenantId)
    .replace('{userId}', userId)
}

/** A service over a recording counter store, limited to one event per window. */
function build() {
  const calls: { op: 'incr' | 'getdel'; key: string; ttl?: number }[] = []
  const redis = {
    incrWithFixedTtl: jest.fn((key: string, ttl: number) => {
      calls.push({ op: 'incr', key, ttl })
      return Promise.resolve(calls.filter((c) => c.op === 'incr' && c.key === key).length)
    }),
    getdel: jest.fn((key: string) => {
      calls.push({ op: 'getdel', key })
      return Promise.resolve(null)
    })
  }
  const options = {
    hmacKey: HMAC_KEY,
    workspaces: { accessDeniedEvents: { max: 1, windowSeconds: 60 } }
  }
  const service = new WorkspaceDeniedEventsService(
    { emit: jest.fn() } as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    redis as never,
    options as never
  )
  return { service, calls }
}

const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve))

describe('access.denied keys', () => {
  // Verifies each pinned account is keyed by the contract's own subject and digest, which the
  // vectors spell out: a subject that stopped carrying its byte-length prefix names another key.
  it.each(VECTORS)('derives the pinned subject, digest and keys for $tenantId / $userId', (v) => {
    const digest = createHmac('sha256', HMAC_KEY)
      .update(renderSubject(v.tenantId, v.userId), 'utf8')
      .digest('hex')

    expect(renderSubject(v.tenantId, v.userId)).toBe(v.userSubject)
    expect(digest).toBe(v.digestHex)
    expect(v.windowKey).toBe(`${contract.redisKeyPrefixes['accessDeniedWindow']}:${digest}`)
    expect(v.suppressedKey).toBe(`${contract.redisKeyPrefixes['accessDeniedSuppressed']}:${digest}`)
  })

  // Verifies the library writes exactly the pinned keys: the window counter on every denial with
  // the window's length as its expiry, and the suppressed counter with a day, on the denial past
  // the limit.
  it.each(VECTORS)('writes the pinned keys for $tenantId / $userId', async (v) => {
    const { service, calls } = build()
    const ref = {
      tenantId: v.tenantId,
      userId: v.userId,
      workspaceId: 'w1',
      surface: 'http' as const
    }
    const refuse = (): never => {
      throw new WorkspaceAccessRefusal(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND, 'not_member')
    }

    expect(() => service.admit(ref, refuse)).toThrow(AuthException)
    await settle()
    expect(() => service.admit(ref, refuse)).toThrow(AuthException)
    await settle()

    expect(calls).toEqual([
      { op: 'incr', key: v.windowKey, ttl: 60 },
      { op: 'getdel', key: v.suppressedKey },
      { op: 'incr', key: v.windowKey, ttl: 60 },
      { op: 'incr', key: v.suppressedKey, ttl: 86_400 }
    ])
  })

  // Verifies the two keys are listed among the account-derived keys, spelled as the derivation the
  // vectors exercise, so a contract test on the sibling side sees them.
  it.each([
    ['accessDeniedWindow', 'wad'],
    ['accessDeniedSuppressed', 'wads']
  ])('lists %s as the %s prefix of an account-derived key', (name, prefix) => {
    expect(contract.redisKeyPrefixes[name]).toBe(prefix)
    expect(contract.userSubjectDerivedKeys[name]).toBe(
      `${prefix}:{hmac_sha256(hmacKey, userSubject)}`
    )
  })

  // Verifies the pinned accounts name distinct keys. The pair whose ids join to the same text,
  // (a, b:c) and (a:b, c), is driven against the service in its own spec.
  it('keeps every pinned account on its own keys', () => {
    const keys = VECTORS.flatMap((v) => [v.windowKey, v.suppressedKey])

    expect(new Set(keys).size).toBe(keys.length)
  })
})
