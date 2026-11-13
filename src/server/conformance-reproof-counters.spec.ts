/**
 * @fileoverview The failure counters of the password re-proof flows, held to the contract's known
 * answers.
 *
 * A key template asserted against text proves the file still says it. These cases take each vector
 * the contract pins, recompute it with `node:crypto` and nothing from the library, and require the
 * library's own derivation to produce the same bytes, so a counter that drifts from the shared
 * keyspace (a bare user id, a tenant-less subject, another flow label) fails here.
 *
 * @layer Test
 */

import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { reproofCounterId, type ReproofFlow } from './constants/reproof-counter'

interface Vector {
  readonly flow: ReproofFlow
  readonly tenantId: string
  readonly userId: string
  readonly userSubject: string
  readonly identifierHex: string
  readonly key: string
}

interface Contract {
  readonly version: number
  readonly hmacKeyDerivation: { readonly vectors: readonly { readonly derivedKeyHex: string }[] }
  readonly userSubjectPreimages: { readonly dashboard: string }
  readonly userSubjectDerivedKeys: Readonly<Record<string, string>>
  readonly reproofCounterVectors: { readonly vectors: readonly Vector[] }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as Contract

const KEY_TEXT = contract.hmacKeyDerivation.vectors[0]?.derivedKeyHex ?? ''
const VECTORS = contract.reproofCounterVectors.vectors

/** The dashboard subject, rendered from the contract's own grammar with no library code. */
function subjectOf(tenantId: string, userId: string): string {
  return contract.userSubjectPreimages.dashboard
    .replace('{utf8ByteLength(tenantId)}', String(Buffer.byteLength(tenantId, 'utf8')))
    .replace('{tenantId}', tenantId)
    .replace('{userId}', userId)
}

describe('the password re-proof counters in the contract', () => {
  it('pins the derivation key and a vector for every case the contract lists', () => {
    expect(contract.version).toBe(6)
    expect(KEY_TEXT).toMatch(/^[0-9a-f]{64}$/)
    expect(VECTORS.length).toBeGreaterThanOrEqual(5)
    expect(new Set(VECTORS.map(({ flow }) => flow))).toEqual(
      new Set(['change-password', 'email-change'])
    )
  })

  it('declares the two counters as templates over the tenant-scoped subject', () => {
    expect(contract.userSubjectDerivedKeys['changePasswordFailureCounter']).toBe(
      "lf:{hmac_sha256(hmacKey, 'reauth:change-password:{userSubject}')}"
    )
    expect(contract.userSubjectDerivedKeys['emailChangeFailureCounter']).toBe(
      "lf:{hmac_sha256(hmacKey, 'reauth:email-change:{userSubject}')}"
    )
  })

  // Scenario: each vector's subject, recomputed from the contract's grammar. Expected: identical,
  // including for an accented tenant (a length prefix in BYTES) and one containing the delimiter.
  it.each(VECTORS)('renders the subject of $flow for $tenantId / $userId', (vector) => {
    expect(subjectOf(vector.tenantId, vector.userId)).toBe(vector.userSubject)
  })

  // Scenario: each vector's identifier, recomputed with node:crypto from the key text and the
  // preimage. Expected: the contract's hex, and `lf:` plus it is the key.
  it.each(VECTORS)('recomputes the key of $flow for $tenantId / $userId', (vector) => {
    const identifier = createHmac('sha256', KEY_TEXT)
      .update(`reauth:${vector.flow}:${vector.userSubject}`, 'utf8')
      .digest('hex')

    expect(identifier).toBe(vector.identifierHex)
    expect(vector.key).toBe(`lf:${vector.identifierHex}`)
  })

  // Scenario: the library's derivation for each vector. Expected: the contract's identifier, so a
  // counter derived any other way splits this library's budget from the sibling's.
  it.each(VECTORS)('derives the counter of $flow for $tenantId / $userId as pinned', (vector) => {
    expect(reproofCounterId(vector.flow, vector.userId, vector.tenantId, KEY_TEXT)).toBe(
      vector.identifierHex
    )
  })

  // Scenario: two tenants' user `1`, and the (tenant, user) pairs a bare delimiter would merge.
  // Expected: distinct keys, so neither tenant's failures can spend the other's budget.
  it('gives distinct counters to two tenants and to delimiter-ambiguous pairs', () => {
    const keys = new Set(VECTORS.map(({ key }) => key))

    expect(keys.size).toBe(VECTORS.length)
    expect(reproofCounterId('change-password', '1', 'tenant-a', KEY_TEXT)).not.toBe(
      reproofCounterId('change-password', '1', 'tenant-b', KEY_TEXT)
    )
    expect(reproofCounterId('email-change', 'u1', 'acme:prod', KEY_TEXT)).not.toBe(
      reproofCounterId('email-change', 'prod:u1', 'acme', KEY_TEXT)
    )
  })

  // Scenario: the same account in the two flows. Expected: separate counters, so a wrong password
  // on one flow never spends the other's budget or the login's.
  it('keeps the two flows of one account apart', () => {
    expect(reproofCounterId('change-password', 'u1', 'acme', KEY_TEXT)).not.toBe(
      reproofCounterId('email-change', 'u1', 'acme', KEY_TEXT)
    )
  })
})
