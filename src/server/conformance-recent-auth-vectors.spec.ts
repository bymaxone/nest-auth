/**
 * @fileoverview The recent-authentication mark, held to the contract's known answers.
 *
 * The key is bound to the session that earned it. These cases take each vector the contract pins,
 * recompute it with `node:crypto` and nothing from the library, and require the library's own
 * derivation to produce the same bytes, so a mark that drifts from the shared keyspace (a bare
 * subject, an unbound key, a hashed or reshaped session id) fails here.
 *
 * @layer Test
 */

import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { recentAuthKey } from './constants/recent-auth'
import { sessionId } from './constants/session-id'

interface Vector {
  readonly tenantId: string
  readonly userId: string
  readonly userSubject: string
  readonly sid: string
  readonly identifierHex: string
  readonly key: string
}

interface Contract {
  readonly hmacKeyDerivation: { readonly vectors: readonly { readonly derivedKeyHex: string }[] }
  readonly userSubjectDerivedKeys: Readonly<Record<string, string>>
  readonly recentAuthMarkerVectors: { readonly vectors: readonly Vector[] }
  readonly accessTokenClaims: { readonly sessionClaim: { readonly claim: string } }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as Contract

const KEY_TEXT = contract.hmacKeyDerivation.vectors[0]?.derivedKeyHex ?? ''
const VECTORS = contract.recentAuthMarkerVectors.vectors

describe('the recent-authentication mark in the contract', () => {
  it('declares the key as the subject digest followed by the session id', () => {
    expect(contract.userSubjectDerivedKeys['recentAuthMarker']).toBe(
      'ra:{hmac_sha256(hmacKey, userSubject)}:{sid}'
    )
    expect(contract.accessTokenClaims.sessionClaim.claim).toBe('sid')
    expect(VECTORS.length).toBeGreaterThanOrEqual(3)
  })

  // Scenario: each vector, recomputed from the key text, the subject and the sid. Expected: the
  // contract's identifier and key, and `ra:` plus the identifier plus `:` plus the sid is the key.
  it.each(VECTORS)('recomputes the key for $tenantId / $userId', (vector) => {
    const identifier = createHmac('sha256', KEY_TEXT)
      .update(vector.userSubject, 'utf8')
      .digest('hex')

    expect(identifier).toBe(vector.identifierHex)
    expect(vector.key).toBe(`ra:${identifier}:${vector.sid}`)
  })

  // Scenario: the library's derivation for each vector's tenant, user and session id. Expected:
  // the contract's key. The library's HMAC key is the contract's key text.
  it.each(VECTORS)('derives the key for $tenantId / $userId as the contract pins it', (vector) => {
    expect(recentAuthKey('dashboard', vector.userId, KEY_TEXT, vector.tenantId, vector.sid)).toBe(
      vector.key
    )
  })

  it.each(VECTORS)('pins a session id in the contract shape for $tenantId / $userId', (vector) => {
    expect(sessionId(vector.sid)).toBe(vector.sid)
  })
})
