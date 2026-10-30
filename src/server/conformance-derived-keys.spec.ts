/**
 * @fileoverview The account-derived Redis keys, rendered from the contract and compared with the
 * keys the code derives.
 *
 * `conformance.spec.ts` pins what the contract SAYS. A key template asserted against a literal
 * only proves the file still holds that literal: the code can derive a different key and the
 * assertion stays green, because both sides of it are text. These cases render each template
 * from the contract's own grammar, for known inputs, with `node:crypto` and nothing from the
 * library, and require the key the code produces to be the same string. A contract that names one
 * key while the code writes another therefore fails here, whichever of the two moved.
 */

import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { recentAuthKey } from './constants/recent-auth'
import { sessionIndexKey, tokenEpochKey } from './constants/user-keys'

interface DerivedKeyContract {
  readonly userSubjectPreimages: Readonly<Record<string, unknown>>
  readonly userSubjectDerivedKeys: Readonly<Record<string, unknown>>
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as DerivedKeyContract

const HMAC_KEY = 'a'.repeat(64)

type Plane = 'dashboard' | 'platform'

/** The inputs the keys are rendered for: the delimiter inside a tenant id, and a multi-byte one. */
const CASES: ReadonlyArray<{ plane: Plane; userId: string; tenantId: string | undefined }> = [
  { plane: 'dashboard', userId: 'u1', tenantId: 'tenant-1' },
  { plane: 'dashboard', userId: 'prod:u1', tenantId: 'acme' },
  { plane: 'dashboard', userId: 'u1', tenantId: 'acme:prod' },
  { plane: 'dashboard', userId: 'u1', tenantId: 'açaí' },
  { plane: 'platform', userId: 'admin-1', tenantId: undefined }
]

function declared(section: Readonly<Record<string, unknown>>, name: string): string {
  const value = section[name]
  if (typeof value !== 'string') throw new Error(`the contract declares no string for ${name}`)
  return value
}

/** Fills a preimage template's placeholders; an unknown placeholder is an error, not an empty string. */
function renderPreimage(
  template: string,
  input: { userId: string; tenantId: string | undefined }
): string {
  return template.replace(/\{([^}]+)\}/g, (_match, name: string) => {
    if (name === 'userId') return input.userId
    if (name === 'tenantId') return input.tenantId ?? ''
    if (name === 'utf8ByteLength(tenantId)') {
      return String(Buffer.byteLength(input.tenantId ?? '', 'utf8'))
    }
    throw new Error(`unknown placeholder {${name}} in a preimage template`)
  })
}

/** Renders `{a|b}:{hmac_sha256(hmacKey, userSubject)}` for one plane, from the contract's own text. */
function renderDerivedKey(
  template: string,
  plane: Plane,
  input: { userId: string; tenantId: string | undefined }
): string {
  const subject = renderPreimage(declared(contract.userSubjectPreimages, plane), input)
  const digest = createHmac('sha256', HMAC_KEY).update(subject, 'utf8').digest('hex')
  return template
    .replace(/\{([a-z]+)\|([a-z]+)\}/, (_match, dashboard: string, platform: string) =>
      plane === 'dashboard' ? dashboard : platform
    )
    .replace('{hmac_sha256(hmacKey, userSubject)}', digest)
}

describe('account-derived keys rendered from the contract', () => {
  // Scenario: the key naming a user's live sessions and the key holding their token epoch, for a
  // tenant id that contains the delimiter and one with multi-byte characters. Expected: the key
  // the code derives equals the key the contract's templates render. Why: a verifier that builds
  // its key from the declaration reads a key nothing writes, resolves an absent epoch as 0, and
  // then never rejects, so every epoch-bump revocation is a silent no-op.
  describe.each([
    ['sessionIndex', sessionIndexKey],
    ['tokenEpoch', tokenEpochKey]
  ] as const)('%s', (name, derive) => {
    it.each(CASES)('derives %j as the contract renders it', (input) => {
      const rendered = renderDerivedKey(
        declared(contract.userSubjectDerivedKeys, name),
        input.plane,
        input
      )

      expect(derive(input.plane, input.userId, HMAC_KEY, input.tenantId)).toBe(rendered)
    })
  })

  // Scenario: the recent-authentication marker. Expected: the code's key is the contract's
  // template for the same input. Why: the marker is shared with the sibling backend, and a
  // different spelling on one side makes a fresh re-authentication invisible to the other.
  it.each(CASES)('derives the recentAuthMarker for %j as the contract renders it', (input) => {
    const rendered = renderDerivedKey(
      declared(contract.userSubjectDerivedKeys, 'recentAuthMarker'),
      input.plane,
      input
    )

    expect(recentAuthKey(input.plane, input.userId, HMAC_KEY, input.tenantId)).toBe(rendered)
  })

  // Scenario: two tenants whose ids make the same string under a bare delimiter. Expected: the
  // rendered keys differ. Why: this is the property the length prefix exists for, asserted on the
  // contract's own grammar so a preimage edited back to a bare ':' fails here as well as in the
  // code.
  it('renders distinct keys for (acme:prod, u1) and (acme, prod:u1)', () => {
    const template = declared(contract.userSubjectDerivedKeys, 'tokenEpoch')

    const first = renderDerivedKey(template, 'dashboard', { userId: 'u1', tenantId: 'acme:prod' })
    const second = renderDerivedKey(template, 'dashboard', { userId: 'prod:u1', tenantId: 'acme' })

    expect(first).not.toBe(second)
  })
})
