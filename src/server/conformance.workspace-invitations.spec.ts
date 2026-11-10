/**
 * @fileoverview Holds the workspace-invitation section of the wire contract to the code: the full
 * key vectors, the limits, and the guarantee that no other preimage or source file spells the
 * invitation prefixes.
 *
 * @layer Test
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

import {
  INVITATIONS_PER_INVITER_PER_HOUR,
  MAX_RESENDS,
  RESEND_COOLDOWN_SECONDS
} from './constants/workspace-invitation-limits'
import {
  invitationEmailSubject,
  invitationIndexKey,
  invitationKey,
  invitationSetKey,
  inviterRateKey,
  inviterRateSubject
} from './constants/workspace-invitation-keys'
import { workspaceSubject } from './constants/workspace-keys'

interface KeyVector {
  tenantId: string
  workspaceId: string
  email: string
  token: string
  indexSubject: string
  indexKey: string
  setSubject: string
  setKey: string
  recordKey: string
}

interface RateVector {
  tenantId: string
  userId: string
  subject: string
  key: string
}

interface Contract {
  hmacKeyDerivation: { vectors: Array<{ derivedKeyHex: string }> }
  identifierPreimages: Record<string, unknown>
  userSubjectPreimages: unknown
  rateLimits: Record<string, string>
  workspaceInvitations: {
    fullKeyVectors: KeyVector[]
    inviterRateVectors: RateVector[]
    rules: {
      resendCooldownSeconds: number
      maxResends: number
      invitationsPerInviterPerHour: number
    }
  }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as Contract
const hmacKey = contract.hmacKeyDerivation.vectors[0]?.derivedKeyHex ?? ''
const section = contract.workspaceInvitations

describe('workspace invitation key vectors', () => {
  it.each(section.fullKeyVectors)(
    'derives the keys for $tenantId / $workspaceId / $email',
    (vector) => {
      const { tenantId, workspaceId, email, token } = vector

      expect(invitationEmailSubject(tenantId, workspaceId, email)).toBe(vector.indexSubject)
      expect(`{namespace}:${invitationIndexKey(tenantId, workspaceId, email, hmacKey)}`).toBe(
        vector.indexKey
      )
      expect(workspaceSubject(tenantId, workspaceId)).toBe(vector.setSubject)
      expect(`{namespace}:${invitationSetKey(tenantId, workspaceId, hmacKey)}`).toBe(vector.setKey)
      expect(`{namespace}:${invitationKey(token)}`).toBe(vector.recordKey)
    }
  )

  it.each(section.inviterRateVectors)('derives the counter for $tenantId / $userId', (vector) => {
    expect(inviterRateSubject(vector.tenantId, vector.userId)).toBe(vector.subject)
    expect(`{namespace}:${inviterRateKey(vector.tenantId, vector.userId, hmacKey)}`).toBe(
      vector.key
    )
  })

  it('has vectors that tell two tuples with one concatenation apart', () => {
    const keys = section.fullKeyVectors.map((v) => v.indexKey)

    expect(new Set(keys).size).toBe(keys.length)
  })
})

describe('workspace invitation limits', () => {
  it('are the ones the contract states', () => {
    expect(RESEND_COOLDOWN_SECONDS).toBe(section.rules.resendCooldownSeconds)
    expect(MAX_RESENDS).toBe(section.rules.maxResends)
    expect(INVITATIONS_PER_INVITER_PER_HOUR).toBe(section.rules.invitationsPerInviterPerHour)
  })
})

describe('workspace invitation prefixes', () => {
  const strings = (value: unknown): string[] =>
    typeof value === 'string'
      ? [value]
      : value !== null && typeof value === 'object'
        ? Object.values(value).flatMap(strings)
        : []

  it('are used by no other preimage the contract names', () => {
    const others = Object.entries(contract.identifierPreimages)
      .filter(([name]) => !['workspaceInvitationEmail', 'workspaceInviterRate'].includes(name))
      .map(([, value]) => value)
    const preimages = [...strings(others), ...strings(contract.userSubjectPreimages)]

    expect(preimages.filter((text) => /^(wie|wir):/.test(text))).toEqual([])
  })

  it('are spelled in no source file except the key builders', () => {
    const files: string[] = []
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name)
        if (statSync(path).isDirectory()) walk(path)
        else if (/\.ts$/.test(name) && !/\.spec\.ts$/.test(name)) files.push(path)
      }
    }
    walk(join(__dirname, '..'))

    const spelled = files
      .filter((file) => /['"`](wie|wir):/.test(readFileSync(file, 'utf8')))
      .map((file) => relative(join(__dirname, '../..'), file))

    expect(spelled).toEqual(['src/server/constants/workspace-invitation-keys.ts'])
  })
})
