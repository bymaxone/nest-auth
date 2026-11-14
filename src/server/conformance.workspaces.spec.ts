/**
 * @fileoverview Checks the workspace-membership cache against the cross-implementation wire
 * contract: the subjects, the keys, the entry, the lifetimes and the error codes.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  WORKSPACE_MEMBERSHIP_CACHE_MAX_TTL_SECONDS,
  resolveWorkspaceOptions
} from './config/workspace-options'
import {
  WORKSPACE_VERSION_RETENTION_SECONDS,
  membershipCacheKeyBase,
  membershipSubject,
  membershipVersionKey,
  workspaceSubject,
  workspaceVersionKey
} from './constants/workspace-keys'
import { AUTH_ERROR_CODES, AUTH_ERROR_STATUS } from './errors/auth-error-codes'

interface Vector {
  tenantId: string
  workspaceId: string
  userId: string
  workspaceSubject: string
  workspaceDigestHex: string
  membershipSubject: string
  membershipDigestHex: string
}

interface WorkspaceContract {
  version: number
  hmacKeyDerivation: { vectors: Array<{ derivedKeyHex: string }> }
  redisKeyPrefixes: Record<string, string>
  errorCatalog: { codes: string[]; statuses: Record<string, number> }
  workspaceMembershipCache: {
    workspaceSubject: string
    membershipSubject: string
    keys: Record<string, string>
    entryValue: string
    ttl: { default: number; max: number }
    versionRetentionSeconds: number
    vectors: Vector[]
  }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as WorkspaceContract
const section = contract.workspaceMembershipCache
const hmacKey = contract.hmacKeyDerivation.vectors[0]?.derivedKeyHex ?? ''

/** The nine codes the workspace layer adds, with the statuses the contract pins for them. */
const WORKSPACE_CODES = [
  [AUTH_ERROR_CODES.WORKSPACE_REQUIRED, 400],
  [AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND, 404],
  [AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE, 403],
  [AUTH_ERROR_CODES.LAST_OWNER, 409],
  [AUTH_ERROR_CODES.ALREADY_MEMBER, 409],
  [AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH, 403],
  [AUTH_ERROR_CODES.REGISTRATION_CLOSED, 403],
  [AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED, 403],
  [AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION, 409]
] as const

describe('workspace membership cache conformance', () => {
  it('is declared by a contract at version 7', () => {
    expect(contract.version).toBe(7)
  })

  it('pins the derived HMAC key the vectors are computed with', () => {
    expect(hmacKey).toMatch(/^[0-9a-f]{64}$/)
  })

  // The expectation is rendered from the contract's own template, so a change to either side
  // turns the test red instead of repeating the value here.
  describe.each(section.vectors)('vector $tenantId / $workspaceId / $userId', (vector) => {
    const render = (template: string): string =>
      template
        .replace('{utf8ByteLength(tenantId)}', String(Buffer.byteLength(vector.tenantId, 'utf8')))
        .replace('{tenantId}', vector.tenantId)
        .replace(
          '{utf8ByteLength(workspaceId)}',
          String(Buffer.byteLength(vector.workspaceId, 'utf8'))
        )
        .replace('{workspaceId}', vector.workspaceId)
        .replace('{userId}', vector.userId)

    it('builds the subjects the contract templates render', () => {
      expect(workspaceSubject(vector.tenantId, vector.workspaceId)).toBe(
        render(section.workspaceSubject)
      )
      expect(membershipSubject(vector.tenantId, vector.workspaceId, vector.userId)).toBe(
        render(section.membershipSubject)
      )
    })

    it('builds the subjects the vector pins', () => {
      expect(workspaceSubject(vector.tenantId, vector.workspaceId)).toBe(vector.workspaceSubject)
      expect(membershipSubject(vector.tenantId, vector.workspaceId, vector.userId)).toBe(
        vector.membershipSubject
      )
    })

    it('derives the keys the vector digests pin', () => {
      const { workspaceId, tenantId, userId } = vector

      expect(workspaceVersionKey(tenantId, workspaceId, hmacKey)).toBe(
        `${contract.redisKeyPrefixes['workspaceVersion']}:${vector.workspaceDigestHex}`
      )
      expect(membershipVersionKey(tenantId, workspaceId, userId, hmacKey)).toBe(
        `${contract.redisKeyPrefixes['membershipVersion']}:${vector.membershipDigestHex}`
      )
      expect(membershipCacheKeyBase(tenantId, workspaceId, userId, hmacKey)).toBe(
        `${contract.redisKeyPrefixes['membershipCache']}:${vector.membershipDigestHex}`
      )
    })
  })

  it('names the three keys with the shapes the code builds', () => {
    expect(section.keys['workspaceVersion']).toBe(
      '{namespace}:wsv:{hmac_sha256(hmacKey, workspaceSubject)}'
    )
    expect(section.keys['membershipVersion']).toBe(
      '{namespace}:wmv:{hmac_sha256(hmacKey, membershipSubject)}'
    )
    expect(section.keys['membershipCache']).toBe(
      '{namespace}:wm:{hmac_sha256(hmacKey, membershipSubject)}:{workspaceVersion}:{membershipVersion}'
    )
  })

  it('writes the entry the contract describes', () => {
    const written = JSON.stringify({ role: '<role>', status: 'active' })

    expect(JSON.stringify(JSON.parse(section.entryValue))).toBe(written)
  })

  it('pins the lifetimes the code enforces', () => {
    const resolved = resolveWorkspaceOptions({
      jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
      roles: { hierarchy: { ADMIN: [] } },
      rateLimit: { clientIpSource: 'peer' },
      workspaces: {
        enabled: true,
        roles: { hierarchy: { owner: [] }, ownerRole: 'owner' }
      }
    })

    expect(section.ttl.max).toBe(WORKSPACE_MEMBERSHIP_CACHE_MAX_TTL_SECONDS)
    expect(section.ttl.default).toBe(resolved?.membershipCacheTtlSeconds)
    expect(section.versionRetentionSeconds).toBe(WORKSPACE_VERSION_RETENTION_SECONDS)
  })

  it.each(WORKSPACE_CODES)('carries %s with the status %p', (code, status) => {
    expect(contract.errorCatalog.codes).toContain(code)
    expect(contract.errorCatalog.statuses[code]).toBe(status)
    expect(AUTH_ERROR_STATUS[code]).toBe(status)
  })
})
