/**
 * @fileoverview Runs the workspace-membership cache's behavioural scenarios and full-key vectors
 * from the wire contract against the real service over an in-memory Redis, and checks that no
 * other identifier preimage can collide with the workspace subjects.
 *
 * @layer Test
 */

/// <reference path="../../test/e2e/ioredis-mock.d.ts" />

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

import type { Redis } from 'ioredis'
import RedisMock from 'ioredis-mock'

import { resolveOptions } from './config/resolved-options'
import {
  membershipCacheKeyBase,
  membershipVersionKey,
  workspaceVersionKey
} from './constants/workspace-keys'
import type { AuthMembership } from './interfaces/membership-repository.interface'
import type { AuthWorkspace, WorkspaceStatus } from './interfaces/workspace-repository.interface'
import { AuthRedisService } from './redis/auth-redis.service'
import { WorkspaceAccessService } from './services/workspace-access.service'

interface Step {
  do: 'resolve' | 'bumpMembership' | 'bumpWorkspace' | 'seedEntry'
  entry?: string
  under?: string
  repository: { workspace: WorkspaceStatus; membership: 'active'; role: string }
  expect: {
    answer?: string | null
    source?: string
    cachedUnder?: string | null
    versions?: string
  }
}

interface FullKeyVector {
  tenantId: string
  workspaceId: string
  userId: string
  workspaceVersion: string
  membershipVersion: string
  workspaceVersionKey: string
  membershipVersionKey: string
  membershipCacheKey: string
}

interface Contract {
  hmacKeyDerivation: { vectors: Array<{ derivedKeyHex: string }> }
  identifierPreimages: unknown
  userSubjectPreimages: unknown
  workspaceMembershipCache: {
    fullKeyVectors: FullKeyVector[]
    scenarios: { steps: Step[] }
  }
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as Contract
const hmacKey = contract.hmacKeyDerivation.vectors[0]?.derivedKeyHex ?? ''

describe('full-key vectors', () => {
  it.each(contract.workspaceMembershipCache.fullKeyVectors)(
    'derives the keys for $tenantId / $workspaceId at $workspaceVersion:$membershipVersion',
    (vector) => {
      const { tenantId, workspaceId, userId } = vector

      expect(`{namespace}:${workspaceVersionKey(tenantId, workspaceId, hmacKey)}`).toBe(
        vector.workspaceVersionKey
      )
      expect(`{namespace}:${membershipVersionKey(tenantId, workspaceId, userId, hmacKey)}`).toBe(
        vector.membershipVersionKey
      )
      expect(
        `{namespace}:${membershipCacheKeyBase(tenantId, workspaceId, userId, hmacKey)}:` +
          `${vector.workspaceVersion}:${vector.membershipVersion}`
      ).toBe(vector.membershipCacheKey)
    }
  )
})

describe('behavioural scenarios', () => {
  const REF = { tenantId: 't1', workspaceId: 'w1', userId: 'u1' }

  it('plays every contract step against the real service', async () => {
    const options = resolveOptions({
      jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
      roles: { hierarchy: { ADMIN: [] } },
      rateLimit: { clientIpSource: 'peer' },
      workspaces: { enabled: true, roles: { hierarchy: { owner: [] }, ownerRole: 'owner' } }
    })
    const redis = new AuthRedisService(
      new RedisMock({ port: 42_000 }) as Partial<Redis> as Redis,
      options
    )
    const state = { workspace: 'active' as WorkspaceStatus, role: 'editor', workspaceReads: 0 }
    const workspaces = {
      findById: async (): Promise<AuthWorkspace> => {
        state.workspaceReads += 1
        return {
          id: 'w1',
          tenantId: 't1',
          name: 'W',
          status: state.workspace,
          createdAt: new Date(0),
          deletionScheduledAt: null
        }
      }
    }
    const memberships = {
      find: async (): Promise<AuthMembership> => ({
        ...REF,
        role: state.role,
        status: 'active',
        invitedByUserId: null,
        createdAt: new Date(0),
        updatedAt: new Date(0)
      })
    }
    const service = new WorkspaceAccessService(
      redis,
      workspaces as never,
      memberships as never,
      options
    )
    const base = membershipCacheKeyBase('t1', 'w1', 'u1', options.hmacKey)
    const versions = { workspace: 0, membership: 0 }

    for (const step of contract.workspaceMembershipCache.scenarios.steps) {
      state.workspace = step.repository.workspace
      state.role = step.repository.role
      const readsBefore = state.workspaceReads
      if (step.do === 'bumpMembership') {
        await service.invalidateMembership(REF)
        versions.membership += 1
      } else if (step.do === 'bumpWorkspace') {
        await service.invalidateWorkspace(REF)
        versions.workspace += 1
      } else if (step.do === 'seedEntry') {
        await redis.set(`${base}:${step.under}`, step.entry ?? '')
      }
      if (step.do === 'resolve' || step.do === 'seedEntry') {
        const answer = await service.resolveMembership(REF)
        expect(answer?.role ?? null).toBe(step.expect.answer)
        expect(state.workspaceReads > readsBefore ? 'repository' : 'cache').toBe(step.expect.source)
      }
      if (step.expect.versions !== undefined) {
        expect(`${versions.workspace}:${versions.membership}`).toBe(step.expect.versions)
      }
      if (step.expect.cachedUnder !== undefined) {
        const current = `${versions.workspace}:${versions.membership}`
        const entry = await redis.get(`${base}:${step.expect.cachedUnder ?? current}`)
        expect(entry !== null && JSON.parse(entry).status === 'active').toBe(
          step.expect.cachedUnder !== null
        )
      }
    }
  })
})

describe('workspace subject prefixes', () => {
  /** Every string value in a contract section, at any depth. */
  const strings = (value: unknown): string[] =>
    typeof value === 'string'
      ? [value]
      : value !== null && typeof value === 'object'
        ? Object.values(value).flatMap(strings)
        : []

  it('is used by no other preimage the contract names', () => {
    const preimages = [
      ...strings(contract.identifierPreimages),
      ...strings(contract.userSubjectPreimages)
    ]

    expect(preimages.filter((text) => /^(wsp|wms):/.test(text))).toEqual([])
  })

  it('is spelled in no source file except the key builders', () => {
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
      .filter((file) => /['"`](wsp|wms):/.test(readFileSync(file, 'utf8')))
      .map((file) => relative(join(__dirname, '../..'), file))

    expect(spelled).toEqual(['src/server/constants/workspace-keys.ts'])
  })
})
