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
import type {
  AuthMembership,
  IMembershipRepository
} from './interfaces/membership-repository.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository,
  WorkspaceStatus
} from './interfaces/workspace-repository.interface'
import { AuthRedisService } from './redis/auth-redis.service'
import { WorkspaceAccessService } from './services/workspace-access.service'

interface Step {
  do: 'resolve' | 'bumpMembership' | 'bumpWorkspace' | 'seedEntry' | 'dropCounter'
  entry?: string
  under?: string
  counter?: 'membership' | 'workspace'
  concurrentBump?: 'membership' | 'workspace'
  repository: { workspace: WorkspaceStatus; membership: 'active'; role: string }
  expect: {
    answer?: string | null
    source?: string
    cachedUnder?: string | null
    absentUnder?: string[]
    versions?: string
    countersAbsent?: boolean
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
    scenarios: { steps: Step[]; counterLoss: { steps: Step[] } }
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

const REF = { tenantId: 't1', workspaceId: 'w1', userId: 'u1' }

/** One isolated in-memory keyspace per harness. */
let nextPort = 42_000

/** The state the in-memory repositories report, and how often the workspace was read. */
interface RepositoryState {
  workspace: WorkspaceStatus
  role: string
  workspaceReads: number
  /** Runs after the membership row is read and before the repositories answer. */
  afterMembershipRead?: (() => Promise<void>) | undefined
}

/** Two in-memory repositories that report `state` and count the workspace reads. */
function memoryRepositories(state: RepositoryState): {
  workspaces: IWorkspaceRepository
  memberships: IMembershipRepository
} {
  const workspaces: Partial<IWorkspaceRepository> = {
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
  const memberships: Partial<IMembershipRepository> = {
    find: async (): Promise<AuthMembership> => {
      const row: AuthMembership = {
        ...REF,
        role: state.role,
        status: 'active',
        invitedByUserId: null,
        createdAt: new Date(0),
        updatedAt: new Date(0)
      }
      await state.afterMembershipRead?.()
      return row
    }
  }
  return {
    workspaces: workspaces as IWorkspaceRepository,
    memberships: memberships as IMembershipRepository
  }
}

/** The real service over an in-memory Redis and two repositories driven by `state`. */
function scenarioHarness(): {
  service: WorkspaceAccessService
  redis: AuthRedisService
  state: RepositoryState
  base: string
  hmacKey: string
  versions: { workspace: number; membership: number }
} {
  const options = resolveOptions({
    jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
    roles: { hierarchy: { ADMIN: [] } },
    rateLimit: { clientIpSource: 'peer' },
    workspaces: { enabled: true, roles: { hierarchy: { owner: [] }, ownerRole: 'owner' } }
  })
  const redis = new AuthRedisService(
    new RedisMock({ port: (nextPort += 1) }) as Partial<Redis> as Redis,
    options
  )
  const state: RepositoryState = { workspace: 'active', role: 'editor', workspaceReads: 0 }
  const { workspaces, memberships } = memoryRepositories(state)
  const service = new WorkspaceAccessService(redis, workspaces, memberships, options)
  return {
    service,
    redis,
    state,
    base: membershipCacheKeyBase('t1', 'w1', 'u1', options.hmacKey),
    hmacKey: options.hmacKey,
    versions: { workspace: 0, membership: 0 }
  }
}

type Harness = ReturnType<typeof scenarioHarness>

/** Moves a counter the way the library does and keeps the harness's view of the versions. */
async function bump(harness: Harness, counter: 'membership' | 'workspace'): Promise<void> {
  if (counter === 'membership') await harness.service.invalidateMembership(REF)
  else await harness.service.invalidateWorkspace(REF)
  harness.versions[counter] += 1
}

/** Performs the action of one contract step. */
async function act(harness: Harness, step: Step): Promise<void> {
  const { redis, base, versions } = harness
  if (step.do === 'bumpMembership') await bump(harness, 'membership')
  else if (step.do === 'bumpWorkspace') await bump(harness, 'workspace')
  else if (step.do === 'seedEntry') await redis.set(`${base}:${step.under}`, step.entry ?? '')
  else if (step.do === 'dropCounter') {
    const counter = step.counter ?? 'membership'
    const key =
      counter === 'membership'
        ? membershipVersionKey('t1', 'w1', 'u1', harness.hmacKey)
        : workspaceVersionKey('t1', 'w1', harness.hmacKey)
    await redis.del(key)
    versions[counter] = 0
  }
}

/** Performs one contract step and checks what the step expects. */
async function playStep(harness: Harness, step: Step): Promise<void> {
  const { service, redis, state, base, versions } = harness
  state.workspace = step.repository.workspace
  state.role = step.repository.role
  const readsBefore = state.workspaceReads
  await act(harness, step)
  if (step.do === 'resolve' || step.do === 'seedEntry') {
    const concurrent = step.concurrentBump
    state.afterMembershipRead =
      concurrent === undefined
        ? undefined
        : async () => {
            state.afterMembershipRead = undefined
            await bump(harness, concurrent)
          }
    const answer = await service.resolveMembership(REF)
    expect(answer?.role ?? null).toBe(step.expect.answer)
    expect(state.workspaceReads > readsBefore ? 'repository' : 'cache').toBe(step.expect.source)
  }
  const current = `${versions.workspace}:${versions.membership}`
  if (step.expect.versions !== undefined) expect(current).toBe(step.expect.versions)
  if (step.expect.cachedUnder !== undefined) {
    const entry = await redis.get(`${base}:${step.expect.cachedUnder ?? current}`)
    expect(entry !== null && JSON.parse(entry).status === 'active').toBe(
      step.expect.cachedUnder !== null
    )
  }
  for (const under of step.expect.absentUnder ?? []) {
    expect(await redis.get(`${base}:${under}`)).toBeNull()
  }
  if (step.expect.countersAbsent === true) await expectNoCounters(harness)
}

/** Neither version counter exists: a read has never created one. */
async function expectNoCounters(harness: Harness): Promise<void> {
  const { redis, hmacKey } = harness
  expect(await redis.get(workspaceVersionKey('t1', 'w1', hmacKey))).toBeNull()
  expect(await redis.get(membershipVersionKey('t1', 'w1', 'u1', hmacKey))).toBeNull()
}

describe('behavioural scenarios', () => {
  it('plays every contract step against the real service', async () => {
    const harness = scenarioHarness()

    for (const step of contract.workspaceMembershipCache.scenarios.steps) {
      await playStep(harness, step)
    }
  })

  // A bump that lands before the fill, and a counter that is lost, must leave nothing readable
  // under a value the library can reach again.
  it('plays the counter-loss steps on a fresh store', async () => {
    const harness = scenarioHarness()

    for (const step of contract.workspaceMembershipCache.scenarios.counterLoss.steps) {
      await playStep(harness, step)
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
