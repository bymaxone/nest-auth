/**
 * @fileoverview The services that decide a revocation, the state of an account and a membership check the built-ins their decisions
 * are made with at the start of a call and again after each lookup they wait for, so a replacement made during a lookup is
 * refused before the decision that follows it.
 *
 * @layer Test
 */

import { resolveOptions } from '../config/resolved-options'
import type { ResolvedOptions } from '../config/resolved-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'
import type { AuthRedisService } from '../redis/auth-redis.service'
import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import { WorkspaceAccessService } from './workspace-access.service'

// The test's own copies: the windows below replace a built-in, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

const SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'
const OPTIONS: ResolvedOptions = resolveOptions({
  jwt: { secret: SECRET },
  roles: { hierarchy: { ADMIN: [] } },
  rateLimit: { clientIpSource: 'peer' },
  workspaces: {
    enabled: true,
    membershipCacheTtlSeconds: 0,
    roles: { hierarchy: { owner: ['editor'], editor: [] }, ownerRole: 'owner' }
  }
} as BymaxAuthModuleOptions)

/** Replaces `Set.prototype.has`, once however many lookups call it, and sets what puts it back. */
function replaceDuringLookup(restore: { current: () => void; done?: boolean }): void {
  if (restore.done === true) return
  restore.done = true
  const held = getOwn(Set.prototype, 'has') as PropertyDescriptor
  define(Set.prototype, 'has', { ...held, value: () => true })
  restore.current = (): void => void define(Set.prototype, 'has', held)
}

/** The status of the refusal the call raises, `true` when it answered, or `undefined` for any other failure. */
async function outcome(run: () => Promise<unknown>): Promise<number | true | undefined> {
  try {
    await run()
    return true
  } catch (error) {
    return (error as { getStatus?: () => number }).getStatus?.()
  }
}

describe('AuthRevocationService while a built-in is replaced', () => {
  const payload = { jti: 'j', sub: 'u', tenantId: 't', epoch: 0 }

  // Scenario: `Set.prototype.has` replaced before the call. Expected: the library's refusal and no store read. Why: the first
  // check of the decision is made before anything is asked of the store.
  it('is refused before it reads the store when a built-in is replaced', async () => {
    const redis = {
      get: jest.fn(),
      getUserTokenEpoch: jest.fn()
    } as Partial<AuthRedisService> as AuthRedisService
    const service = new AuthRevocationService(redis)
    const restore = { current: (): void => undefined }
    replaceDuringLookup(restore)
    let result: number | true | undefined
    try {
      result = await outcome(() => service.isAccessTokenRevoked(payload))
    } finally {
      restore.current()
    }

    expect(result).toBe(500)
    expect(redis.get).not.toHaveBeenCalled()
  })

  // Scenario: the lookup of the user's epoch replaces `Set.prototype.has` while it is awaited. Expected: the library's refusal and
  // no answer. Why: the answer compares the token's epoch with the one the lookup returned, after the await.
  it('is refused when a built-in is replaced during the lookup of the epoch', async () => {
    const restore = { current: (): void => undefined }
    const redis = {
      get: async (): Promise<null> => null,
      getUserTokenEpoch: async (): Promise<number> => {
        await Promise.resolve()
        replaceDuringLookup(restore)
        return 0
      }
    } as Partial<AuthRedisService> as AuthRedisService
    let result: number | true | undefined
    try {
      result = await outcome(() => new AuthRevocationService(redis).isAccessTokenRevoked(payload))
    } finally {
      restore.current()
    }

    expect(result).toBe(500)
  })

  it('answers when nothing is replaced', async () => {
    const redis = {
      get: async (): Promise<null> => null,
      getUserTokenEpoch: async (): Promise<number> => 0
    } as Partial<AuthRedisService> as AuthRedisService

    await expect(new AuthRevocationService(redis).isAccessTokenRevoked(payload)).resolves.toBe(
      false
    )
  })
})

describe('AccountStatusService while a built-in is replaced', () => {
  const build = (lookup: () => void): AccountStatusService => {
    const redis = {
      get: async (): Promise<string> => {
        await Promise.resolve()
        lookup()
        return 'ACTIVE'
      }
    } as Partial<AuthRedisService> as AuthRedisService
    const repository = {
      findById: async (): Promise<object> => {
        await Promise.resolve()
        lookup()
        return { status: 'ACTIVE', emailVerified: true }
      }
    }
    return new AccountStatusService(redis, repository as never, OPTIONS, {
      findById: repository.findById
    } as never)
  }

  // Scenario: the status lookup replaces `Set.prototype.has` while it is awaited and answers an active account. Expected: the
  // library's refusal. Why: the status is judged against the blocked list after the await.
  it('is refused on the cached path when a built-in is replaced during the lookup', async () => {
    const restore = { current: (): void => undefined }
    let result: number | true | undefined
    try {
      result = await outcome(() =>
        build(() => replaceDuringLookup(restore)).assertDashboardAccountUsable({
          userId: 'u',
          tenantId: 't'
        })
      )
    } finally {
      restore.current()
    }

    expect(result).toBe(500)
  })

  // Scenario: the account read from the repository now (for work apart from a request) replaces the built-in while it is awaited.
  it('is refused on the read-now path when a built-in is replaced during the lookup', async () => {
    const restore = { current: (): void => undefined }
    let result: number | true | undefined
    try {
      result = await outcome(() =>
        build(() => replaceDuringLookup(restore)).assertDashboardAccountUsableNow({
          userId: 'u',
          tenantId: 't'
        })
      )
    } finally {
      restore.current()
    }

    expect(result).toBe(500)
  })

  // Scenario: the administrator read from the platform repository replaces the built-in while it is awaited.
  it('is refused for an administrator when a built-in is replaced during the lookup', async () => {
    const restore = { current: (): void => undefined }
    let result: number | true | undefined
    try {
      result = await outcome(() =>
        build(() => replaceDuringLookup(restore)).assertPlatformAccountUsable('admin')
      )
    } finally {
      restore.current()
    }

    expect(result).toBe(500)
  })

  it('admits an active account when nothing is replaced', async () => {
    await expect(
      build(() => undefined).assertDashboardAccountUsable({ userId: 'u', tenantId: 't' })
    ).resolves.toBeUndefined()
  })
})

describe('WorkspaceAccessService while a built-in is replaced', () => {
  const active = { tenantId: 't', workspaceId: 'w', userId: 'u' }
  const build = (lookup: () => void): WorkspaceAccessService => {
    const workspaceRepo = {
      findById: async (): Promise<object> => {
        await Promise.resolve()
        lookup()
        return { id: 'w', tenantId: 't', status: 'active' }
      }
    }
    const membershipRepo = {
      find: async (): Promise<object> => ({ ...active, id: 'm', status: 'active', role: 'owner' })
    }
    const accountStatus = { assertDashboardAccountUsableNow: async (): Promise<void> => undefined }
    return new WorkspaceAccessService(
      {} as AuthRedisService,
      workspaceRepo as never,
      membershipRepo as never,
      OPTIONS,
      accountStatus as never
    )
  }

  // Scenario: a built-in replaced before the call. Expected: the library's refusal and no repository read. Why: the check at the
  // start covers what the service does before it reads anything.
  it('is refused before it reads a repository when a built-in is replaced', async () => {
    const lookup = jest.fn()
    const service = build(lookup)
    const restore = { current: (): void => undefined }
    replaceDuringLookup(restore)
    let result: number | true | undefined
    try {
      result = await outcome(() => service.resolveAccess(active))
    } finally {
      restore.current()
    }

    expect(result).toBe(500)
    expect(lookup).not.toHaveBeenCalled()
  })

  // Scenario: the repository read replaces the built-in while it is awaited, for a check made apart from a request. Expected: the
  // library's refusal. Why: the role is decided against the roles the route accepts after the read.
  it('is refused for a queued check when a built-in is replaced during the read', async () => {
    const restore = { current: (): void => undefined }
    let result: number | true | undefined
    try {
      result = await outcome(() =>
        build(() => replaceDuringLookup(restore)).assertStillAuthorized(
          { tenantId: 't', workspaceId: 'w', actorUserId: 'u' } as never,
          ['owner']
        )
      )
    } finally {
      restore.current()
    }

    expect(result).toBe(500)
  })

  it('admits a member when nothing is replaced', async () => {
    await expect(
      build(() => undefined).assertStillAuthorized(
        { tenantId: 't', workspaceId: 'w', actorUserId: 'u' } as never,
        ['owner']
      )
    ).resolves.toMatchObject({ role: 'owner' })
  })
})
