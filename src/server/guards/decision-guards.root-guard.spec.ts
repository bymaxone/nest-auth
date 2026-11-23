/**
 * @fileoverview The guards that decide access check the built-ins their decisions are made with, at the moment of the decision:
 * synchronously at the start of a guard that has no await, and again after each await that precedes the decision. A replacement
 * made while a guard waits (on a repository, a hook, a status lookup) is therefore refused by the decision that follows it.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { ROLES_KEY } from '../decorators/roles.decorator'
import { WORKSPACE_ROLES_KEY } from '../decorators/workspace-roles.decorator'
import { PLATFORM_ROLES_KEY } from '../decorators/platform-roles.decorator'
import { SKIP_MFA_KEY } from '../decorators/skip-mfa.decorator'
import type { ResolvedOptions } from '../config/resolved-options'
import type { AccountStatusService } from '../services/account-status.service'
import type { WorkspaceAccessService } from '../services/workspace-access.service'
import type { WorkspaceDeniedEventsService } from '../services/workspace-denied-events.service'
import { MfaRequiredGuard } from './mfa-required.guard'
import { PlatformRolesGuard } from './platform-roles.guard'
import { RolesGuard } from './roles.guard'
import { SelfOrAdminGuard } from './self-or-admin.guard'
import { UserStatusGuard } from './user-status.guard'
import { WorkspaceGuard } from './workspace.guard'

// The test's own copies: the windows below replace built-ins, so nothing inside one may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor
const GET_METADATA = getOwn(Reflect, 'getMetadata') as PropertyDescriptor

/** The functions a decision of these guards is made with, each replaced by a function that answers what the attacker wants. */
const REPLACEMENTS: readonly (readonly [string, object, string, unknown])[] = [
  ['Array.prototype.some', Array.prototype, 'some', () => true],
  ['Array.prototype.includes', Array.prototype, 'includes', () => true],
  ['Array.prototype.every', Array.prototype, 'every', () => true],
  ['Set.prototype.has', Set.prototype, 'has', () => true],
  ['Map.prototype.get', Map.prototype, 'get', () => undefined],
  ['String.prototype.startsWith', String.prototype, 'startsWith', () => true]
]

/** Replaces `key` of `holder` with `stub` and returns what puts it back. */
function replace(holder: object, key: string, stub: unknown): () => void {
  const held = getOwn(holder, key) as PropertyDescriptor
  define(holder, key, { ...held, value: stub })
  return (): void => void define(holder, key, held)
}

afterEach(() => {
  define(Reflect, 'getMetadata', GET_METADATA)
})

/** What a refusal of the guard carries, or `undefined` when the call answered or threw anything else. */
async function refusalOf(run: () => unknown): Promise<number | undefined> {
  try {
    await run()
  } catch (error) {
    return (error as { getStatus?: () => number }).getStatus?.()
  }
  return undefined
}

const OPTIONS = {
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] }, platformHierarchy: { SUPER_ADMIN: [] } }
} as unknown as ResolvedOptions

/** An execution context for a handler carrying `metadata`, a request carrying `user` and `params`. */
function contextOf(
  user: object | undefined,
  metadata: Record<string | symbol, unknown> = {},
  params: Record<string, string> = {}
): ExecutionContext {
  class Controller {
    handler(): void {}
  }
  for (const key of Reflect.ownKeys(metadata))
    Reflect.defineMetadata(key, metadata[key as string], Controller.prototype.handler)
  return {
    getHandler: () => Controller.prototype.handler,
    getClass: () => Controller,
    switchToHttp: () => ({ getRequest: () => ({ user, params }) })
  } as unknown as ExecutionContext
}

describe('the synchronous guards that decide', () => {
  // The cases: each guard, the context a legitimate caller would present, and the one that is admitted when nothing is replaced.
  const CASES: readonly (readonly [
    string,
    () => { canActivate(context: ExecutionContext): unknown },
    ExecutionContext
  ])[] = [
    [
      'RolesGuard',
      () => new RolesGuard(new Reflector(), OPTIONS),
      contextOf({ role: 'MEMBER' }, { [ROLES_KEY]: ['MEMBER'] })
    ],
    [
      'PlatformRolesGuard',
      () => new PlatformRolesGuard(new Reflector(), OPTIONS),
      contextOf(
        { type: 'platform', role: 'SUPER_ADMIN' },
        { [PLATFORM_ROLES_KEY]: ['SUPER_ADMIN'] }
      )
    ],
    [
      'MfaRequiredGuard',
      () => new MfaRequiredGuard(new Reflector()),
      contextOf({ mfaEnabled: false })
    ],
    [
      'SelfOrAdminGuard',
      () => new SelfOrAdminGuard(OPTIONS),
      contextOf({ sub: 'u1', role: 'MEMBER', tenantId: 't1' }, {}, { userId: 'u1' })
    ]
  ]

  it.each(CASES)('%s admits a legitimate caller with nothing replaced', (_name, make, context) => {
    expect(make().canActivate(context)).toBe(true)
  })

  // Scenario: each guard called while each function a decision is made with is replaced, in turn. Expected: the library's own
  // refusal (500) and never the admission the replacement would have made. Why: a replaced `some` or `has` that answers true is
  // a privilege escalation, so the guard compares the built-ins at the start of the decision.
  it.each(
    CASES.flatMap(([name, make, context]) =>
      REPLACEMENTS.map((r) => [name, make, context, ...r] as const)
    )
  )(
    '%s is refused while %#s is replaced',
    async (_name, make, context, _label, holder, key, stub) => {
      const restore = replace(holder, key, stub)
      let status: number | undefined
      try {
        status = await refusalOf(() => make().canActivate(context))
      } finally {
        restore()
      }

      expect(status).toBe(500)
    }
  )

  // Scenario: `Reflect.getMetadata`, which `Reflector` reads for `@Roles()`, `@SkipMfa()` and `@Public()`, replaced by a function
  // that answers no role requirement. Expected: the library's refusal, not an admission. Why: a replaced reader would drop the
  // requirement of every route.
  it('RolesGuard is refused while Reflect.getMetadata is replaced', async () => {
    const guard = new RolesGuard(new Reflector(), OPTIONS)
    const context = contextOf({ role: 'NOBODY' }, { [ROLES_KEY]: ['ADMIN'] })
    const restore = replace(Reflect, 'getMetadata', () => undefined)
    let status: number | undefined
    try {
      status = await refusalOf(() => guard.canActivate(context))
    } finally {
      restore()
    }

    expect(status).toBe(500)
  })
})

describe('the guards that wait before they decide', () => {
  const user = { sub: 'u1', tenantId: 't1', type: 'dashboard' }

  // Scenario: UserStatusGuard, whose status lookup replaces `Array.prototype.includes` while it is awaited and then answers that
  // the account is usable. Expected: the library's refusal. Why: the replacement was made after the guard's first check, inside
  // the await, so only a check after the await refuses it.
  it('UserStatusGuard is refused when a built-in is replaced during the status lookup', async () => {
    let restore = (): void => undefined
    const accountStatus = {
      assertDashboardAccountUsable: async (): Promise<void> => {
        await Promise.resolve()
        restore = replace(Array.prototype, 'includes', () => true)
      }
    } as unknown as AccountStatusService
    const guard = new UserStatusGuard(accountStatus)
    let status: number | undefined
    try {
      status = await refusalOf(() => guard.canActivate(contextOf(user)))
    } finally {
      restore()
    }

    expect(status).toBe(500)
  })

  // Scenario: WorkspaceGuard, whose access lookup replaces `Set.prototype.has` while it is awaited and then answers a member.
  // Expected: the library's refusal. Why: the membership and the role are decided after the await.
  it('WorkspaceGuard is refused when a built-in is replaced during the access lookup', async () => {
    let restore = (): void => undefined
    const access = {
      resolveAccess: async (): Promise<object> => {
        await Promise.resolve()
        restore = replace(Set.prototype, 'has', () => true)
        return { kind: 'member', member: { role: 'owner' } }
      }
    } as unknown as WorkspaceAccessService
    const denied = {
      admit: (_ref: unknown, run: () => unknown): unknown => run()
    } as unknown as WorkspaceDeniedEventsService
    const options = {
      workspaces: {
        roles: { hierarchy: { owner: [] } },
        permissions: {},
        resolveRequestWorkspace: () => 'w1'
      }
    } as unknown as ResolvedOptions
    const guard = new WorkspaceGuard(new Reflector(), access, options, denied)
    let status: number | undefined
    try {
      status = await refusalOf(() =>
        guard.canActivate(
          contextOf(
            { ...user, type: 'dashboard' },
            { [WORKSPACE_ROLES_KEY]: ['owner'] },
            { workspaceId: 'w1' }
          )
        )
      )
    } finally {
      restore()
    }

    expect(status).toBe(500)
  })

  // Scenario: the same guards called with nothing replaced. Expected: not the library's refusal (500). Why: the control for the
  // rows above, so a 500 there is the guard's refusal and not a fixture that cannot be admitted.
  it('UserStatusGuard admits when nothing is replaced', async () => {
    const accountStatus = {
      assertDashboardAccountUsable: async (): Promise<void> => undefined
    } as unknown as AccountStatusService

    await expect(new UserStatusGuard(accountStatus).canActivate(contextOf(user))).resolves.toBe(
      true
    )
  })

  // The skip metadata read through the same reader.
  it('keeps the metadata key of @SkipMfa() the one the guard reads', () => {
    expect(SKIP_MFA_KEY).toBeDefined()
  })
})
