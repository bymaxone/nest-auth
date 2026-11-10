/**
 * @fileoverview Shared harness of the workspace invitation accept specs: an in-memory Redis, the
 * real store and ceiling, stubbed repositories and collaborators, and the records they accept.
 *
 * @layer Test
 */

/// <reference path="../../../../test/e2e/ioredis-mock.d.ts" />

import type { Redis } from 'ioredis'
import RedisMock from 'ioredis-mock'

import { MembershipService } from '../membership.service'
import type { PasswordService } from '../password.service'
import type { SessionService } from '../session.service'
import type { TokenManagerService } from '../token-manager.service'
import type { WorkspaceAccessService } from '../workspace-access.service'
import type { WorkspaceEventsService } from '../workspace-events.service'
import { WorkspaceInvitationAcceptService } from '../workspace-invitation-accept.service'
import { WorkspaceInvitationStore } from '../workspace-invitation.store'
import { WORKSPACE_REF, workspaceOptions, workspaceRow } from './workspace-service-harness'
import { invitationKey } from '../../constants/workspace-invitation-keys'
import type { AuthException } from '../../errors/auth-exception'
import type { IAuthHooks } from '../../interfaces/auth-hooks.interface'
import type {
  AuthMembership,
  IMembershipRepository
} from '../../interfaces/membership-repository.interface'
import type { AuthUser, IUserRepository } from '../../interfaces/user-repository.interface'
import type {
  BootstrapInvitationRecord,
  MemberInvitationRecord
} from '../../interfaces/workspace-invitation.interface'
import type { IWorkspaceRepository } from '../../interfaces/workspace-repository.interface'
import { AuthRedisService } from '../../redis/auth-redis.service'

/** The instant the clock is fixed at, so timestamps and lifetimes are exact. */
export const NOW = Date.parse('2026-01-10T12:00:00.000Z')

/** A raw invitation token: 64 characters, as the issuing side mints them. */
export const TOKEN = 'a'.repeat(64)

/** The address every record in these specs invites. */
export const EMAIL = 'invitee@example.com'

let port = 45_000

/**
 * An account.
 *
 * @param id - Its id; the address defaults to `{id}@example.com`.
 * @param overrides - Fields to change.
 */
export function user(id: string, overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    id,
    email: `${id}@example.com`,
    name: `Name of ${id}`,
    passwordHash: null,
    role: 'member',
    status: 'active',
    tenantId: 't1',
    emailVerified: true,
    mfaEnabled: false,
    lastLoginAt: null,
    createdAt: new Date(0),
    ...overrides
  }
}

/**
 * A membership of the workspace every record names.
 *
 * @param userId - The member.
 * @param role - The role they hold.
 * @param status - Their status; active by default.
 */
export function member(
  userId: string,
  role: string,
  status: AuthMembership['status'] = 'active'
): AuthMembership {
  return {
    ...WORKSPACE_REF,
    userId,
    role,
    status,
    invitedByUserId: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  }
}

/**
 * A member invitation record for `EMAIL`, issued by `inviter` as a viewer.
 *
 * @param overrides - Fields to change.
 */
export function memberRecord(
  overrides: Partial<MemberInvitationRecord> = {}
): MemberInvitationRecord {
  return {
    kind: 'member',
    email: EMAIL,
    role: 'viewer',
    ...WORKSPACE_REF,
    inviterUserId: 'inviter',
    createdAt: new Date(NOW).toISOString(),
    resendCount: 0,
    ...overrides
  }
}

/**
 * A platform bootstrap record for `EMAIL`, for a workspace named Acme.
 *
 * @param overrides - Fields to change.
 */
export function bootstrapRecord(
  overrides: Partial<BootstrapInvitationRecord> = {}
): BootstrapInvitationRecord {
  return {
    kind: 'bootstrap',
    email: EMAIL,
    role: 'owner',
    ...WORKSPACE_REF,
    createdAt: new Date(NOW).toISOString(),
    resendCount: 0,
    workspaceName: 'Acme',
    ...overrides
  }
}

/** The service under test, its real store, and every stubbed collaborator. */
export interface Harness {
  service: WorkspaceInvitationAcceptService
  store: WorkspaceInvitationStore
  users: { findById: jest.Mock; findByEmail: jest.Mock; create: jest.Mock }
  workspaces: { findById: jest.Mock; createWithOwner: jest.Mock }
  memberships: { find: jest.Mock; create: jest.Mock; countOwned: jest.Mock }
  access: { invalidateMembership: jest.Mock }
  events: { emit: jest.Mock }
  passwords: { assertAcceptable: jest.Mock; hash: jest.Mock }
  tokens: { issueTokens: jest.Mock }
  sessions: { createSession: jest.Mock }
  hooks: { afterInvitationAccepted?: jest.Mock; beforeWorkspaceCreate?: jest.Mock }
}

/** The stubbed repositories: an inviter who is an editor, and no one else a member. */
function stubRepositories(): Pick<Harness, 'users' | 'workspaces' | 'memberships'> {
  return {
    users: {
      findById: jest.fn(async ({ id }: { id: string }) =>
        id === 'caller' ? user('caller', { email: EMAIL }) : user(id)
      ),
      findByEmail: jest.fn().mockResolvedValue(null),
      create: jest.fn(async (data: { email: string; name: string }) =>
        user('new', { email: data.email, name: data.name })
      )
    },
    workspaces: {
      findById: jest.fn().mockResolvedValue(workspaceRow()),
      createWithOwner: jest.fn().mockResolvedValue({ status: 'created', workspace: workspaceRow() })
    },
    memberships: {
      find: jest.fn(async ({ userId }: { userId: string }) =>
        userId === 'inviter' ? member('inviter', 'editor') : null
      ),
      create: jest.fn().mockResolvedValue('ok'),
      countOwned: jest.fn().mockResolvedValue(0)
    }
  }
}

/** The stubbed collaborators that are not repositories. */
function stubCollaborators(): Pick<
  Harness,
  'access' | 'events' | 'passwords' | 'tokens' | 'sessions'
> {
  return {
    access: { invalidateMembership: jest.fn().mockResolvedValue(undefined) },
    events: { emit: jest.fn() },
    passwords: {
      assertAcceptable: jest.fn().mockResolvedValue(undefined),
      hash: jest.fn().mockResolvedValue('hash')
    },
    tokens: {
      issueTokens: jest
        .fn()
        .mockResolvedValue({ user: { id: 'new' }, accessToken: 'a', rawRefreshToken: 'r' })
    },
    sessions: { createSession: jest.fn().mockResolvedValue('sid') }
  }
}

/**
 * The service over an in-memory Redis and stubbed collaborators.
 *
 * @param sessionsEnabled - Whether sessions are on.
 * @param hooks - The host hooks to give the service.
 * @param workspaces - Workspace settings to add or override.
 */
export function build(
  sessionsEnabled = false,
  hooks: Harness['hooks'] = {},
  workspaces: Parameters<typeof workspaceOptions>[0] = {}
): Harness {
  const options = workspaceOptions(workspaces)
  Object.assign(options.sessions, { enabled: sessionsEnabled })
  const redis = new AuthRedisService(
    new RedisMock({ port: (port += 1) }) as Partial<Redis> as Redis,
    options
  )
  const store = new WorkspaceInvitationStore(redis, options)
  const repositories = stubRepositories()
  const others = stubCollaborators()
  const ceiling = new MembershipService(
    {} as Partial<IMembershipRepository> as IMembershipRepository,
    {} as never,
    {} as never,
    options
  )
  const service = new WorkspaceInvitationAcceptService(
    store,
    ceiling,
    others.access as Partial<WorkspaceAccessService> as WorkspaceAccessService,
    others.events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    others.passwords as Partial<PasswordService> as PasswordService,
    others.tokens as Partial<TokenManagerService> as TokenManagerService,
    others.sessions as Partial<SessionService> as SessionService,
    repositories.users as Partial<IUserRepository> as IUserRepository,
    repositories.workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
    repositories.memberships as Partial<IMembershipRepository> as IMembershipRepository,
    hooks as Partial<IAuthHooks> as IAuthHooks,
    options
  )
  return { service, store, ...repositories, ...others, hooks }
}

/** Publishes a record under `TOKEN` the way the issuing side does. */
export async function seed(
  h: Harness,
  record: MemberInvitationRecord | BootstrapInvitationRecord = memberRecord()
): Promise<void> {
  const outcome = await h.store.publish(
    { tenantId: record.tenantId, workspaceId: record.workspaceId },
    record.email,
    invitationKey(TOKEN),
    record,
    604_800,
    0,
    null
  )
  if (outcome !== 'published') throw new Error('seed failed')
}

/**
 * The error code a promise rejects with, or `undefined` when it resolves.
 *
 * @param promise - The call under test.
 */
export async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

/** The verified token of the signed-in caller. */
export const CALLER = { sub: 'caller', tenantId: 't1' }
/** The request facts a signup acceptance receives. */
export const REQUEST = { ip: '203.0.113.7', userAgent: 'jest', headers: { 'user-agent': 'jest' } }
/** A signup body for the invitation seeded under `TOKEN`. */
export const SIGNUP = { token: TOKEN, name: 'Ada Lovelace', password: 'correct horse battery' }
