/**
 * @fileoverview Shared harness of the workspace invitation accept specs: an in-memory Redis, the
 * real store and ceiling, stubbed repositories and collaborators, and the records they accept.
 *
 * @layer Test
 */

/// <reference path="../../../../test/e2e/ioredis-mock.d.ts" />

import { Logger } from '@nestjs/common'
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
import {
  CONTEXT,
  WORKSPACE_REF,
  optionsWithoutWorkspaces,
  workspaceOptions,
  workspaceRow
} from './workspace-service-harness'
import { invitationKey } from '../../constants/workspace-invitation-keys'
import { AUTH_ERROR_CODES } from '../../errors/auth-error-codes'
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

export const NOW = Date.parse('2026-01-10T12:00:00.000Z')
export const TOKEN = 'a'.repeat(64)
export const EMAIL = 'invitee@example.com'
let port = 45_000

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

export interface Harness {
  service: WorkspaceInvitationAcceptService
  store: WorkspaceInvitationStore
  users: { findById: jest.Mock; findByEmail: jest.Mock; create: jest.Mock }
  workspaces: { findById: jest.Mock; createWithOwner: jest.Mock }
  memberships: { find: jest.Mock; create: jest.Mock }
  access: { invalidateMembership: jest.Mock }
  events: { emit: jest.Mock }
  passwords: { assertAcceptable: jest.Mock; hash: jest.Mock }
  tokens: { issueTokens: jest.Mock }
  sessions: { createSession: jest.Mock }
  hooks: { afterInvitationAccepted?: jest.Mock }
}

export function build(sessionsEnabled = false, hooks: Harness['hooks'] = {}): Harness {
  const options = workspaceOptions()
  Object.assign(options.sessions, { enabled: sessionsEnabled })
  const redis = new AuthRedisService(
    new RedisMock({ port: (port += 1) }) as Partial<Redis> as Redis,
    options
  )
  const store = new WorkspaceInvitationStore(redis, options)
  const users = {
    findById: jest.fn(async ({ id }: { id: string }) =>
      id === 'caller' ? user('caller', { email: EMAIL }) : user(id)
    ),
    findByEmail: jest.fn().mockResolvedValue(null),
    create: jest.fn(async (data: { email: string; name: string }) =>
      user('new', { email: data.email, name: data.name })
    )
  }
  const workspaces = {
    findById: jest.fn().mockResolvedValue(workspaceRow()),
    createWithOwner: jest.fn().mockResolvedValue({ status: 'created', workspace: workspaceRow() })
  }
  const memberships = {
    find: jest.fn(async ({ userId }: { userId: string }) =>
      userId === 'inviter' ? member('inviter', 'editor') : null
    ),
    create: jest.fn().mockResolvedValue('ok')
  }
  const access = { invalidateMembership: jest.fn().mockResolvedValue(undefined) }
  const events = { emit: jest.fn() }
  const passwords = {
    assertAcceptable: jest.fn().mockResolvedValue(undefined),
    hash: jest.fn().mockResolvedValue('hash')
  }
  const tokens = {
    issueTokens: jest
      .fn()
      .mockResolvedValue({ user: { id: 'new' }, accessToken: 'a', rawRefreshToken: 'r' })
  }
  const sessions = { createSession: jest.fn().mockResolvedValue('sid') }
  const ceiling = new MembershipService(
    {} as Partial<IMembershipRepository> as IMembershipRepository,
    {} as never,
    {} as never,
    options
  )
  const service = new WorkspaceInvitationAcceptService(
    store,
    ceiling,
    access as Partial<WorkspaceAccessService> as WorkspaceAccessService,
    events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    passwords as Partial<PasswordService> as PasswordService,
    tokens as Partial<TokenManagerService> as TokenManagerService,
    sessions as Partial<SessionService> as SessionService,
    users as Partial<IUserRepository> as IUserRepository,
    workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
    memberships as Partial<IMembershipRepository> as IMembershipRepository,
    hooks as Partial<IAuthHooks> as IAuthHooks,
    options
  )
  return {
    service,
    store,
    users,
    workspaces,
    memberships,
    access,
    events,
    passwords,
    tokens,
    sessions,
    hooks
  }
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

export async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

export const CALLER = { sub: 'caller', tenantId: 't1' }
export const REQUEST = { ip: '203.0.113.7', userAgent: 'jest', headers: { 'user-agent': 'jest' } }
export const SIGNUP = { token: TOKEN, name: 'Ada Lovelace', password: 'correct horse battery' }
