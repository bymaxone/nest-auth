/**
 * @fileoverview Shared harness of the workspace invitation service specs: an in-memory Redis, the
 * real store, and stubbed repositories, provider and hook.
 *
 * @layer Test
 */

/// <reference path="../../../../test/e2e/ioredis-mock.d.ts" />

import type { Redis } from 'ioredis'
import RedisMock from 'ioredis-mock'

import { WORKSPACE_REF, workspaceOptions, workspaceRow } from './workspace-service-harness'
import type { AuthException } from '../../errors/auth-exception'
import type { WorkspaceActor } from '../../interfaces/acting-member.interface'
import type { IEmailProvider, WorkspaceInviteData } from '../../interfaces/email-provider.interface'
import type {
  AuthMembership,
  IMembershipRepository
} from '../../interfaces/membership-repository.interface'
import type { AuthUser, IUserRepository } from '../../interfaces/user-repository.interface'
import type { IWorkspaceRepository } from '../../interfaces/workspace-repository.interface'
import { AuthRedisService } from '../../redis/auth-redis.service'
import { MembershipService } from '../membership.service'
import type { WorkspaceEventsService } from '../workspace-events.service'
import { WorkspaceInvitationService } from '../workspace-invitation.service'
import { WorkspaceInvitationStore } from '../workspace-invitation.store'

export const NOW = Date.parse('2026-01-10T12:00:00.000Z')
export const OWNER: WorkspaceActor = { userId: 'owner-1', role: 'owner' }
export const EDITOR: WorkspaceActor = { userId: 'editor-1', role: 'editor' }
export const COOLDOWN_MS = 60_000
let port = 43_000

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

export function membership(userId: string, status: AuthMembership['status']): AuthMembership {
  return {
    ...WORKSPACE_REF,
    userId,
    role: 'viewer',
    status,
    invitedByUserId: null,
    createdAt: new Date(0),
    updatedAt: new Date(0)
  }
}

export interface Harness {
  service: WorkspaceInvitationService
  store: WorkspaceInvitationStore
  redis: AuthRedisService
  users: { findById: jest.Mock; findByEmail: jest.Mock }
  workspaces: { findById: jest.Mock }
  memberships: { find: jest.Mock }
  email: { sendWorkspaceInvitation: jest.Mock }
  events: { emit: jest.Mock }
}

export function build(extra: Parameters<typeof workspaceOptions>[0] = {}): Harness {
  const options = workspaceOptions(extra)
  const redis = new AuthRedisService(
    new RedisMock({ port: (port += 1) }) as Partial<Redis> as Redis,
    options
  )
  const store = new WorkspaceInvitationStore(redis, options)
  const users = {
    findById: jest.fn(async ({ id }: { id: string }) => user(id)),
    findByEmail: jest.fn().mockResolvedValue(null)
  }
  const workspaces = { findById: jest.fn().mockResolvedValue(workspaceRow()) }
  const memberships = { find: jest.fn().mockResolvedValue(null) }
  const email = { sendWorkspaceInvitation: jest.fn().mockResolvedValue(undefined) }
  const events = { emit: jest.fn() }
  const ceiling = new MembershipService(
    {} as Partial<IMembershipRepository> as IMembershipRepository,
    {} as never,
    {} as never,
    options
  )
  const service = new WorkspaceInvitationService(
    store,
    redis,
    ceiling,
    events as Partial<WorkspaceEventsService> as WorkspaceEventsService,
    users as Partial<IUserRepository> as IUserRepository,
    workspaces as Partial<IWorkspaceRepository> as IWorkspaceRepository,
    memberships as Partial<IMembershipRepository> as IMembershipRepository,
    email as Partial<IEmailProvider> as IEmailProvider,
    options
  )
  return { service, store, redis, users, workspaces, memberships, email, events }
}

export async function code(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise
  } catch (error) {
    return (error as AuthException).getResponse
      ? ((error as AuthException).getResponse() as { error: { code: string } }).error.code
      : undefined
  }
  return undefined
}

export function sent(h: Harness, call = 0): { to: string; data: WorkspaceInviteData } {
  const args = h.email.sendWorkspaceInvitation.mock.calls[call] as [
    string,
    string,
    WorkspaceInviteData
  ]
  return { to: args[1], data: args[2] }
}
