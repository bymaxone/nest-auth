/**
 * @fileoverview Workspace invitations: invite an address, list the pending ones, resend, revoke,
 * and let a token holder preview what it is for.
 *
 * @layer Service
 */

import { Inject, Injectable } from '@nestjs/common'

import { MembershipService } from './membership.service'
import { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceInvitationStore } from './workspace-invitation.store'
import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import { inviterRateKey, invitationKey } from '../constants/workspace-invitation-keys'
import {
  INVITATIONS_PER_INVITER_PER_HOUR,
  INVITER_WINDOW_SECONDS,
  MAX_RESENDS,
  RESEND_COOLDOWN_SECONDS
} from '../constants/workspace-invitation-limits'
import { generateSecureToken, sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { WorkspaceActor } from '../interfaces/acting-member.interface'
import type { HookContext } from '../interfaces/auth-hooks.interface'
import type { IEmailProvider } from '../interfaces/email-provider.interface'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import type {
  StoredWorkspaceInvitation,
  WorkspaceInvitationPreview
} from '../interfaces/workspace-invitation.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository,
  WorkspaceRef
} from '../interfaces/workspace-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { describeChannelStatus } from '../utils/describe-error'
import { maskEmail } from '../utils/mask-email'
import { normalizeEmail } from '../utils/normalize-email'
import { pageInvitations } from '../utils/workspace-invitation-page'
import type { InvitationPage } from '../utils/workspace-invitation-page'

/** A live invitation and the key it is stored under. */
interface LiveInvitation {
  key: string
  record: StoredWorkspaceInvitation
}

/**
 * Issues and withdraws workspace invitations.
 *
 * A token is 32 random bytes and only its SHA-256 is stored, so a resend mints a new token and
 * retires the old one. One address has one live invitation per workspace; inviting it again is a
 * resend and is held to the resend limits. The role ceiling is the member ceiling: a member who is
 * not the owner invites only to a role strictly below their own, and acts only on invitations to
 * such roles. An invitation the actor may not act on reads as absent, so the routes confirm
 * nothing about it.
 */
@Injectable()
export class WorkspaceInvitationService {
  private readonly group: ResolvedWorkspaceOptions

  private readonly hmacKey: string

  constructor(
    @Inject(WorkspaceInvitationStore) private readonly store: WorkspaceInvitationStore,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(MembershipService) private readonly members: MembershipService,
    @Inject(WorkspaceEventsService) private readonly events: WorkspaceEventsService,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly users: IUserRepository,
    @Inject(BYMAX_AUTH_WORKSPACE_REPOSITORY) private readonly workspaces: IWorkspaceRepository,
    @Inject(BYMAX_AUTH_MEMBERSHIP_REPOSITORY) private readonly memberships: IMembershipRepository,
    @Inject(BYMAX_AUTH_EMAIL_PROVIDER) private readonly email: IEmailProvider,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    if (options.workspaces === undefined) {
      throw new Error('[BymaxAuthModule] WorkspaceInvitationService needs workspaces.enabled.')
    }
    this.group = options.workspaces
    this.hmacKey = options.hmacKey
  }

  /**
   * Refuses to boot when the configured email provider cannot deliver a workspace invitation.
   *
   * @throws When the provider implements no `sendWorkspaceInvitation`.
   */
  onModuleInit(): void {
    if (!this.email.sendWorkspaceInvitation) {
      throw new Error(
        'BymaxAuthModule: controllers.workspaceInvitations is enabled but the configured email ' +
          'provider implements no sendWorkspaceInvitation. The flow cannot deliver its token ' +
          'without it.'
      )
    }
  }

  /**
   * Invites an address to a workspace, or resends to one already invited.
   *
   * @param ref - The workspace.
   * @param actor - Who invites, with the role the guard resolved for them.
   * @param rawEmail - The invitee.
   * @param role - The role the invitation grants.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.validation` for a role outside the hierarchy,
   *   `auth.insufficient_workspace_role` above the actor's ceiling, `auth.already_member` for an
   *   active member, `auth.too_many_requests` at a limit or when the address changed under the
   *   call, `auth.workspace_not_found` when the workspace is gone.
   */
  async invite(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    rawEmail: string,
    role: string,
    context: HookContext
  ): Promise<void> {
    this.members.assertMayGrant(actor.role, role)
    const email = normalizeEmail(rawEmail)
    await this.takeInviterSlot(ref.tenantId, actor.userId)
    const indexed = await this.store.readByEmail(ref, email)
    const live = indexed?.record == null ? null : { key: indexed.key, record: indexed.record }
    if (live !== null) this.assertMayReissue(actor, live.record)
    const account = await this.assertNotMember(ref, email)
    await this.issue(
      { ref, actor, email, role, expected: indexed?.key ?? null, live, account },
      context
    )
  }

  /**
   * Sends a pending invitation again under a new token.
   *
   * An address with no pending invitation, or one the actor may not act on, is answered like a
   * success and changes nothing.
   *
   * @param ref - The workspace.
   * @param actor - Who resends.
   * @param rawEmail - The invitee.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.too_many_requests` inside the cooldown, past the resend limit, or
   *   when the address changed under the call.
   */
  async resend(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    rawEmail: string,
    context: HookContext
  ): Promise<void> {
    const email = normalizeEmail(rawEmail)
    const indexed = await this.store.readByEmail(ref, email)
    const live = indexed?.record == null ? null : { key: indexed.key, record: indexed.record }
    if (live === null || !this.members.mayActOn(actor.role, live.record.role)) return
    this.assertMayReissue(actor, live.record)
    await this.takeInviterSlot(ref.tenantId, actor.userId)
    const account = await this.users.findByEmail({ email, tenantId: ref.tenantId })
    await this.issue(
      { ref, actor, email, role: live.record.role, expected: live.key, live, account },
      context
    )
  }

  /**
   * Withdraws a pending invitation. An address with none, or one the actor may not act on, is
   * answered like a success and changes nothing.
   *
   * @param ref - The workspace.
   * @param actor - Who revokes.
   * @param rawEmail - The invitee.
   * @param context - Request metadata for the hook.
   */
  async revoke(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    rawEmail: string,
    context: HookContext
  ): Promise<void> {
    const email = normalizeEmail(rawEmail)
    const indexed = await this.store.readByEmail(ref, email)
    if (indexed?.record == null || !this.members.mayActOn(actor.role, indexed.record.role)) return
    await this.store.remove(ref, email, indexed.key)
    this.events.emit(
      {
        type: 'invitation.revoked',
        ...ref,
        actorUserId: actor.userId,
        email,
        role: indexed.record.role,
        at: new Date(Date.now()).toISOString()
      },
      context
    )
  }

  /**
   * Lists the workspace's pending invitations, oldest first.
   *
   * @param ref - The workspace.
   * @param page - The cursor and size.
   * @returns One page.
   */
  async list(
    ref: WorkspaceRef,
    page: { cursor?: string; limit?: number }
  ): Promise<InvitationPage> {
    return pageInvitations(await this.store.pending(ref), page, Date.now())
  }

  /**
   * Tells a token holder what the token is for, without signing in.
   *
   * Every token that cannot be previewed, whether it never existed, expired, was consumed, or names
   * a workspace or inviter that is gone, is answered with the same error after the same repository
   * reads: a stand-in lookup runs where the real one is missing, so neither the body nor the work
   * done separates one case from another.
   *
   * @param token - The raw token.
   * @returns What the invitation is for.
   * @throws {AuthException} `auth.invalid_invitation_token` for any token that cannot be previewed.
   */
  async preview(token: string): Promise<WorkspaceInvitationPreview> {
    const record = await this.store.readByHash(sha256(token))
    const probe = record ?? STAND_IN
    const [workspace, inviter, account] = await Promise.all([
      this.workspaces.findById({ tenantId: probe.tenantId, workspaceId: probe.workspaceId }),
      this.users.findById({ id: probe.inviterUserId, tenantId: probe.tenantId }),
      this.users.findByEmail({ email: probe.email, tenantId: probe.tenantId })
    ])
    if (record === null || workspace?.status !== 'active' || inviter === null) {
      throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    }
    return {
      workspaceName: workspace.name,
      inviterName: inviter.name,
      role: record.role,
      maskedEmail: maskEmail(record.email),
      accountExists: account !== null
    }
  }

  /** Counts one invitation against the inviter's hour, refusing the twenty-first. */
  private async takeInviterSlot(tenantId: string, userId: string): Promise<void> {
    const used = await this.redis.incrWithFixedTtl(
      inviterRateKey(tenantId, userId, this.hmacKey),
      INVITER_WINDOW_SECONDS
    )
    if (used > INVITATIONS_PER_INVITER_PER_HOUR) {
      throw new AuthException(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
    }
  }

  /** Refuses to replace an invitation the actor may not act on, or one sent too recently or often. */
  private assertMayReissue(actor: WorkspaceActor, record: StoredWorkspaceInvitation): void {
    if (!this.members.mayActOn(actor.role, record.role)) {
      throw new AuthException(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
    }
    const age = (Date.now() - Date.parse(record.createdAt)) / 1_000
    if (age < RESEND_COOLDOWN_SECONDS || record.resendCount >= MAX_RESENDS) {
      throw new AuthException(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
    }
  }

  /** Refuses an address that already belongs to the workspace; returns its account, if any. */
  private async assertNotMember(ref: WorkspaceRef, email: string): Promise<AuthUser | null> {
    const account = await this.users.findByEmail({ email, tenantId: ref.tenantId })
    if (account === null) return null
    const member = await this.memberships.find({ ...ref, userId: account.id })
    if (member?.status === 'active') throw new AuthException(AUTH_ERROR_CODES.ALREADY_MEMBER)
    return account
  }

  /** Mints a token, stores its record, retires the one it replaces, and mails it. */
  private async issue(plan: IssuePlan, context: HookContext): Promise<void> {
    const { ref, actor, email, role, live } = plan
    const workspace = await this.activeWorkspace(ref)
    const inviter = await this.users.findById({ id: actor.userId, tenantId: ref.tenantId })
    if (inviter === null) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)

    const token = generateSecureToken(32)
    const key = invitationKey(token)
    const ttl = this.group.invitationTtlSeconds
    const record: StoredWorkspaceInvitation = {
      email,
      role,
      tenantId: ref.tenantId,
      workspaceId: ref.workspaceId,
      inviterUserId: actor.userId,
      createdAt: new Date(Date.now()).toISOString(),
      resendCount: live === null ? 0 : live.record.resendCount + 1
    }
    // The index is claimed first: a crash before the record is written leaves an index naming
    // nothing, which reads as no invitation. Whether the claim held is decided by `publish`, which
    // writes only while the index still names this record.
    await this.store.claimIndex(ref, email, plan.expected, key, ttl)
    // A replacement takes the place of the record it retires, so only a first invitation is capped.
    const limit = live === null ? this.group.maxPendingInvitationsPerWorkspace : 0
    if ((await this.store.publish(ref, email, key, record, ttl, limit)) !== 'published') {
      // Releases the claim if this writer still holds it; a writer that lost it releases nothing.
      await this.store.remove(ref, email, key)
      throw new AuthException(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
    }
    if (live !== null) await this.store.remove(ref, email, live.key)

    await this.deliver(ref, email, workspace, inviter, record, token, plan.account !== null, ttl)
    this.events.emit(
      {
        type: live === null ? 'member.invited' : 'invitation.resent',
        ...ref,
        actorUserId: actor.userId,
        email,
        role,
        at: record.createdAt
      },
      context
    )
  }

  /** Mails the token. A failure is re-thrown without its text, which can quote the token. */
  private async deliver(
    ref: WorkspaceRef,
    email: string,
    workspace: AuthWorkspace,
    inviter: AuthUser,
    record: StoredWorkspaceInvitation,
    token: string,
    accountExists: boolean,
    ttl: number
  ): Promise<void> {
    try {
      await this.email.sendWorkspaceInvitation?.(ref.tenantId, email, {
        inviterName: inviter.name,
        workspaceName: workspace.name,
        role: record.role,
        inviteToken: token,
        expiresAt: new Date(Date.parse(record.createdAt) + ttl * 1_000),
        accountExists
      })
    } catch (err: unknown) {
      throw new Error(describeChannelStatus(err))
    }
  }

  private async activeWorkspace(ref: WorkspaceRef): Promise<AuthWorkspace> {
    const workspace = await this.workspaces.findById(ref)
    if (workspace?.status !== 'active') {
      throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    }
    return workspace
  }
}

/** Everything one issue needs, so the step that writes it takes one argument. */
interface IssuePlan {
  ref: WorkspaceRef
  actor: WorkspaceActor
  email: string
  role: string
  /** The record key the index held when it was read, or `null` for none. */
  expected: string | null
  /** The live invitation being replaced, or `null` for a first one. */
  live: LiveInvitation | null
  /** The account the address belongs to, when there is one. */
  account: AuthUser | null
}

/** Lookup values that match nothing, used where a token names nothing. */
const STAND_IN = {
  email: 'no-invitation@invalid.invalid',
  tenantId: '',
  workspaceId: '',
  inviterUserId: ''
}
