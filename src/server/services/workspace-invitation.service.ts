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
  GUARDED_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_OPTIONS,
  GUARDED_USER_REPOSITORY,
  GUARDED_WORKSPACE_REPOSITORY
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
import { randomUUID } from '../crypto/captured-crypto'
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
import { awaiting, checked, pinned, PinnedAll, started } from '../utils/settle'
import { pageInvitations } from '../utils/workspace-invitation-page'
import type { InvitationPage } from '../utils/workspace-invitation-page'
import { normalizeWorkspaceName } from '../utils/workspace-name'

/** How often a revoke reads an address again when its invitation is replaced under it. */
const REVOKE_ATTEMPTS = 3

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
@PinnedAll()
@Injectable()
export class WorkspaceInvitationService {
  private readonly group: ResolvedWorkspaceOptions

  private readonly hmacKey: string

  constructor(
    @Inject(WorkspaceInvitationStore) private readonly store: WorkspaceInvitationStore,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(MembershipService) private readonly members: MembershipService,
    @Inject(WorkspaceEventsService) private readonly events: WorkspaceEventsService,
    @Inject(GUARDED_USER_REPOSITORY) private readonly users: IUserRepository,
    @Inject(GUARDED_WORKSPACE_REPOSITORY) private readonly workspaces: IWorkspaceRepository,
    @Inject(GUARDED_MEMBERSHIP_REPOSITORY) private readonly memberships: IMembershipRepository,
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
   *   address that already has a membership, in any status, `auth.too_many_requests` at a limit or when the address changed under the
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
    await pinned(this.takeInviterSlot(ref.tenantId, actor.userId))
    const indexed = await pinned(this.store.readByEmail(ref, email))
    const live = indexed?.record == null ? null : { key: indexed.key, record: indexed.record }
    if (live !== null) this.assertMayReissue(actor, live.record)
    const account = await pinned(this.assertNotMember(ref, email))
    await pinned(
      this.issue(
        { ref, actor, email, role, expected: indexed?.key ?? null, live, account },
        context
      )
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
    const indexed = await pinned(this.store.readByEmail(ref, email))
    const live = indexed?.record == null ? null : { key: indexed.key, record: indexed.record }
    if (live === null || !this.members.mayActOn(actor.role, live.record.role)) return
    this.assertMayReissue(actor, live.record)
    await pinned(this.takeInviterSlot(ref.tenantId, actor.userId))
    const account = await pinned(this.users.findByEmail({ email, tenantId: ref.tenantId }))
    await pinned(
      this.issue(
        { ref, actor, email, role: live.record.role, expected: live.key, live, account },
        context
      )
    )
  }

  /**
   * Withdraws a pending invitation. An address with none, or one the actor may not act on, is
   * answered like a success and changes nothing. An invitation that replaces the one being
   * withdrawn is read again and held to the same ceiling.
   *
   * @param ref - The workspace.
   * @param actor - Who revokes.
   * @param rawEmail - The invitee.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.too_many_requests` when the invitation was replaced during each
   *   attempt to remove it.
   */
  async revoke(
    ref: WorkspaceRef,
    actor: WorkspaceActor,
    rawEmail: string,
    context: HookContext
  ): Promise<void> {
    await pinned(
      this.withdraw(
        ref,
        normalizeEmail(rawEmail),
        (record) => this.members.mayActOn(actor.role, record.role),
        actor.userId,
        context
      )
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
    return checked(pageInvitations(await pinned(this.store.pending(ref)), page, Date.now()))
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
    const record = await pinned(this.store.readByHash(sha256(token)))
    const probe = lookupOf(record)
    const workspaceRead = started(
      this.workspaces.findById({ tenantId: probe.tenantId, workspaceId: probe.workspaceId })
    )
    const inviterRead = started(
      this.users.findById({ id: probe.inviterUserId, tenantId: probe.tenantId })
    )
    const accountRead = started(
      this.users.findByEmail({ email: probe.email, tenantId: probe.tenantId })
    )
    const workspace = (await awaiting(workspaceRead)).value
    const inviter = (await awaiting(inviterRead)).value
    const account = (await awaiting(accountRead)).value
    if (record === null) throw invalidToken()
    const answer = {
      role: record.role,
      maskedEmail: maskEmail(record.email),
      accountExists: account !== null
    }
    if (record.kind === 'bootstrap') {
      // Its workspace does not exist yet; one that exists and is not active names nothing usable.
      if (workspace !== null && workspace.status !== 'active') throw invalidToken()
      const bootstrap = {
        kind: 'bootstrap',
        workspaceName: record.workspaceName,
        ...answer
      } as const
      return checked(bootstrap)
    }
    if (workspace?.status !== 'active' || inviter === null) throw invalidToken()
    const preview = {
      kind: 'member',
      workspaceName: workspace.name,
      inviterName: inviter.name,
      ...answer
    } as const
    return checked(preview)
  }

  /**
   * Invites an address to own a workspace that does not exist yet, on behalf of the platform.
   *
   * There is no route for it: the platform plane's authorization is the host's. The workspace and
   * its owner membership are created when the invitation is accepted, under the id returned here.
   * Each call is its own invitation to its own workspace; nothing is replaced.
   *
   * @param params - The tenant, the invitee, the workspace's name, and the inviter's display name
   *   for the message (it is not stored).
   * @param context - Request metadata for the hook.
   * @returns The id the workspace will be created with.
   * @throws {AuthException} `auth.validation` for an unusable workspace name.
   */
  async inviteAsPlatform(
    params: { tenantId: string; email: string; workspaceName: string; inviterName: string },
    context: HookContext
  ): Promise<{ workspaceId: string }> {
    const email = normalizeEmail(params.email)
    const workspaceName = normalizeWorkspaceName(params.workspaceName)
    const ref = { tenantId: params.tenantId, workspaceId: randomUUID() }
    const token = generateSecureToken(32)
    const ttl = this.group.invitationTtlSeconds
    const record: StoredWorkspaceInvitation = {
      kind: 'bootstrap',
      email,
      role: this.group.roles.ownerRole,
      ...ref,
      createdAt: new Date(Date.now()).toISOString(),
      resendCount: 0,
      workspaceName
    }
    const outcome = await pinned(
      this.store.publish(ref, email, invitationKey(token), record, ttl, 0, null)
    )
    // The id is fresh, so nothing can already hold its index.
    if (outcome !== 'published') throw new AuthException(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
    const account = await pinned(this.users.findByEmail({ email, tenantId: ref.tenantId }))
    await pinned(
      this.deliver(
        ref,
        email,
        workspaceName,
        params.inviterName,
        record,
        token,
        account !== null,
        ttl
      )
    )
    this.events.emit(
      {
        type: 'member.invited',
        ...ref,
        actorUserId: null,
        email,
        role: record.role,
        at: record.createdAt
      },
      context
    )
    return checked({ workspaceId: ref.workspaceId })
  }

  /**
   * Withdraws a platform bootstrap invitation. An address with none, or with an ordinary member
   * invitation, is answered like a success and changes nothing. A replacement of the invitation
   * being withdrawn is read again and removed only if it is a bootstrap one too.
   *
   * @param ref - The workspace id `inviteAsPlatform` returned.
   * @param rawEmail - The invitee.
   * @param context - Request metadata for the hook.
   * @throws {AuthException} `auth.too_many_requests` when the invitation was replaced during each
   *   attempt to remove it.
   */
  async revokeAsPlatform(ref: WorkspaceRef, rawEmail: string, context: HookContext): Promise<void> {
    await pinned(
      this.withdraw(
        ref,
        normalizeEmail(rawEmail),
        (record) => record.kind === 'bootstrap',
        null,
        context
      )
    )
  }

  /**
   * Removes the address's invitation and reports it, when `mayWithdraw` accepts what is there.
   *
   * The report is for a removal only. When the index stops naming the record, before the record is
   * read or before it is removed, the address is read again and what replaced it is judged anew.
   *
   * @param ref - The workspace.
   * @param email - The invitee, normalized.
   * @param mayWithdraw - Whether this caller may remove the record it is shown.
   * @param actorUserId - Who revokes, or `null` for the platform.
   * @param context - Request metadata for the hook.
   */
  private async withdraw(
    ref: WorkspaceRef,
    email: string,
    mayWithdraw: (record: StoredWorkspaceInvitation) => boolean,
    actorUserId: string | null,
    context: HookContext
  ): Promise<void> {
    for (let attempt = 0; attempt < REVOKE_ATTEMPTS; attempt += 1) {
      const indexed = await pinned(this.store.readByEmail(ref, email))
      if (indexed === null) return
      if (indexed.record === null) {
        // A publish deletes the record it replaces, so a record that is gone may have a successor.
        if (await pinned(this.store.names(ref, email, indexed.key))) return
        continue
      }
      if (!mayWithdraw(indexed.record)) return
      const removed = await pinned(this.store.remove(ref, email, indexed.key))
      if (!removed) continue
      const { role } = indexed.record
      const at = new Date(Date.now()).toISOString()
      this.events.emit(
        { type: 'invitation.revoked', ...ref, actorUserId, email, role, at },
        context
      )
      return
    }
    throw new AuthException(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)
  }

  /** Counts one invitation against the inviter's hour, refusing the twenty-first. */
  private async takeInviterSlot(tenantId: string, userId: string): Promise<void> {
    const used = await pinned(
      this.redis.incrWithFixedTtl(
        inviterRateKey(tenantId, userId, this.hmacKey),
        INVITER_WINDOW_SECONDS
      )
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

  /** Refuses an address that already has a membership of the workspace; returns its account. */
  private async assertNotMember(ref: WorkspaceRef, email: string): Promise<AuthUser | null> {
    const account = await pinned(this.users.findByEmail({ email, tenantId: ref.tenantId }))
    if (account === null) return null
    const member = await pinned(this.memberships.find({ ...ref, userId: account.id }))
    // A suspended member is still a member: an invitation cannot reinstate one.
    if (member !== null) throw new AuthException(AUTH_ERROR_CODES.ALREADY_MEMBER)
    return checked(account)
  }

  /** Mints a token, stores its record, retires the one it replaces, and mails it. */
  private async issue(plan: IssuePlan, context: HookContext): Promise<void> {
    const { ref, actor, email, role, live } = plan
    const workspace = await pinned(this.activeWorkspace(ref))
    const inviter = await pinned(this.users.findById({ id: actor.userId, tenantId: ref.tenantId }))
    if (inviter === null) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)

    const token = generateSecureToken(32)
    const key = invitationKey(token)
    const ttl = this.group.invitationTtlSeconds
    const record: StoredWorkspaceInvitation = {
      kind: 'member',
      email,
      role,
      tenantId: ref.tenantId,
      workspaceId: ref.workspaceId,
      inviterUserId: actor.userId,
      createdAt: new Date(Date.now()).toISOString(),
      resendCount: live === null ? 0 : live.record.resendCount + 1
    }
    // A replacement takes the place of the record it retires, so only a first invitation is capped.
    const limit = live === null ? this.group.maxPendingInvitationsPerWorkspace : 0
    const outcome = await pinned(
      this.store.publish(ref, email, key, record, ttl, limit, plan.expected)
    )
    if (outcome !== 'published') throw new AuthException(AUTH_ERROR_CODES.TOO_MANY_REQUESTS)

    await pinned(
      this.deliver(
        ref,
        email,
        workspace.name,
        inviter.name,
        record,
        token,
        plan.account !== null,
        ttl
      )
    )
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
    workspaceName: string,
    inviterName: string,
    record: StoredWorkspaceInvitation,
    token: string,
    accountExists: boolean,
    ttl: number
  ): Promise<void> {
    try {
      await pinned(
        this.email.sendWorkspaceInvitation?.(ref.tenantId, email, {
          inviterName,
          workspaceName,
          role: record.role,
          inviteToken: token,
          expiresAt: new Date(Date.parse(record.createdAt) + ttl * 1_000),
          accountExists,
          kind: record.kind
        })
      )
    } catch (err: unknown) {
      throw new Error(describeChannelStatus(err))
    }
  }

  private async activeWorkspace(ref: WorkspaceRef): Promise<AuthWorkspace> {
    const workspace = await pinned(this.workspaces.findById(ref))
    if (workspace?.status !== 'active') {
      throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
    }
    return checked(workspace)
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

/**
 * The values a preview looks up for a record: its own, with the stand-in inviter where the record
 * has none, so every token costs the same three reads.
 */
function lookupOf(record: StoredWorkspaceInvitation | null): typeof STAND_IN {
  if (record === null) return STAND_IN
  return {
    email: record.email,
    tenantId: record.tenantId,
    workspaceId: record.workspaceId,
    inviterUserId: record.kind === 'member' ? record.inviterUserId : STAND_IN.inviterUserId
  }
}

/** The one answer for a token that cannot be previewed. */
function invalidToken(): AuthException {
  return new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
}
