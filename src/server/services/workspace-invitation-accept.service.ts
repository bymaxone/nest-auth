/**
 * @fileoverview Accepting a workspace invitation: by a signed-in account whose address it names,
 * or by a holder with no account yet, who creates one.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'

import { MembershipService } from './membership.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'
import { WorkspaceAccessService } from './workspace-access.service'
import { WorkspaceEventsService } from './workspace-events.service'
import { WorkspaceInvitationStore } from './workspace-invitation.store'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import { sha256 } from '../crypto/secure-token'
import type { AcceptWorkspaceInvitationSignupDto } from '../dto/accept-workspace-invitation-signup.dto'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { AuthResult } from '../interfaces/auth-result.interface'
import type { IMembershipRepository } from '../interfaces/membership-repository.interface'
import type {
  AuthUser,
  IUserRepository,
  SafeAuthUser
} from '../interfaces/user-repository.interface'
import type {
  BootstrapInvitationRecord,
  StoredWorkspaceInvitation
} from '../interfaces/workspace-invitation.interface'
import type {
  IWorkspaceRepository,
  WorkspaceRef
} from '../interfaces/workspace-repository.interface'
import { assertNotBlocked } from '../utils/assert-not-blocked'
import { toSafeUser } from '../utils/mfa-safe-user'
import { normalizeEmail } from '../utils/normalize-email'
import { runDetached } from '../utils/run-detached'
import { sanitizeHeaders } from '../utils/sanitize-headers'

/** What a signed-in acceptance answers: where the caller now belongs, and as what. */
export interface AcceptedInvitation {
  /** The workspace the caller joined. */
  workspaceId: string
  /** The role they hold there. */
  role: string
}

/** What a signup acceptance answers: the new account's session and where it now belongs. */
export interface AcceptedSignup {
  /** The session, issued as a sign-in would. */
  result: AuthResult
  /** The workspace joined and the role held there. */
  accepted: AcceptedInvitation
}

/** The request facts a signup acceptance needs for its session and its hook. */
export interface SignupRequest {
  /** The client address. */
  ip: string
  /** The `User-Agent` header. */
  userAgent: string
  /** The raw request headers, for the hook. */
  headers: Record<string, string | string[] | undefined>
}

/** A record read by its token, with the key it is stored under. */
export interface LoadedInvitation {
  /** The key the record is stored under. */
  key: string
  /** The record. */
  record: StoredWorkspaceInvitation
}

/**
 * Accepts workspace invitations.
 *
 * The order is the contract: everything that can be decided without spending the token is decided
 * first, the membership is written next, and the token is consumed only after that. A failure
 * before the write leaves the invitation usable; a failure after it retries into an existing
 * membership, which counts as success, so the invitee is never left without the invitation they
 * were promised and the token cannot be used twice by anyone but the one address it names.
 */
@Injectable()
export class WorkspaceInvitationAcceptService {
  private readonly logger = new Logger(WorkspaceInvitationAcceptService.name)

  private readonly group: ResolvedWorkspaceOptions

  constructor(
    @Inject(WorkspaceInvitationStore) private readonly store: WorkspaceInvitationStore,
    @Inject(MembershipService) private readonly ceiling: MembershipService,
    @Inject(WorkspaceAccessService) private readonly access: WorkspaceAccessService,
    @Inject(WorkspaceEventsService) private readonly events: WorkspaceEventsService,
    @Inject(PasswordService) private readonly passwords: PasswordService,
    @Inject(TokenManagerService) private readonly tokens: TokenManagerService,
    @Inject(SessionService) private readonly sessions: SessionService,
    @Inject(BYMAX_AUTH_USER_REPOSITORY) private readonly users: IUserRepository,
    @Inject(BYMAX_AUTH_WORKSPACE_REPOSITORY) private readonly workspaces: IWorkspaceRepository,
    @Inject(BYMAX_AUTH_MEMBERSHIP_REPOSITORY) private readonly memberships: IMembershipRepository,
    @Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions
  ) {
    if (options.workspaces === undefined) {
      throw new Error(
        '[BymaxAuthModule] WorkspaceInvitationAcceptService needs workspaces.enabled.'
      )
    }
    this.group = options.workspaces
  }

  /**
   * Accepts an invitation as a signed-in account.
   *
   * @param caller - The verified token's subject and tenant.
   * @param token - The raw invitation token.
   * @param context - Request metadata for the hook.
   * @returns The workspace the caller joined and the role they hold there, which is the role they
   *   already held when they were a member before.
   * @throws {AuthException} `auth.invalid_invitation_token` for a token that cannot be honoured,
   *   whatever the reason; `auth.invitation_email_mismatch` when the caller's address is not the
   *   invited one and `auth.email_not_verified` when it is but is not verified, each with the
   *   token left unspent; `auth.workspace_limit_reached` for a bootstrap invitation the caller may
   *   not own another workspace of.
   */
  async accept(
    caller: { sub: string; tenantId: string },
    token: string,
    context: HookContext
  ): Promise<AcceptedInvitation> {
    const loaded = await this.load(token)
    const user = await this.users.findById({ id: caller.sub, tenantId: caller.tenantId })
    if (user === null) throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    if (user.tenantId !== loaded.record.tenantId) throw invalidToken()
    assertAddress(loaded.record, user.email, user.emailVerified)
    await this.assertStillGrantable(loaded.record)
    return this.finish(loaded, user, context)
  }

  /**
   * Vets an invitation against the profile an OAuth provider returned, before the account it is
   * for exists or is known. Nothing is written and the token is not spent.
   *
   * @param tokenHash - The sha256 the OAuth state record carries, never the raw token.
   * @param tenantId - The tenant the OAuth flow resolved to.
   * @param profile - The provider's address for the person and whether the provider verified it.
   * @returns The record, to be handed to {@link completeOAuth}.
   * @throws {AuthException} `auth.invalid_invitation_token` for a record that cannot be honoured
   *   or is another tenant's; `auth.invitation_email_mismatch` when the address is not the invited
   *   one and `auth.email_not_verified` when it is but the provider did not verify it.
   */
  async prepareOAuth(
    tokenHash: string,
    tenantId: string,
    profile: { email: string; emailVerified: boolean }
  ): Promise<LoadedInvitation> {
    const loaded = await this.loadByHash(tokenHash)
    if (loaded.record.tenantId !== tenantId) throw invalidToken()
    assertAddress(loaded.record, profile.email, profile.emailVerified)
    await this.assertStillGrantable(loaded.record)
    return loaded
  }

  /**
   * Completes an invitation vetted by {@link prepareOAuth} for the account the OAuth flow signs in.
   *
   * The account must be the invited address in the invitation's tenant. The membership is written
   * first and the token spent after, as for every acceptance, and a bootstrap invitation applies
   * the owner cap and the host's `beforeWorkspaceCreate` before it creates the workspace.
   *
   * @param loaded - What {@link prepareOAuth} returned.
   * @param user - The account the flow signed in.
   * @param created - Whether the flow created the account, which is when the host's
   *   after-acceptance hook runs.
   * @param context - Request metadata for the hooks.
   * @returns The workspace joined and the role held there.
   * @throws {AuthException} The refusals of {@link accept} for the account, and
   *   `auth.workspace_limit_reached` or `auth.forbidden` for a bootstrap invitation the account may
   *   not own another workspace of; none of them spends the token.
   */
  async completeOAuth(
    loaded: LoadedInvitation,
    user: AuthUser,
    created: boolean,
    context: HookContext
  ): Promise<AcceptedInvitation> {
    if (user.tenantId !== loaded.record.tenantId) throw invalidToken()
    assertAddress(loaded.record, user.email, user.emailVerified)
    const accepted = await this.finish(loaded, user, context)
    if (created) {
      runDetached(
        this.logger,
        () => this.hooks.afterInvitationAccepted?.(toSafeUser(user), context),
        'afterInvitationAccepted hook threw'
      )
    }
    return accepted
  }

  /**
   * Accepts an invitation by creating the account it was addressed to.
   *
   * @param dto - The token and the new account's name and password.
   * @param request - The request facts for the session and the hook.
   * @returns The new account's session, issued as a sign-in would.
   * @throws {AuthException} `auth.invalid_invitation_token`; `auth.email_already_exists` when the
   *   address already has an account, whose holder signs in and uses {@link accept}; and whatever
   *   the password policy refuses.
   */
  async acceptSignup(
    dto: AcceptWorkspaceInvitationSignupDto,
    request: SignupRequest
  ): Promise<AcceptedSignup> {
    const loaded = await this.load(dto.token)
    await this.assertStillGrantable(loaded.record)
    const { email, tenantId } = loaded.record
    if ((await this.users.findByEmail({ email, tenantId })) !== null) {
      throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    }
    // Judged before anything is written or spent: a refused password is the invitee's mistake to
    // correct, and the invitation must still be there when they do.
    await this.passwords.assertAcceptable(dto.password, 'password')
    const created = await this.createAccount(dto, email, tenantId)
    const context: HookContext = {
      plane: 'dashboard',
      tenantId,
      userId: created.id,
      ip: request.ip,
      userAgent: request.userAgent,
      sanitizedHeaders: sanitizeHeaders(request.headers)
    }
    const accepted = await this.finish(loaded, created, context)
    return { result: await this.signIn(toSafeUser(created), request, context), accepted }
  }

  /**
   * Creates the account, answering a concurrent creation of the same address as the account that
   * already exists, whatever error the repository raised for it.
   */
  private async createAccount(
    dto: AcceptWorkspaceInvitationSignupDto,
    email: string,
    tenantId: string
  ): Promise<AuthUser> {
    const passwordHash = await this.passwords.hash(dto.password)
    try {
      // The invitation reached this address, which is what verification proves.
      return await this.users.create({
        email,
        name: dto.name,
        passwordHash,
        tenantId,
        emailVerified: true
      })
    } catch (error: unknown) {
      if ((await this.users.findByEmail({ email, tenantId })) !== null) {
        throw new AuthException(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
      }
      throw error
    }
  }

  /** Reads the record a token names, or refuses a token that names nothing usable. */
  private async load(token: string): Promise<LoadedInvitation> {
    return this.loadByHash(sha256(token))
  }

  /** Reads the record a token's hash names, or refuses a hash that names nothing usable. */
  private async loadByHash(tokenHash: string): Promise<LoadedInvitation> {
    const record = await this.store.readByHash(tokenHash)
    if (record === null || !this.grantsAKnownRole(record)) throw invalidToken()
    return { key: `winv:${tokenHash}`, record }
  }

  /** A member record grants a role of the hierarchy; a bootstrap record grants the owner role. */
  private grantsAKnownRole(record: StoredWorkspaceInvitation): boolean {
    return record.kind === 'bootstrap'
      ? record.role === this.group.roles.ownerRole
      : Object.hasOwn(this.group.roles.hierarchy, record.role)
  }

  /**
   * Re-checks what was true of the inviter and the workspace when the invitation was minted.
   *
   * An invitation delegates authority, and authority is revocable, so it is judged again at
   * redemption. Every failure answers as an invalid token: the redeemer did not lose the
   * authority, and the reason would describe someone else's account.
   */
  private async assertStillGrantable(record: StoredWorkspaceInvitation): Promise<void> {
    const ref = refOf(record)
    const workspace = await this.workspaces.findById(ref)
    if (record.kind === 'bootstrap') {
      // A bootstrap invitation is accepted before its workspace exists, or again after it was
      // created but before the token was spent.
      if (workspace !== null && workspace.status !== 'active') throw invalidToken()
      return
    }
    if (workspace?.status !== 'active') throw invalidToken()
    const inviter = await this.users.findById({
      id: record.inviterUserId,
      tenantId: record.tenantId
    })
    const membership = await this.memberships.find({ ...ref, userId: record.inviterUserId })
    const stands =
      inviter !== null &&
      isInGoodStanding(inviter, this.options.blockedStatuses) &&
      inviter.tenantId === record.tenantId &&
      membership?.status === 'active' &&
      this.ceiling.mayActOn(membership.role, record.role)
    if (!stands) {
      this.logger.warn('workspace invitation: the inviter can no longer grant the invited role')
      throw invalidToken()
    }
  }

  /**
   * Writes the membership, then spends the token, then tells the cache and the hook.
   *
   * The acceptance takes effect when the membership is written. A revoke or a resend that lands
   * between the write and the spend therefore cannot undo it: the token's own record is deleted
   * regardless, the index and the set entry only while they still name it, and the hook event says
   * the spend lost the race.
   */
  private async finish(
    loaded: LoadedInvitation,
    user: AuthUser,
    context: HookContext
  ): Promise<AcceptedInvitation> {
    const { record } = loaded
    const ref = refOf(record)
    const role = await this.join(record, user, context)
    const spent = await this.store.remove(ref, record.email, loaded.key)
    await this.access.invalidateMembership({ ...ref, userId: user.id })
    this.events.emit(
      {
        type: 'invitation.accepted',
        ...ref,
        actorUserId: user.id,
        email: record.email,
        role,
        userId: user.id,
        at: new Date(Date.now()).toISOString(),
        ...(spent ? {} : { lostConsumeRace: true })
      },
      context
    )
    return { workspaceId: record.workspaceId, role }
  }

  /**
   * Makes the account a member of the workspace it was invited to, or of the one it will own.
   *
   * @returns The role the account holds there.
   */
  private async join(
    record: StoredWorkspaceInvitation,
    user: AuthUser,
    context: HookContext
  ): Promise<string> {
    const ref = refOf(record)
    const at = new Date(Date.now()).toISOString()
    if (record.kind === 'bootstrap') return this.createOwned(record, user, at, context)
    const created = await this.memberships.create({
      ...ref,
      userId: user.id,
      role: record.role,
      invitedByUserId: record.inviterUserId,
      audit: {
        type: 'invitation.accepted',
        ...ref,
        actorUserId: user.id,
        email: record.email,
        role: record.role,
        userId: user.id,
        at
      }
    })
    if (created === 'workspace_not_found') throw invalidToken()
    if (created === 'ok') return record.role
    // Already a member: the invitation is spent and changes nothing, so the answer is the role
    // they hold, not the one the invitation offered. A membership that is not active is not one
    // the invitation can reinstate, and it is not spent for it.
    const existing = await this.memberships.find({ ...ref, userId: user.id })
    if (existing?.status !== 'active') throw invalidToken()
    return existing.role
  }

  /** Creates the workspace a bootstrap invitation was for, owned by the accepting account. */
  private async createOwned(
    record: BootstrapInvitationRecord,
    user: AuthUser,
    at: string,
    context: HookContext
  ): Promise<string> {
    const ref = refOf(record)
    const existing = await this.workspaces.findById(ref)
    if (existing !== null) {
      // Created by an earlier attempt that did not get to spend the token. It is read again here,
      // so it is judged again: a workspace that stopped being active in between is not joined.
      if (existing.status !== 'active') throw invalidToken()
      const member = await this.memberships.find({ ...ref, userId: user.id })
      if (member?.status !== 'active' || member.role !== record.role) throw invalidToken()
      return record.role
    }
    await this.assertMayOwnAnother(record, user, context)
    const created = await this.workspaces.createWithOwner({
      ...ref,
      name: record.workspaceName,
      ownerUserId: user.id,
      ownerRole: record.role,
      maxWorkspacesPerUser: this.group.maxWorkspacesPerUser,
      audit: { type: 'workspace.created', ...ref, actorUserId: user.id, at }
    })
    if (created.status === 'limit_reached') {
      throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED)
    }
    return record.role
  }

  /**
   * Applies to a bootstrap acceptance what the create route applies to a workspace the account
   * creates itself, except the self-serve switch: the owner cap, then the host's
   * `beforeWorkspaceCreate`. The platform has already decided that this account may own a
   * workspace, but the host's plan or quota may have changed since, and the acceptance can land
   * days after the invitation. A refusal does not spend the token.
   *
   * @throws {AuthException} `auth.workspace_limit_reached` at the cap, `auth.forbidden` naming
   *   `name` with the hook's reason when the hook refuses.
   */
  private async assertMayOwnAnother(
    record: BootstrapInvitationRecord,
    user: AuthUser,
    context: HookContext
  ): Promise<void> {
    const { maxWorkspacesPerUser } = this.group
    if (maxWorkspacesPerUser > 0) {
      const owned = await this.memberships.countOwned({
        tenantId: record.tenantId,
        userId: user.id,
        ownerRole: record.role
      })
      if (owned >= maxWorkspacesPerUser) {
        throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_LIMIT_REACHED)
      }
    }
    const verdict = await this.hooks.beforeWorkspaceCreate?.(
      toSafeUser(user),
      { name: record.workspaceName },
      context
    )
    if (verdict !== undefined && !verdict.allowed) {
      throw new AuthException(AUTH_ERROR_CODES.FORBIDDEN, [
        { field: 'name', message: verdict.reason ?? 'Workspace creation was refused' }
      ])
    }
  }

  /** Issues the new account's session as a sign-in does, and fires the host's hook. */
  private async signIn(
    user: SafeAuthUser,
    request: SignupRequest,
    context: HookContext
  ): Promise<AuthResult> {
    const result = await this.tokens.issueTokens(user, request.ip, request.userAgent)
    if (this.options.sessions.enabled) {
      await this.sessions.createSession({
        userId: user.id,
        tenantId: user.tenantId,
        rawRefreshToken: result.rawRefreshToken,
        ip: request.ip,
        userAgent: request.userAgent
      })
    }
    runDetached(
      this.logger,
      () => this.hooks.afterInvitationAccepted?.(user, context),
      'afterInvitationAccepted hook threw'
    )
    return result
  }
}

/**
 * Refuses an address that is not the invited one, then one that is but is not verified.
 *
 * @throws {AuthException} `auth.invitation_email_mismatch`, or `auth.email_not_verified`.
 */
function assertAddress(record: StoredWorkspaceInvitation, email: string, verified: boolean): void {
  if (normalizeEmail(email) !== record.email) {
    throw new AuthException(AUTH_ERROR_CODES.INVITATION_EMAIL_MISMATCH)
  }
  if (!verified) throw new AuthException(AUTH_ERROR_CODES.EMAIL_NOT_VERIFIED)
}

/** The one answer for every token that cannot be honoured. */
function invalidToken(): AuthException {
  return new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
}

/** The workspace a record names. */
function refOf(record: StoredWorkspaceInvitation): WorkspaceRef {
  return { tenantId: record.tenantId, workspaceId: record.workspaceId }
}

/** Whether an account's status is outside the blocked set. */
function isInGoodStanding(user: { status: string }, blocked: readonly string[]): boolean {
  try {
    assertNotBlocked(user.status, blocked)
    return true
  } catch {
    return false
  }
}
