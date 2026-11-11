/**
 * @fileoverview Resolves whether a user is an active member of a workspace, and with which role,
 * from a versioned Redis cache backed by the membership and workspace repositories.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger, Optional } from '@nestjs/common'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from '../bymax-auth.constants'
import { AccountStatusService } from './account-status.service'
import type { ResolvedOptions } from '../config/resolved-options'
import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import {
  BUMP_VERSION_SCRIPT,
  FILL_MEMBERSHIP_SCRIPT,
  READ_MEMBERSHIP_SCRIPT
} from '../constants/workspace-access-scripts'
import {
  WORKSPACE_VERSION_RETENTION_SECONDS,
  membershipCacheKeyBase,
  membershipVersionKey,
  workspaceVersionKey
} from '../constants/workspace-keys'
import { NO_CONTROL_CHARACTERS } from '../dto/no-control-characters'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type {
  IMembershipRepository,
  MembershipRef
} from '../interfaces/membership-repository.interface'
import type { WorkspaceJobContext } from '../interfaces/workspace-job-context.interface'
import type { WorkspaceRoleList } from '../interfaces/workspace-options.interface'
import type {
  IWorkspaceRepository,
  WorkspaceRef
} from '../interfaces/workspace-repository.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { exceedsCodePoints } from '../utils/code-points'
import { assertWorkspaceId } from '../utils/resolve-request-workspace'
import { assertWorkspaceAccess } from '../utils/workspace-access-decision'

/** An active member of an active workspace, as the access check resolves it. */
export interface ResolvedWorkspaceMember extends MembershipRef {
  /** The member's role in the workspace. */
  role: string
}

/**
 * What the rows say about a caller's access to a workspace.
 *
 * - `member`: an active member of an active workspace.
 * - `pending_deletion`: an active OWNER of a workspace pending deletion. Only an owner is told, so
 *   the answer lets a client offer to restore it; every other caller reads as `denied`.
 * - `denied`: anything else, a missing workspace, an inactive one and a non-member alike.
 *   `pendingDeletion` is set when the workspace is pending deletion and the caller is an active
 *   member who does not own it: still `denied` to the caller, but the host is told why.
 */
export type WorkspaceAccess =
  | { kind: 'member'; member: ResolvedWorkspaceMember }
  | { kind: 'pending_deletion'; member: ResolvedWorkspaceMember }
  | { kind: 'denied'; pendingDeletion?: true }

/** The version counters and the cached entry one Redis round trip returns. */
interface MembershipRead {
  workspaceVersion: string
  membershipVersion: string
  role: string | null
}

/**
 * Decides workspace access for one request.
 *
 * A request is allowed only for an ACTIVE membership of an ACTIVE workspace; every other state
 * reads as "not a member", so a caller cannot tell a workspace it may not enter from one that does
 * not exist.
 *
 * The cache is advisory. Redis being unreachable never fails a request: the answer then comes from
 * the repositories, which are authoritative, and nothing is written back.
 *
 * The repository reads that fill the cache must come from the primary or be read-your-writes: a
 * lagging replica would cache a removed member as present under the new version. A counter evicted
 * under memory pressure restarts at 0 and can make an entry written under 0:0 readable again for
 * up to its lifetime, the exposure the token-epoch counters have, so run the store with a
 * no-eviction policy for the auth keyspace.
 */
@Injectable()
export class WorkspaceAccessService {
  private readonly logger = new Logger(WorkspaceAccessService.name)
  private readonly group: ResolvedWorkspaceOptions

  constructor(
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_WORKSPACE_REPOSITORY)
    private readonly workspaceRepo: IWorkspaceRepository,
    @Inject(BYMAX_AUTH_MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: IMembershipRepository,
    @Inject(BYMAX_AUTH_OPTIONS) private readonly options: ResolvedOptions,
    @Inject(AccountStatusService)
    @Optional()
    private readonly accountStatus: AccountStatusService | null = null
  ) {
    if (options.workspaces === undefined) {
      throw new Error('[BymaxAuthModule] WorkspaceAccessService needs workspaces.enabled.')
    }
    this.group = options.workspaces
  }

  /**
   * Resolves a user's access to a workspace.
   *
   * @param ref - The tenant, workspace and user.
   * @returns The member and role when the membership AND the workspace are active, else `null`.
   * @throws {TypeError} When any part of the key is blank.
   */
  async resolveMembership(ref: MembershipRef): Promise<ResolvedWorkspaceMember | null> {
    const access = await this.resolveAccess(ref)
    return access.kind === 'member' ? access.member : null
  }

  /**
   * Resolves what the rows say about a caller's access to a workspace, without reading anything the
   * refusal needs beyond the two rows every refusal already reads.
   *
   * @param ref - The tenant, workspace and user.
   * @returns The access: `member`, `pending_deletion` for the owner of a workspace pending
   *   deletion, or `denied`.
   * @throws {TypeError} When any part of the key is blank.
   */
  async resolveAccess(ref: MembershipRef): Promise<WorkspaceAccess> {
    assertKey(ref)
    const ttl = this.group.membershipCacheTtlSeconds
    if (ttl === 0) return this.readRepositories(ref)

    const cached = await this.readCache(ref)
    if (cached !== null && cached.role !== null) {
      return { kind: 'member', member: { ...ref, role: cached.role } }
    }

    const access = await this.readRepositories(ref)
    if (cached !== null && access.kind === 'member') {
      await this.fillCache(ref, cached, access.member.role, ttl)
    }
    return access
  }

  /**
   * Answers whether an account may act in a workspace NOW, for work that runs apart from a request.
   *
   * A queued job can run long after the request that enqueued it, so its contract is "authorized at
   * this moment" and nothing cached may answer it. The workspace, the membership and the account
   * are all read from the repositories, never from the access cache or the status cache, and the
   * decision is the one a route's guard makes: the same refusals in the same order, with
   * `workspace_not_found` for anyone who is not an active member (and for every non-owner of a
   * workspace pending deletion). The account is judged first: a banned or deleted actor is refused
   * with that status's own code, which is the incident case where a queued job must not act. The
   * cost is three repository reads per call. The repositories must read from the primary.
   *
   * @param context - What was stamped at enqueue time.
   * @param roles - The roles that may perform the job's work.
   * @param options - `allowPending` admits the owner of a workspace pending deletion.
   * @returns The member, with the role they hold now.
   * @throws {AuthException} `auth.validation` naming the field for a malformed context, the
   *   status's own code or `auth.token_invalid` for an account that is blocked or gone, then
   *   `auth.workspace_not_found`, `auth.workspace_pending_deletion` or
   *   `auth.insufficient_workspace_role`.
   * @throws {TypeError} When the service was built without the account status service.
   */
  async assertStillAuthorized(
    context: WorkspaceJobContext,
    roles: WorkspaceRoleList,
    options: { allowPending?: boolean } = {}
  ): Promise<ResolvedWorkspaceMember> {
    if (this.accountStatus === null) {
      throw new TypeError('assertStillAuthorized needs the account status service')
    }
    // A payload that came back from a queue may not be an object at all.
    const claimed: Partial<WorkspaceJobContext> =
      typeof context === 'object' && context !== null ? context : {}
    const ref = {
      tenantId: assertBoundedText('tenantId', claimed.tenantId),
      workspaceId: assertWorkspaceId(claimed.workspaceId),
      userId: assertBoundedText('actorUserId', claimed.actorUserId)
    }
    await this.accountStatus.assertDashboardAccountUsableNow({
      userId: ref.userId,
      tenantId: ref.tenantId
    })
    return assertWorkspaceAccess(
      await this.readRepositories(ref),
      roles,
      this.group.roles.hierarchy,
      options.allowPending === true
    )
  }

  /**
   * Drops the cached access of one membership. Call it after changing a membership outside this
   * library; a host that cannot guarantee that sets `membershipCacheTtlSeconds: 0`.
   *
   * @param ref - The tenant, workspace and user.
   * @throws {TypeError} When any part of the key is blank.
   * @throws The Redis error when the bump fails: a change is never reported as invalidated.
   */
  async invalidateMembership(ref: MembershipRef): Promise<void> {
    assertKey(ref)
    await this.bump(
      membershipVersionKey(ref.tenantId, ref.workspaceId, ref.userId, this.options.hmacKey)
    )
  }

  /**
   * Drops the cached access of EVERY member of a workspace, for an event that changes the whole
   * workspace such as scheduling its deletion.
   *
   * @param ref - The tenant and workspace.
   * @throws {TypeError} When any part of the key is blank.
   * @throws The Redis error when the bump fails: a change is never reported as invalidated.
   */
  async invalidateWorkspace(ref: WorkspaceRef): Promise<void> {
    assertKey(ref)
    await this.bump(workspaceVersionKey(ref.tenantId, ref.workspaceId, this.options.hmacKey))
  }

  private async bump(key: string): Promise<void> {
    await this.redis.eval(BUMP_VERSION_SCRIPT, [key], [String(WORKSPACE_VERSION_RETENTION_SECONDS)])
  }

  private async readCache(ref: MembershipRef): Promise<MembershipRead | null> {
    try {
      const { hmacKey } = this.options
      const reply = await this.redis.eval(
        READ_MEMBERSHIP_SCRIPT,
        [
          workspaceVersionKey(ref.tenantId, ref.workspaceId, hmacKey),
          membershipVersionKey(ref.tenantId, ref.workspaceId, ref.userId, hmacKey),
          membershipCacheKeyBase(ref.tenantId, ref.workspaceId, ref.userId, hmacKey)
        ],
        []
      )
      return parseRead(reply)
    } catch {
      // The cache is advisory: an unreachable store must cost a repository read, not a request.
      this.logger.warn('Workspace membership cache unavailable; reading the repositories.')
      return null
    }
  }

  private async fillCache(
    ref: MembershipRef,
    read: MembershipRead,
    role: string,
    ttl: number
  ): Promise<void> {
    const { hmacKey } = this.options
    const base = membershipCacheKeyBase(ref.tenantId, ref.workspaceId, ref.userId, hmacKey)
    try {
      await this.redis.eval(
        FILL_MEMBERSHIP_SCRIPT,
        [
          workspaceVersionKey(ref.tenantId, ref.workspaceId, hmacKey),
          membershipVersionKey(ref.tenantId, ref.workspaceId, ref.userId, hmacKey),
          `${base}:${read.workspaceVersion}:${read.membershipVersion}`
        ],
        [
          JSON.stringify({ role, status: 'active' }),
          String(ttl),
          String(WORKSPACE_VERSION_RETENTION_SECONDS),
          read.workspaceVersion,
          read.membershipVersion
        ]
      )
    } catch {
      this.logger.warn('Workspace membership cache unavailable; the answer was not cached.')
    }
  }

  /**
   * Reads the workspace and the membership together, whatever the first one says.
   *
   * A missing workspace, an inactive one and a non-member then cost the same repository work, so
   * the time an answer takes does not tell a caller which of the three it was. The pending-deletion
   * answer for an owner is decided from these same two rows.
   */
  private async readRepositories(ref: MembershipRef): Promise<WorkspaceAccess> {
    const [workspace, membership] = await Promise.all([
      this.workspaceRepo.findById({ tenantId: ref.tenantId, workspaceId: ref.workspaceId }),
      this.membershipRepo.find(ref)
    ])
    if (membership?.status !== 'active' || workspace === null) return { kind: 'denied' }
    const member = { ...ref, role: membership.role }
    if (workspace.status === 'active') return { kind: 'member', member }
    if (workspace.status !== 'pending_deletion') return { kind: 'denied' }
    const ownsIt = membership.role === this.group.roles.ownerRole
    return ownsIt ? { kind: 'pending_deletion', member } : { kind: 'denied', pendingDeletion: true }
  }
}

/**
 * Requires every part of a key to be a non-blank string.
 *
 * @param ref - The key to check.
 * @throws {TypeError} Naming the blank part.
 */
function assertKey(ref: { tenantId: string; workspaceId: string; userId?: string }): void {
  for (const [part, value] of Object.entries(ref)) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new TypeError(`${part} must be a non-empty string`)
    }
  }
}

/**
 * Reads the script's reply into the versions and, when a valid active entry exists, its role.
 *
 * @param reply - What `READ_MEMBERSHIP_SCRIPT` returned.
 * @returns The versions and role, or `null` for a reply of another shape.
 */
function parseRead(reply: unknown): MembershipRead | null {
  if (!Array.isArray(reply) || reply.length !== 3) return null
  const [workspaceVersion, membershipVersion, entry] = reply as unknown[]
  if (typeof workspaceVersion !== 'string' || typeof membershipVersion !== 'string') return null
  return { workspaceVersion, membershipVersion, role: parseEntry(entry) }
}

/**
 * Reads a cache entry's role.
 *
 * @param entry - The stored value, or the empty string on a miss, which is not JSON and so reads
 *   as no entry.
 * @returns The role of an entry that is an active membership, else `null`.
 */
function parseEntry(entry: unknown): string | null {
  if (typeof entry !== 'string') return null
  try {
    const parsed = JSON.parse(entry) as { role?: unknown; status?: unknown }
    return typeof parsed.role === 'string' && parsed.status === 'active' ? parsed.role : null
  } catch {
    return null
  }
}

/**
 * Requires a field of a job's context to be a non-blank string of bounded length without control
 * characters, as the path parameter of a request is.
 *
 * @param field - The field's name, for the error.
 * @param value - What the context holds.
 * @returns The value.
 * @throws {AuthException} `auth.validation` naming the field.
 */
function assertBoundedText(field: string, value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.trim() === '' ||
    exceedsCodePoints(value, 128) ||
    !NO_CONTROL_CHARACTERS.test(value)
  ) {
    throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [
      {
        field,
        message: `${field} must be 1 to 128 characters, not blank, with no control characters`
      }
    ])
  }
  return value
}
