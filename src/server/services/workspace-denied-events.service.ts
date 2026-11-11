/**
 * @fileoverview The single emitter of `access.denied`: tells the host's `onWorkspaceEvent` hook
 * that an account was refused a workspace, bounded per account so a probe cannot flood the hook.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'

import { WorkspaceEventsService } from './workspace-events.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { userSubject } from '../constants/user-subject'
import { hmacSha256 } from '../crypto/secure-token'
import { WorkspaceAccessRefusal } from '../errors/workspace-access-refusal'
import type { WorkspaceAuditEvent } from '../interfaces/workspace-audit.interface'
import { AuthRedisService } from '../redis/auth-redis.service'
import { runDetached } from '../utils/run-detached'

/** How long a suppressed count is kept: it must outlive any window, which is capped at one hour. */
const SUPPRESSED_COUNT_TTL_SECONDS = 86_400

type DeniedEvent = Extract<WorkspaceAuditEvent, { type: 'access.denied' }>

/** Who was refused, where, and in which workspace. */
export interface DeniedAccess {
  /** The tenant, from the verified token. */
  readonly tenantId: string
  /** The account, from the verified token. */
  readonly userId: string
  /** The workspace that was named, after it has been validated. */
  readonly workspaceId: string
  /** The surface that refused. */
  readonly surface: DeniedEvent['surface']
}

/**
 * Runs a workspace access decision and reports its refusal.
 *
 * The decision is never affected: a refusal is rethrown unchanged and at once, and the report is
 * made afterwards, detached, so a slow or failing Redis or hook cannot delay or change the answer.
 *
 * Per account (the tenant and the user together) at most `max` events are emitted in a fixed window
 * of `windowSeconds`, counted in one key whose expiry is set by its first denial. A denial past the
 * limit is not emitted but counted in a second key that outlives the window by a long way, and the
 * next event that is emitted reads and clears it with one atomic step and carries it as
 * `suppressedCount`, so a client that probes past the limit and then stops is still visible. The
 * two keys are two slots, which is fine: the order of the steps is what matters, and a lost
 * increment can only under-count. When Redis fails nothing is emitted, never an unlimited stream,
 * and one warning per window per process says so.
 */
@Injectable()
export class WorkspaceDeniedEventsService {
  private readonly logger = new Logger(WorkspaceDeniedEventsService.name)
  private lastWarningAt = Number.NEGATIVE_INFINITY
  private readonly limits: { readonly max: number; readonly windowSeconds: number }
  private readonly hmacKey: string

  constructor(
    @Inject(WorkspaceEventsService) private readonly events: WorkspaceEventsService,
    @Inject(AuthRedisService) private readonly redis: AuthRedisService,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions
  ) {
    if (options.workspaces === undefined) {
      throw new Error('[BymaxAuthModule] WorkspaceDeniedEventsService needs workspaces.enabled.')
    }
    this.limits = options.workspaces.accessDeniedEvents
    this.hmacKey = options.hmacKey
  }

  /**
   * Runs `decide` and reports the access refusal it raises, if any.
   *
   * @param denied - Who is asking, and where.
   * @param decide - The access decision.
   * @returns What `decide` returns.
   * @throws Whatever `decide` throws, unchanged.
   */
  admit<T>(denied: DeniedAccess, decide: () => T): T {
    try {
      return decide()
    } catch (error) {
      if (error instanceof WorkspaceAccessRefusal) {
        runDetached(this.logger, () => this.report(denied, error), 'access.denied was not reported')
      }
      throw error
    }
  }

  private async report(denied: DeniedAccess, refusal: WorkspaceAccessRefusal): Promise<void> {
    const limits = this.limits
    const digest = hmacSha256(
      userSubject('dashboard', denied.userId, denied.tenantId),
      this.hmacKey
    )
    const windowKey = `wad:${digest}`
    const suppressedKey = `wads:${digest}`

    let suppressedCount: number
    try {
      const inWindow = await this.redis.incrWithFixedTtl(windowKey, limits.windowSeconds)
      if (inWindow > limits.max) {
        await this.redis.incrWithFixedTtl(suppressedKey, SUPPRESSED_COUNT_TTL_SECONDS)
        return
      }
      suppressedCount = Number((await this.redis.getdel(suppressedKey)) ?? 0)
    } catch {
      this.warnOncePerWindow(limits.windowSeconds)
      return
    }

    this.events.emit(
      {
        type: 'access.denied',
        tenantId: denied.tenantId,
        workspaceId: denied.workspaceId,
        actorUserId: denied.userId,
        userId: denied.userId,
        surface: denied.surface,
        code: refusal.refusalCode,
        reason: refusal.reason,
        suppressedCount,
        at: new Date().toISOString()
      },
      {
        userId: denied.userId,
        tenantId: denied.tenantId,
        plane: 'dashboard',
        ip: '',
        userAgent: '',
        sanitizedHeaders: {}
      }
    )
  }

  private warnOncePerWindow(windowSeconds: number): void {
    const now = Date.now()
    if (now - this.lastWarningAt < windowSeconds * 1000) return
    this.lastWarningAt = now
    this.logger.warn(
      'access.denied events are not being emitted: the counter store is unavailable. The access decision is unaffected.'
    )
  }
}
