/**
 * @fileoverview Fans a workspace audit event out to the host's `onWorkspaceEvent` hook after the
 * change it describes has committed.
 *
 * @layer Service
 */

import { Inject, Injectable, Logger } from '@nestjs/common'

import { BYMAX_AUTH_HOOKS } from '../bymax-auth.constants'
import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { WorkspaceAuditEvent } from '../interfaces/workspace-audit.interface'
import { runDetached } from '../utils/run-detached'

/**
 * Delivers workspace events to the host.
 *
 * Delivery is best-effort and detached: a hook that is slow, throws or rejects never delays or
 * fails the operation that produced the event. A failure is logged through the module logger with
 * the hook name and the event type only: the event itself can carry an email address, so it is never
 * written to the log. The persisted audit row, written by the repository
 * in the same transaction as the change, is the record; this is a notification.
 */
@Injectable()
export class WorkspaceEventsService {
  private readonly logger = new Logger(WorkspaceEventsService.name)

  constructor(@Inject(BYMAX_AUTH_HOOKS) private readonly hooks: IAuthHooks) {}

  /**
   * Hands an event to the `onWorkspaceEvent` hook, if the host defined one.
   *
   * @param event - The event that was persisted with the change.
   * @param context - Request metadata for the hook.
   */
  emit(event: WorkspaceAuditEvent, context: HookContext): void {
    runDetached(
      this.logger,
      () => this.hooks.onWorkspaceEvent?.(event, context),
      `onWorkspaceEvent hook failed for ${event.type}`
    )
  }
}
