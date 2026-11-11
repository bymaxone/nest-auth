/**
 * @fileoverview `WsWorkspaceGuard`: lets a socket message through only for a workspace it names, in
 * which the connected account is an active member holding an accepted role.
 *
 * @layer Guard
 */

import { Inject, Injectable } from '@nestjs/common'
import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import type { ResolvedWorkspaceOptions } from '../config/workspace-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { WorkspaceAccessService } from '../services/workspace-access.service'
import { WorkspaceDeniedEventsService } from '../services/workspace-denied-events.service'
import { admitsPendingWorkspace, declaredWorkspaceRoles } from '../utils/declared-workspace-roles'
import { assertWorkspaceId, assertWorkspaceMessage } from '../utils/resolve-request-workspace'
import { assertWorkspaceAccess } from '../utils/workspace-access-decision'
import { rememberMessageWorkspace } from '../utils/ws-message-workspace'

/** What `WsJwtGuard` leaves on the client: the verified identity. */
interface WsWorkspaceClient {
  data: { user?: { sub?: unknown; tenantId?: unknown } }
}

/**
 * Authorizes a socket message in the workspace it names.
 *
 * Run it after `WsJwtGuard`, which authenticates the connection and leaves the verified identity on
 * `client.data.user`; the identity of a ticket carries no workspace, so the workspace is judged per
 * message and never at the handshake. It is `WorkspaceGuard` for a gateway handler, with the same
 * declarations (`@WorkspaceRoles`, `@WorkspacePermission`, `@AllowPendingWorkspace`), the same
 * access resolution and the same refusals in the same order:
 *
 * 1. a handler that declares no roles is refused `403 auth.forbidden` before anything else;
 * 2. a connection with no verified dashboard identity is refused `401 auth.token_invalid`, and a
 *    message that is not an object, which cannot carry a membership, `400 auth.validation`;
 * 3. the workspace is read from the message body (`data.workspaceId`, or `workspaces.resolveWsWorkspace`
 *    given the body), never from the URL, a header or the ticket, and a value that is blank,
 *    over-long or holds a control character is `400 auth.validation` naming `workspaceId`, before
 *    any lookup;
 * 4. a workspace that does not exist, one the account does not belong to, and one pending deletion
 *    that the account does not own all answer the identical `404 auth.workspace_not_found`; the
 *    owner of a pending workspace gets `409 auth.workspace_pending_deletion` unless the handler
 *    carries `@AllowPendingWorkspace()`;
 * 5. the role is checked through `workspaces.roles.hierarchy`;
 * 6. the membership is kept with the message for `@CurrentWsWorkspace()`, never on the connection:
 *    overlapping messages on one socket would overwrite a slot on the client, and a handler that
 *    awaited something would act in a workspace another message was admitted to.
 *
 * Every message is judged again, through the access cache, so a member removed between two messages
 * is refused on the next one.
 */
@Injectable()
export class WsWorkspaceGuard implements CanActivate {
  private readonly group: ResolvedWorkspaceOptions

  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(WorkspaceAccessService) private readonly access: WorkspaceAccessService,
    @Inject(BYMAX_AUTH_OPTIONS) options: ResolvedOptions,
    @Inject(WorkspaceDeniedEventsService) private readonly denied: WorkspaceDeniedEventsService
  ) {
    if (options.workspaces === undefined) {
      throw new Error('[BymaxAuthModule] WsWorkspaceGuard needs workspaces.enabled.')
    }
    this.group = options.workspaces
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const accepted = declaredWorkspaceRoles(this.reflector, context, this.group.permissions)
    const ws = context.switchToWs()
    const client = ws.getClient<WsWorkspaceClient>()
    const user = client.data.user
    if (!hasText(user?.sub) || !hasText(user.tenantId)) {
      throw new AuthException(AUTH_ERROR_CODES.TOKEN_INVALID)
    }

    const message = assertWorkspaceMessage(ws.getData<unknown>())
    const workspaceId = assertWorkspaceId(this.named(message))
    const access = await this.access.resolveAccess({
      tenantId: user.tenantId,
      workspaceId,
      userId: user.sub
    })
    const member = this.denied.admit(
      { tenantId: user.tenantId, userId: user.sub, workspaceId, surface: 'ws' },
      () =>
        assertWorkspaceAccess(
          access,
          accepted,
          this.group.roles.hierarchy,
          admitsPendingWorkspace(this.reflector, context)
        )
    )

    rememberMessageWorkspace(message, { ...member })
    return true
  }

  /** The workspace the message names, as the host's resolver or the default field reads it. */
  private named(message: object): unknown {
    if (this.group.resolveWsWorkspace !== undefined) return this.group.resolveWsWorkspace(message)
    return (message as { workspaceId?: unknown }).workspaceId
  }
}

/** Whether a claim is a non-blank string. */
function hasText(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== ''
}
