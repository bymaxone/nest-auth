/**
 * @fileoverview The refusal the workspace access decision raises, carrying why the host is told
 * it was refused beside the code the caller is answered with.
 *
 * @layer Error
 */

import type { AUTH_ERROR_CODES } from './auth-error-codes'
import { AuthException } from './auth-exception'

/** The public codes a workspace access refusal answers with. */
export type WorkspaceRefusalCode =
  | typeof AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND
  | typeof AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION
  | typeof AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE

/**
 * Why the decision refused, as the host alone is told. It can differ from what the code says: a
 * non-owner of a workspace pending deletion is answered `auth.workspace_not_found`, like a stranger,
 * and the reason is still `pending_deletion`.
 */
export type WorkspaceRefusalReason = 'not_member' | 'pending_deletion' | 'insufficient_role'

/**
 * An {@link AuthException} that also says why the access decision refused.
 *
 * The caller sees the code and nothing else: the reason lives on the exception object and is never
 * part of the response body, so it reaches only the host's `access.denied` event.
 */
export class WorkspaceAccessRefusal extends AuthException {
  /**
   * @param refusalCode - The public code the caller is answered with.
   * @param reason - Why the decision refused.
   */
  constructor(
    readonly refusalCode: WorkspaceRefusalCode,
    readonly reason: WorkspaceRefusalReason
  ) {
    super(refusalCode)
  }
}
