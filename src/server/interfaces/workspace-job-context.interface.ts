/**
 * @fileoverview What a queued job carries so its worker can ask whether it is still authorized.
 *
 * @layer Interface
 */

/**
 * The workspace a job acts in and the account that enqueued it, stamped at enqueue time from the
 * request's `@CurrentWorkspace()`.
 *
 * It is a claim, not a proof: a worker must call `WorkspaceAccessService.assertStillAuthorized`
 * with it before any side effect, because a job can run long after the request that enqueued it and
 * the member may have been removed, demoted or banned in between. A `workspaceId` read from a job
 * payload is never to be trusted without that call.
 */
export interface WorkspaceJobContext {
  /** The tenant the job belongs to. */
  readonly tenantId: string
  /** The workspace the job acts in. */
  readonly workspaceId: string
  /** The account the job acts for. */
  readonly actorUserId: string
}
