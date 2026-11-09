/**
 * @fileoverview `@AllowPendingWorkspace()`: lets a route run for the owner of a workspace that is
 * pending deletion.
 *
 * @layer Decorator
 */

import { SetMetadata } from '@nestjs/common'

/** Metadata key under which {@link AllowPendingWorkspace} marks a route. */
export const ALLOW_PENDING_WORKSPACE_KEY = 'allowPendingWorkspace'

/**
 * Admits the owner of a workspace pending deletion to this route.
 *
 * Every other route refuses that owner with `409 auth.workspace_pending_deletion`, so a client can
 * offer to restore the workspace, and refuses everyone else with the `404` any other refusal gets.
 * Put this on the restore route and nowhere else: a route that runs while a workspace is waiting
 * to be deleted can act on data that is about to go. The route-inventory spec lists the routes that
 * carry it, so adding it elsewhere is a red test and not a quiet change.
 *
 * @returns A method and class decorator.
 */
export const AllowPendingWorkspace = (): MethodDecorator & ClassDecorator =>
  SetMetadata(ALLOW_PENDING_WORKSPACE_KEY, true)
