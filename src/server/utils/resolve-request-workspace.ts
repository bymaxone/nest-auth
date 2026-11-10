/**
 * @fileoverview Reads the workspace a request names, from the route or the host's resolver.
 *
 * @layer Utility
 */

import { exceedsCodePoints } from './code-points'
import { NO_CONTROL_CHARACTERS } from '../dto/no-control-characters'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { TenantResolverRequest } from '../interfaces/auth-module-options.interface'

/** Longest workspace id accepted, in characters. */
const MAX_WORKSPACE_ID_LENGTH = 128

/** A request as far as workspace resolution reads it. */
export interface WorkspaceRouteRequest extends TenantResolverRequest {
  readonly params?: Readonly<Record<string, unknown>>
}

/**
 * Raises the `400` for a workspace id that is not usable as one.
 *
 * @param message - What is wrong with it.
 * @throws {AuthException} Always, as `auth.validation` on `workspaceId`.
 */
function invalidWorkspaceId(message: string): never {
  throw new AuthException(AUTH_ERROR_CODES.VALIDATION, [{ field: 'workspaceId', message }])
}

/**
 * Requires a candidate workspace id to be a bounded string without control characters.
 *
 * @param value - What a source returned.
 * @returns The id.
 * @throws {AuthException} `auth.validation` when it is not.
 */
export function assertWorkspaceId(value: unknown): string {
  // A blank id is refused here, as `WorkspaceAccessService` refuses one with an error that would
  // reach the caller as a 500. The pattern needs a character, so it also refuses an empty id.
  if (
    typeof value !== 'string' ||
    value.trim() === '' ||
    exceedsCodePoints(value, MAX_WORKSPACE_ID_LENGTH) ||
    !NO_CONTROL_CHARACTERS.test(value)
  ) {
    return invalidWorkspaceId(
      `workspaceId must be 1 to ${MAX_WORKSPACE_ID_LENGTH} characters, not blank, with no control characters`
    )
  }
  return value
}

/**
 * Resolves the workspace a request is about, from exactly the places a caller cannot be tricked
 * through: the route parameter `workspaceId`, and the host's own `resolveRequestWorkspace`.
 *
 * It is never read from the body, a query or a header the library chooses, and it never falls back
 * to a last-used or default workspace: a request that names none is refused, so an action never
 * lands in a workspace the caller did not mean.
 *
 * When both sources answer and differ the request is refused, because two answers mean one of them
 * was supplied by someone who is not the route's author.
 *
 * @param request - The request.
 * @param resolver - The host's `workspaces.resolveRequestWorkspace`, when set.
 * @returns The workspace id.
 * @throws {AuthException} `auth.workspace_required` when no source names one, and
 *   `auth.validation` for a malformed id or two disagreeing ones.
 */
export function resolveRequestWorkspace(
  request: WorkspaceRouteRequest,
  resolver: ((req: TenantResolverRequest) => string | undefined) | undefined
): string {
  const fromRoute: unknown = request.params?.['workspaceId']
  const fromResolver: unknown = resolver?.(request)
  const [first, second] = [fromRoute, fromResolver]
    .filter((value) => value !== undefined)
    .map(assertWorkspaceId)

  if (first === undefined) throw new AuthException(AUTH_ERROR_CODES.WORKSPACE_REQUIRED)
  if (second !== undefined && second !== first) {
    return invalidWorkspaceId('workspaceId differs between the route and the request resolver')
  }
  return first
}
