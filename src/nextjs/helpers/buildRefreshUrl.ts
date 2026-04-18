/**
 * Shared helpers for building the upstream refresh URL used by both
 * {@link createSilentRefreshHandler} and
 * {@link createClientRefreshHandler}.
 *
 * Keeping this logic in a single module prevents the two handlers
 * from drifting on:
 *
 *   - the default refresh pathname (`/auth/refresh`, derived from
 *     `AUTH_DASHBOARD_ROUTES.refresh`),
 *   - trailing-slash handling on the `apiBase`,
 *   - the factory-time validation rules for `apiBase`.
 */

import { AUTH_DASHBOARD_ROUTES } from '@bymax-one/nest-auth/shared'

import { isSafeUpstreamPath, trimTrailingSlash } from './routeHandlerUtils'

/** Default upstream refresh pathname, matching the NestJS module defaults. */
export const DEFAULT_REFRESH_PATH = `/auth/${AUTH_DASHBOARD_ROUTES.refresh}`

/**
 * Compose the absolute URL of the upstream refresh endpoint from a
 * base URL and an optional override path.
 *
 * - Trailing slashes on `apiBase` are trimmed so callers do not have
 *   to standardise their configuration.
 * - When `refreshPath` is omitted, {@link DEFAULT_REFRESH_PATH} is used.
 */
export function buildRefreshUrl(apiBase: string, refreshPath?: string): string {
  return `${trimTrailingSlash(apiBase)}${refreshPath ?? DEFAULT_REFRESH_PATH}`
}

/**
 * Throw when `apiBase` is not an absolute HTTP(S) URL. Factory
 * functions should call this at construction time so a
 * misconfiguration surfaces loudly instead of manifesting as a
 * mysterious 401 at the first inbound refresh request.
 */
export function assertValidApiBase(apiBase: string, factoryName: string): void {
  if (typeof apiBase !== 'string' || apiBase.length === 0) {
    throw new Error(`${factoryName}: apiBase must be a non-empty string.`)
  }
  if (!apiBase.startsWith('http://') && !apiBase.startsWith('https://')) {
    throw new Error(
      `${factoryName}: apiBase "${apiBase}" must be an absolute URL starting with http:// or https://.`
    )
  }
}

/**
 * Throw when the optional upstream path override violates the
 * {@link isSafeUpstreamPath} contract.
 */
export function assertValidUpstreamPath(
  path: string | undefined,
  factoryName: string,
  label: string
): void {
  if (path === undefined) return
  if (!isSafeUpstreamPath(path)) {
    throw new Error(
      `${factoryName}: ${label} "${path}" must be a same-origin pathname starting with "/" and must not contain ".." or URL control characters.`
    )
  }
}
