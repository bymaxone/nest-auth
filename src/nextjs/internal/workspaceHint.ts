/**
 * The landing hint the proxy hands to `getDefaultDashboard`: the workspace the signed-in caller used
 * last, read from a cookie the host sets.
 *
 * It is a hint to choose a landing path and nothing more. The cookie is writable by the browser, so
 * its value carries no authority: whatever path the host builds from it is still gated by the
 * layout's `getWorkspaceAccess`, which answers the server's decision. What the value does have to
 * be is safe to put in a path, so it is read only when it is a UUID, which is what the library mints
 * for every workspace id; anything else is treated as absent and the default dashboard is used.
 */

import type { NextRequest } from 'next/server'

import type { ResolvedAuthProxyConfig } from '../createAuthProxy'
import { safeRelativePath } from './proxyUtils'

/** What the proxy knows about where to land the caller, beyond their role. */
export interface DashboardHint {
  /** The workspace the caller last used, when the host's cookie names one that is safe to use. */
  readonly lastActiveWorkspaceId?: string
}

/** What the hint reads of a request: its cookies, so a `NextRequest` and a plain double both fit. */
export interface HintRequest {
  readonly cookies: { get(name: string): { value: string } | undefined }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Reads the landing hint for a request.
 *
 * @param request - The incoming request.
 * @param config - The resolved proxy configuration.
 * @returns `{ lastActiveWorkspaceId }` when `lastWorkspaceCookie` is configured and holds a UUID, `{}`
 *   otherwise.
 */
export function dashboardHint(
  request: HintRequest,
  config: ResolvedAuthProxyConfig
): DashboardHint {
  const name = config.lastWorkspaceCookie
  if (name === undefined) return {}
  const value = request.cookies.get(name)?.value
  return value !== undefined && UUID.test(value) ? { lastActiveWorkspaceId: value } : {}
}

/**
 * Resolves where the proxy lands a caller who is signed in and has no better destination: the host's
 * `getDefaultDashboard`, given the role and the landing hint, held to a same-origin path.
 *
 * @param request - The incoming request.
 * @param config - The resolved proxy configuration.
 * @param role - The caller's role from the verified token.
 * @returns A same-origin path; `/` when the host's function returns anything else.
 */
export function landingPath(
  request: NextRequest,
  config: ResolvedAuthProxyConfig,
  role: string
): string {
  const hint = dashboardHint(request, config)
  // Stryker disable next-line StringLiteral: the fallback reaches `toSameOriginPath`, which maps a value not starting with '/' to '/' — so '' and '/' both emit `Location: /`
  return safeRelativePath(config.getDefaultDashboard(role, hint), '/')
}
