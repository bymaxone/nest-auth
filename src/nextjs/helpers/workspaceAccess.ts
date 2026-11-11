/**
 * Server-side read of the caller's access to one workspace, for a Next.js layout or page.
 *
 * `createWorkspaceAccessReader` returns the function a `/w/[workspaceId]` layout awaits to decide
 * between `notFound()`, a role gate and rendering. It asks the server (`GET workspaces/:id/access`)
 * with the request's own cookies, because the proxy cannot decide membership: it sees only a decoded
 * token, and a role decoded there is stale by construction. The answer is the server's, and the
 * server decides again on every later request.
 */

import 'server-only'

import { cookies } from 'next/headers'
import { cache } from 'react'

import {
  AUTH_ROUTES,
  fillRoute,
  type WorkspaceAccessClient,
  AuthClientError
} from '@bymax-one/nest-auth/shared'

import { assertValidApiBase } from './buildRefreshUrl'
import { trimTrailingSlash } from './routeHandlerUtils'

/** What {@link createWorkspaceAccessReader} needs to reach the API. */
export interface WorkspaceAccessReaderConfig {
  /** Absolute base URL of the NestJS API, as given to `createAuthProxy`. */
  readonly apiBase: string
  /** The server's route prefix. Default `auth`. */
  readonly routePrefix?: string
  /** Milliseconds before the request is abandoned. Default 5000. */
  readonly timeoutMs?: number
  /** The `fetch` to use. Default the global one. */
  readonly fetch?: typeof fetch
}

/** The statuses that mean "this caller may not use this workspace" and become `null`. */
const NOT_USABLE: ReadonlySet<number> = new Set([403, 404, 409])

const DEFAULT_TIMEOUT_MS = 5000

const STATUSES: ReadonlySet<unknown> = new Set([
  'active',
  'pending_deletion',
  'suspended',
  'deleted'
])

/** Whether a parsed body has the shape of a workspace access answer, every field of it. */
function isAccess(value: unknown): value is WorkspaceAccessClient {
  if (typeof value !== 'object' || value === null) return false
  const { workspace, role } = value as { workspace?: unknown; role?: unknown }
  if (typeof role !== 'string' || typeof workspace !== 'object' || workspace === null) return false
  const { id, name, status, createdAt, deletionScheduledAt } = workspace as Record<string, unknown>
  return (
    typeof id === 'string' &&
    typeof name === 'string' &&
    STATUSES.has(status) &&
    typeof createdAt === 'string' &&
    (deletionScheduledAt === null || typeof deletionScheduledAt === 'string')
  )
}

/**
 * Builds the reader a layout awaits, memoized per request.
 *
 * Create it once at module scope and import it where it is needed:
 * `export const getWorkspaceAccess = createWorkspaceAccessReader({ apiBase })`. Calls with the same
 * workspace id during one request share one upstream call, through React's `cache`.
 *
 * The reader answers `{ workspace, role }` when the caller is an active member, and `null` when the
 * workspace is not usable for them: not a member or no such workspace (404), a role the route refuses
 * (403), or a workspace pending deletion (409). A workspace id that is not a non-empty string, or is
 * `.` or `..`, is `null` without a request: it came from a URL, and a URL must not be able to make a page fail. Any
 * other failure (an expired token the proxy did not refresh, a rate limit, a server error, a body of
 * the wrong shape) throws an `AuthClientError`, so Next's error boundary shows it rather than a
 * `notFound()` that would be wrong.
 *
 * @param config - Where the API is.
 * @returns The reader.
 * @throws {Error} When `apiBase` is not an absolute http(s) URL.
 */
export function createWorkspaceAccessReader(
  config: WorkspaceAccessReaderConfig
): (workspaceId: string) => Promise<WorkspaceAccessClient | null> {
  assertValidApiBase(config.apiBase, 'createWorkspaceAccessReader')
  const base = `${trimTrailingSlash(config.apiBase)}/${(config.routePrefix ?? 'auth').replace(/^\/+|\/+$/g, '')}`
  const send = config.fetch ?? fetch

  return cache(async (workspaceId: string): Promise<WorkspaceAccessClient | null> => {
    // A '.' or '..' segment is collapsed by a URL parser even when percent-encoded, which would send
    // the request to another route.
    if (typeof workspaceId !== 'string' || ['', '.', '..'].includes(workspaceId)) return null
    const url = `${base}/${fillRoute(AUTH_ROUTES.workspaces.access, { workspaceId })}`
    const response = await send(url, {
      method: 'GET',
      headers: { accept: 'application/json', cookie: (await cookies()).toString() },
      cache: 'no-store',
      signal: AbortSignal.timeout(config.timeoutMs ?? DEFAULT_TIMEOUT_MS)
    })
    if (NOT_USABLE.has(response.status)) return null
    if (!response.ok) {
      throw new AuthClientError(
        `Workspace access read failed with status ${response.status}`,
        response.status
      )
    }
    const body: unknown = await response.json().catch(() => undefined)
    if (!isAccess(body)) {
      throw new AuthClientError('Workspace access answer has an unexpected shape', response.status)
    }
    return body
  })
}
