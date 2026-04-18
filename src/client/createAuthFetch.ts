/**
 * Fetch wrapper for the @bymax-one/nest-auth client subpath.
 *
 * Wraps the platform's native `fetch` so that consumer code can issue
 * authenticated requests without manually:
 *
 *   - attaching `credentials: 'include'` on every call,
 *   - intercepting 401 responses to attempt a transparent refresh,
 *   - retrying the original request after a successful refresh,
 *   - de-duplicating concurrent refresh attempts (single-flight),
 *   - or notifying the application when the session is irrecoverable.
 *
 * Zero runtime dependencies: relies only on the global `fetch` and the
 * stable constants exported from `@bymax-one/nest-auth/shared`.
 */

import { AUTH_PROXY_ROUTES, buildAuthRefreshSkipSuffixes } from '@bymax-one/nest-auth/shared'

/**
 * Configuration options for {@link createAuthFetch}.
 *
 * Every field is optional so that the default factory output works
 * out-of-the-box against a same-domain Next.js proxy. Override only
 * what your deployment actually needs to change.
 */
export interface AuthFetchConfig {
  /**
   * Optional base URL prepended to relative request URLs.
   *
   * When omitted, relative URLs (`/api/users`) are passed to `fetch`
   * verbatim — appropriate for browser environments where the request
   * is naturally same-origin. Provide this in non-browser contexts
   * (Node-side server components, tests, mobile apps) so that the
   * URL parsing in the skip-list logic can operate on a full URL.
   */
  baseUrl?: string

  /**
   * Pathname or full URL of the refresh endpoint.
   *
   * Default: {@link AUTH_PROXY_ROUTES.clientRefresh}
   * (`/api/auth/client-refresh`). Replace this when your application
   * exposes the refresh endpoint at a non-default path.
   */
  refreshEndpoint?: string

  /**
   * Credentials policy for every issued request.
   *
   * Default: `'include'`. Set to `'same-origin'` for same-origin
   * deployments that want to avoid CORS preflights, or to `'omit'`
   * when working with bearer-only deployments that do not use cookies.
   */
  credentials?: RequestCredentials

  /**
   * Headers merged into every request.
   *
   * Default: `{ 'Content-Type': 'application/json' }`. Headers passed
   * per-request in `fetch(..., { headers })` override these.
   */
  defaultHeaders?: Record<string, string>

  /**
   * Callback invoked when a refresh attempt fails irrecoverably.
   *
   * Wire this to a UI redirect, a state-store reset, or a logout
   * helper. The callback runs before the auth-fetched promise
   * rejects, so consumers can rely on side effects having happened.
   */
  onSessionExpired?: () => void

  /**
   * Per-request timeout in milliseconds.
   *
   * Default: `30_000` (30s). Pass `0` to disable the timeout.
   * Disabling is appropriate for long-poll endpoints; for normal
   * requests keep the default to avoid hanging UIs on slow networks.
   */
  timeout?: number

  /**
   * NestJS `routePrefix` the upstream auth server is mounted under.
   *
   * Used to compose the pathname-suffix skip list so that 401s from
   * credential-issuing endpoints (login, refresh, mfa/challenge, …)
   * are NOT retried after a refresh attempt. Default: `'auth'`.
   * Set this explicitly when the server uses a non-default prefix
   * (e.g. `'authentication'`, `'api/v1/auth'`) or 401 retries will
   * misfire on those endpoints.
   */
  routePrefix?: string
}

/**
 * The fetch-compatible function returned by {@link createAuthFetch}.
 *
 * Has the same signature as the native `fetch` but applies the
 * configured credentials, headers, refresh interception, and retry.
 *
 * @remarks
 * Passing a {@link Request} object whose body is a stream is not
 * supported when the request may be retried after a refresh —
 * `Request` body streams can only be read once, and the retry will
 * fail with `TypeError: body already used`. Prefer passing a URL
 * string plus an `init` with a string/`FormData`/`URLSearchParams`
 * body, which can be re-sent safely. This restriction does not
 * apply to GET/HEAD requests or to requests that do not receive a
 * 401 response.
 */
export type AuthFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

/**
 * Default headers applied when the consumer supplies none.
 *
 * Declared at module scope so the array allocation only happens once
 * across all factory calls.
 */
const DEFAULT_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'Content-Type': 'application/json'
})

/**
 * Pathname-suffix matcher: returns `true` when the URL points at an
 * endpoint that must NOT trigger an automatic refresh on 401.
 *
 * The suffix list is provided by the caller so it can reflect the
 * consumer's deployed `routePrefix`. Suffix matching (rather than
 * exact equality) allows a single list to work for layered deployments
 * (e.g. `/api/v1/auth/login`) as long as the trailing `/<prefix>/<path>`
 * portion matches.
 *
 * Defensive: invalid URLs are treated as non-skipped — calling code
 * can let the underlying `fetch` produce its own clearer error.
 */
function shouldSkipRefreshOnUrl(url: string, suffixes: readonly string[]): boolean {
  let pathname: string

  try {
    // Use a deterministic placeholder origin so relative URLs parse.
    // The origin itself is irrelevant — only the pathname is checked.
    pathname = new URL(url, 'http://_placeholder').pathname
  } catch {
    /* istanbul ignore next -- defensive: URL with placeholder origin parses any
       string the platform would let `fetch` accept; this catch only fires for
       inputs that fetch itself would already have rejected. */
    return false
  }

  for (const suffix of suffixes) {
    if (pathname.endsWith(suffix)) {
      return true
    }
  }
  return false
}

/**
 * Resolve the request URL into the absolute string used by the
 * skip-list check. Always returns a string so downstream logic does
 * not need to branch on `RequestInfo` shapes.
 */
function resolveRequestUrl(input: RequestInfo | URL, baseUrl: string | undefined): string {
  if (typeof input === 'string') {
    return baseUrl !== undefined && !/^https?:\/\//i.test(input) ? `${baseUrl}${input}` : input
  }
  if (input instanceof URL) {
    return input.toString()
  }
  // Request object — has its own absolute `url` property.
  return input.url
}

/**
 * Merge the consumer's headers with the configured defaults.
 *
 * Per-request headers always win over defaults so callers can opt out
 * of `Content-Type: application/json` when sending FormData or empty
 * bodies. We avoid `Headers` class here so the function works
 * identically across browser, Node, and edge runtimes (older Node
 * versions diverge in their `Headers` implementation).
 */
function mergeHeaders(
  defaults: Readonly<Record<string, string>>,
  perRequest: HeadersInit | undefined
): Record<string, string> {
  const merged: Record<string, string> = { ...defaults }
  if (perRequest === undefined) {
    return merged
  }

  // Reject prototype-polluting names defensively. HTTP header names are
  // ASCII-only by spec, so any of these reaching this code path indicates
  // a tampered HeadersInit; silently skip rather than enabling pollution.
  const isUnsafeName = (name: string): boolean =>
    name === '__proto__' || name === 'constructor' || name === 'prototype'

  if (Array.isArray(perRequest)) {
    for (const [name, value] of perRequest) {
      if (isUnsafeName(name)) continue
      // eslint-disable-next-line security/detect-object-injection -- name is sanitized above against prototype pollution.
      merged[name] = value
    }
    return merged
  }
  if (typeof Headers !== 'undefined' && perRequest instanceof Headers) {
    perRequest.forEach((value, name) => {
      if (isUnsafeName(name)) return
      // eslint-disable-next-line security/detect-object-injection -- name is sanitized above against prototype pollution.
      merged[name] = value
    })
    return merged
  }

  for (const [name, value] of Object.entries(perRequest as Record<string, unknown>)) {
    if (isUnsafeName(name) || typeof value !== 'string') continue
    // eslint-disable-next-line security/detect-object-injection -- name is sanitized above against prototype pollution.
    merged[name] = value
  }
  return merged
}

/**
 * Apply the configured timeout to the per-request init.
 *
 * Composes with any user-supplied `signal` so that the request is
 * cancelled when EITHER the consumer aborts OR the timeout fires.
 * Returns a no-op cleanup when timeout is disabled.
 */
function attachTimeout(
  init: RequestInit,
  timeoutMs: number
): { init: RequestInit; cleanup: () => void } {
  if (timeoutMs <= 0) {
    return {
      init,
      cleanup: (): void => {
        // No-op when timeout is disabled.
      }
    }
  }

  const controller = new AbortController()
  const timer = setTimeout(() => {
    controller.abort()
  }, timeoutMs)

  const userSignal = init.signal
  if (userSignal != null) {
    if (userSignal.aborted) {
      controller.abort()
    } else {
      userSignal.addEventListener('abort', () => controller.abort(), { once: true })
    }
  }

  return {
    init: { ...init, signal: controller.signal },
    cleanup: () => clearTimeout(timer)
  }
}

/**
 * Fire the refresh endpoint and resolve to `true` on success.
 *
 * Sends an empty POST and discards the response body — the auth
 * cookies are the carrier in cookie-mode deployments, and a
 * non-cookie bearer flow needs to call `refresh()` on the
 * higher-level `AuthClient` directly anyway. The body stream is
 * cancelled explicitly to release the underlying connection in
 * runtimes (Node 18+, Cloudflare Workers) where it would otherwise
 * remain open until garbage collection.
 */
async function performRefresh(endpoint: string, credentials: RequestCredentials): Promise<boolean> {
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      credentials,
      headers: { 'Content-Type': 'application/json' }
    })
    const ok = response.ok
    await response.body?.cancel().catch(/* istanbul ignore next */ () => undefined)
    return ok
  } catch {
    return false
  }
}

/**
 * Create a configured fetch wrapper with cookie- and refresh-aware
 * behavior baked in.
 *
 * @example
 * ```ts
 * const authFetch = createAuthFetch({
 *   baseUrl: 'https://api.example.com',
 *   onSessionExpired: () => router.push('/sign-in')
 * })
 *
 * const response = await authFetch('/api/users')
 * ```
 */
export function createAuthFetch(config: AuthFetchConfig = {}): AuthFetch {
  const baseUrl = config.baseUrl
  const refreshEndpoint = config.refreshEndpoint ?? AUTH_PROXY_ROUTES.clientRefresh
  const credentials: RequestCredentials = config.credentials ?? 'include'
  const defaultHeaders: Readonly<Record<string, string>> = config.defaultHeaders
    ? { ...DEFAULT_HEADERS, ...config.defaultHeaders }
    : DEFAULT_HEADERS
  const onSessionExpired = config.onSessionExpired
  const timeoutMs = config.timeout ?? 30_000
  const skipRefreshSuffixes = buildAuthRefreshSkipSuffixes(config.routePrefix)

  // Per-instance dedup slot. Closing over the slot inside the factory
  // (rather than at module scope) means two `createAuthFetch` instances
  // pointing at different APIs cannot block each other's refreshes —
  // and tests get a fresh slot for free by re-creating the wrapper.
  //
  // Stored as `Promise<boolean>`: `true` means refresh succeeded,
  // `false` means it failed. A boolean (rather than a `Response`) is
  // safe to share across multiple awaiters; `Response` bodies can only
  // be consumed once.
  let inFlightRefresh: Promise<boolean> | null = null

  function getOrStartRefresh(): Promise<boolean> {
    if (inFlightRefresh !== null) {
      return inFlightRefresh
    }
    const attempt = performRefresh(refreshEndpoint, credentials).finally(() => {
      inFlightRefresh = null
    })
    inFlightRefresh = attempt
    return attempt
  }

  return async function authFetch(input, init): Promise<Response> {
    const initBase: RequestInit = {
      ...(init ?? {}),
      credentials,
      headers: mergeHeaders(defaultHeaders, init?.headers)
    }

    const url = resolveRequestUrl(input, baseUrl)

    // The fetch target uses the resolved URL only when `baseUrl` was
    // applied to a relative string input; in every other case we
    // forward the original `input` as-is so existing `Request` objects
    // and absolute URLs reach `fetch` unmodified. URL semantics
    // (scheme, origin, validation) remain `fetch`'s responsibility —
    // the skip-list check above operates on pathname only.
    const targetForFetch: RequestInfo | URL =
      baseUrl !== undefined && typeof input === 'string' ? url : input

    const firstAttempt = attachTimeout(initBase, timeoutMs)
    let response: Response
    try {
      response = await fetch(targetForFetch, firstAttempt.init)
    } finally {
      firstAttempt.cleanup()
    }

    // Only intercept 401s for endpoints that are NOT in the skip list.
    // The skip list covers credential-issuing endpoints (login, refresh,
    // mfa challenge, etc.) where a 401 means "wrong credentials" rather
    // than "session expired".
    if (response.status !== 401 || shouldSkipRefreshOnUrl(url, skipRefreshSuffixes)) {
      return response
    }

    const refreshed = await getOrStartRefresh()
    if (!refreshed) {
      // Isolate consumer-side errors: a throwing callback must not
      // mask the underlying 401 Response from the caller. Surface
      // the error via console.warn so library consumers can debug
      // a broken redirect without breaking the fetch contract.
      try {
        onSessionExpired?.()
      } catch (err) {
        console.warn('[nest-auth] onSessionExpired callback threw:', err)
      }
      return response
    }

    // Retry the original request once. We deliberately do not loop —
    // a fresh 401 after a successful refresh indicates a server-side
    // authorization decision (RBAC, status), not an auth gap.
    const retryAttempt = attachTimeout(initBase, timeoutMs)
    try {
      return await fetch(targetForFetch, retryAttempt.init)
    } finally {
      retryAttempt.cleanup()
    }
  }
}
