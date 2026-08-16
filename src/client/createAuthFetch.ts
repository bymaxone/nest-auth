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

import {
  AUTH_ERROR_CODES,
  AUTH_PROXY_ROUTES,
  buildAuthRefreshSkipSuffixes
} from '@bymax-one/nest-auth/shared'

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
   * Callback invoked when a refresh attempt did not produce a session, whatever the reason.
   *
   * Fires for every failure, including the one that also triggers {@link onSessionExpired} — and
   * before it, so a consumer sees the reason first. This is what makes the answer to *why* usable
   * rather than merely internal: a rate limit deserves "retrying in a moment", a dropped
   * connection deserves "you appear to be offline", and only a refused credential deserves the
   * sign-in screen.
   *
   * Errors thrown here are swallowed and reported through `console.warn`, on the same reasoning as
   * {@link onSessionExpired}: a broken consumer callback must not mask the underlying response.
   *
   * @param failure - Why the attempt failed, and the status behind it when there was one.
   */
  onRefreshFailed?: (failure: RefreshFailure) => void

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
    // Stryker disable next-line BooleanLiteral: unreachable — `URL` with a placeholder origin parses anything `fetch` would accept, so this catch never runs
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
 * How long the 401 classification may wait for the error body.
 *
 * Not the consumer's `timeout`: that one belongs to the request, whose timer is already cleared
 * by the time this runs, and a deployment disabling it (`0`) for long-polling must not thereby
 * let a 401 hang the wrapper. An auth error body is a few hundred bytes, so anything slower is
 * pathological. On expiry the pre-existing behaviour applies — this step may narrow what
 * refreshes, never suspend the wrapper.
 */
const ERROR_BODY_READ_TIMEOUT_MS = 2_000

/**
 * Whether a 401 means the access token expired — the only case a refresh can fix.
 *
 * The path skip list cannot answer this where one route carries both meanings:
 * `POST {prefix}/password/change` is JWT-guarded, so an expired token 401s there and so does a
 * wrong `currentPassword`. Refreshing on the second cost a consumer one refresh per typo, and
 * ten typos in a minute exhausted the refresh limiter — whose 429 the client then read as an
 * expiry, discarding a session the server still honoured.
 *
 * So the code decides. `auth.token_invalid` is the expiry: every guard collapses expired,
 * revoked, malformed and absent onto it deliberately. Any other code is the server answering
 * about something else, which a new token would not change.
 *
 * **A response this cannot read still refreshes** — no envelope, empty, non-JSON — so the
 * wrapper stays usable against an application's own API. Both envelope shapes are read: this
 * library's `{error: {code}}` and the flat `{statusCode, code}` a `@bymax-one/nest-core` backend
 * answers with, since the client cannot tell which it is talking to.
 *
 * Read from a CLONE, so the caller still receives an unconsumed body and a retry still has a
 * request to send.
 *
 * @param response - The 401 response, unconsumed.
 * @returns `true` when a refresh could plausibly help.
 */
async function isExpiredSessionResponse(response: Response): Promise<boolean> {
  const clone = response.clone()
  let timer: ReturnType<typeof setTimeout> | undefined

  // `undefined` is the give-up sentinel and needs no symbol: `json()` cannot resolve to it,
  // because JSON has no such value. Both ways of giving up produce it — the read failing and the
  // read taking too long — and they deliberately answer the same, so neither needs its own arm:
  // a 401 whose body cannot be read is a 401 that says nothing about why, and a refresh is what
  // this wrapper did for every 401 before it started reading them at all.
  //
  // The abandoned read is NOT cancelled, and that is measured rather than assumed: `json()`
  // locks the body, so `cancel()` on it rejects with
  // `TypeError: Invalid state: ReadableStream is locked`. An earlier draft called it inside the
  // `.catch()` below, which meant the cleanup that comment promised never happened and the
  // rejection was swallowed. Owning a reader to make the read genuinely abortable would cost more
  // bundle than the case is worth — a 401 whose body never arrives — so the read is left to the
  // collector, and this says so instead of claiming otherwise.
  const body: unknown = await Promise.race([
    clone.json().catch(() => undefined),
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(undefined), ERROR_BODY_READ_TIMEOUT_MS)
    })
  ])

  clearTimeout(timer)

  if (typeof body !== 'object' || body === null) return true

  const envelope = body as { code?: unknown; error?: { code?: unknown } }
  const code = envelope.error?.code ?? envelope.code

  return typeof code !== 'string' || code === AUTH_ERROR_CODES.TOKEN_INVALID
}

/**
 * Resolve the request URL into the absolute string used by the
 * skip-list check. Always returns a string so downstream logic does
 * not need to branch on `RequestInfo` shapes.
 */
function resolveRequestUrl(input: RequestInfo | URL, baseUrl: string | undefined): string {
  if (typeof input === 'string') {
    // Stryker disable next-line ConditionalExpression: when baseUrl is undefined the expression returns `input` unchanged regardless of the guard's boolean, so `true` is indistinguishable here
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
  // Stryker disable next-line ConditionalExpression: `typeof Headers !== 'undefined'` is a cross-runtime safety check; Headers is always defined in supported runtimes (Node 18+, Edge, browsers), so `true` is equivalent
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
      // Stryker disable next-line ObjectLiteral,BooleanLiteral: an AbortSignal dispatches 'abort' at most once, so `{ once: true }`, `{}`, and `{ once: false }` all produce identical behavior
      userSignal.addEventListener('abort', () => controller.abort(), { once: true })
    }
  }

  return {
    init: { ...init, signal: controller.signal },
    cleanup: () => clearTimeout(timer)
  }
}

/**
 * Why a refresh attempt did not produce a new session.
 *
 * Three answers, not a boolean, because the caller acts differently on each and a boolean forces
 * it to guess. Measured by a consumer against a real browser round: a rate-limited refresh answers
 * `429`, the boolean made that identical to `401`, and the caller signed the user out of a session
 * whose credential was still valid.
 *
 * - `rejected` — 401. The server looked at the credential and refused it. The session is over.
 * - `unavailable` — it answered, but not with a session: a 429, a 5xx, a 403 from an origin guard,
 *   a 404 from a mistyped `routePrefix`. None of those is a statement about the credential.
 * - `unreachable` — no answer at all: offline, DNS, CORS, an aborted request.
 *
 * 403 sits under `unavailable` on purpose. `TrustedOriginGuard` covers `/refresh` and answers
 * `auth.untrusted_origin` with 403, so a misconfigured deployment would otherwise sign out every
 * user. Some 403s DO mean the session is finished — a banned account — and separating those needs
 * the response body, which the caller has and this wrapper does not read.
 */
export type RefreshFailureReason = 'rejected' | 'unavailable' | 'unreachable'

/**
 * The result of one refresh attempt.
 *
 * A discriminated union rather than a boolean with a `429` carve-out. The carve-out was offered
 * and declined by the consumer who found the defect, on the grounds that it reproduces the same
 * shape for whichever status turns out to matter next — the refresh has to report WHY it failed,
 * not whether.
 */
export interface RefreshFailure {
  readonly ok: false
  readonly reason: RefreshFailureReason
  /** HTTP status the server answered with, or `null` when there was no answer. */
  readonly status: number | null
}

export type RefreshOutcome = { readonly ok: true } | RefreshFailure

/**
 * Fire the refresh endpoint and report what came back.
 *
 * Sends an empty POST and discards the response body — the auth cookies are the carrier in
 * cookie-mode deployments, and a non-cookie bearer flow needs to call `refresh()` on the
 * higher-level `AuthClient` directly anyway. The body stream is cancelled explicitly to release
 * the underlying connection in runtimes (Node 18+, Cloudflare Workers) where it would otherwise
 * remain open until garbage collection.
 *
 * @param endpoint - Absolute or relative URL of the refresh route.
 * @param credentials - The `RequestCredentials` mode the wrapper was configured with.
 * @returns `{ ok: true }`, or the reason it did not produce a session.
 */
async function performRefresh(
  endpoint: string,
  credentials: RequestCredentials
): Promise<RefreshOutcome> {
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      credentials,
      headers: { 'Content-Type': 'application/json' }
    })
    const { ok, status } = response
    // Deliberately NOT awaited. Draining releases the connection in runtimes that hold it
    // open until the stream ends, and nothing downstream needs the drain to have COMPLETED —
    // the status has already been read. Under request interception (MSW, undici in jsdom)
    // the promise this returns never settles, so awaiting it deadlocks every call whose
    // response carries a body. `/auth/refresh` carries one on success as well as on failure,
    // which put the deadlock on the happy path at every rotation and made the refresh path
    // untestable.
    void response.body?.cancel().catch(/* istanbul ignore next */ () => undefined)

    if (ok) return { ok: true }

    // 401 ONLY. A 403 does not prove the credential was examined: this package puts
    // `TrustedOriginGuard` on the whole `AuthController`, `/refresh` included, and it answers
    // `auth.untrusted_origin` with 403. Treating that as expiry signs every user of a
    // misconfigured deployment out — the same defect this function was rewritten to remove,
    // reappearing one status over.
    //
    // Other 403s exist and some of them do mean the session is finished — a banned or suspended
    // account among them. Telling those apart needs the response BODY, which this function
    // deliberately does not read: the status is enough to decide whether to retry, and a caller
    // that wants the code has the original response in hand.
    return { ok: false, reason: status === 401 ? 'rejected' : 'unavailable', status }
  } catch {
    // No answer at all: offline, DNS, CORS, an aborted request. The session is very likely intact
    // and the next attempt may well succeed.
    return { ok: false, reason: 'unreachable', status: null }
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
  const onRefreshFailed = config.onRefreshFailed
  const timeoutMs = config.timeout ?? 30_000
  const skipRefreshSuffixes = buildAuthRefreshSkipSuffixes(config.routePrefix)

  // Per-instance dedup slot. Closing over the slot inside the factory
  // (rather than at module scope) means two `createAuthFetch` instances
  // pointing at different APIs cannot block each other's refreshes —
  // and tests get a fresh slot for free by re-creating the wrapper.
  //
  // Stored as a {@link RefreshOutcome}, not a `Response`: a plain value is safe to share across
  // multiple awaiters, and a `Response` body can be consumed only once.
  //
  // It was a boolean until a consumer measured what that costs. A rate-limited refresh answers
  // `429` and the boolean makes it indistinguishable from `401`, so the caller signed the user
  // out while their credential was still valid. Reporting WHY is the fix, and reporting it as a
  // reason rather than as a `429` branch is deliberate: a boolean with one carve-out reproduces
  // the same defect for the next status that turns out to matter.
  let inFlightRefresh: Promise<RefreshOutcome> | null = null

  function getOrStartRefresh(): Promise<RefreshOutcome> {
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
      // Stryker disable next-line ConditionalExpression: when baseUrl is undefined the ternary returns `input` regardless, so the guard's boolean is unobservable
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

    // And then the same question the path cannot answer: a route can be behind the JWT guard
    // AND verify a second credential, so an expired token and a wrong password 401 from the
    // same URL. The code separates them; the path never could.
    if (!(await isExpiredSessionResponse(response))) {
      return response
    }

    const outcome = await getOrStartRefresh()

    // ONLY a refusal ends the session. `unavailable` (429, 5xx, a 404 from a mistyped
    // `routePrefix`) and `unreachable` (offline, CORS, abort) say nothing about the credential —
    // treating them as expiry signs the user out of a session that is still good, and on a rate
    // limit it does so exactly when retrying would have worked.
    //
    // The caller still receives the original 401, so a failed request stays a failed request.
    // What it no longer receives is a claim that the session is over.
    if (!outcome.ok) {
      // Every failure, before the expiry decision, so a consumer that wants to distinguish
      // "retrying" from "signed out" is told the reason rather than left to infer it.
      try {
        onRefreshFailed?.(outcome)
        // Stryker disable next-line BlockStatement: the catch only logs a user-callback error and swallows it; emptying the body leaves the same swallow, observable only via a console spy
      } catch (err: unknown) {
        // Stryker disable next-line StringLiteral: diagnostic-only console.warn label for a swallowed callback error; no consumer behavior depends on the text
        console.warn('[nest-auth] onRefreshFailed callback threw:', err)
      }
    }

    if (!outcome.ok && outcome.reason === 'rejected') {
      // Isolate consumer-side errors: a throwing callback must not
      // mask the underlying 401 Response from the caller. Surface
      // the error via console.warn so library consumers can debug
      // a broken redirect without breaking the fetch contract.
      try {
        onSessionExpired?.()
        // Stryker disable next-line BlockStatement: the catch only logs a user-callback error and swallows it (fire-and-forget); emptying the body leaves the same swallow, observable only via a console spy
      } catch (err: unknown) {
        // Stryker disable next-line StringLiteral: diagnostic-only console.warn label for a swallowed callback error; no consumer behavior depends on the text
        console.warn('[nest-auth] onSessionExpired callback threw:', err)
      }
      return response
    }

    if (!outcome.ok) return response

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
