/**
 * Utility functions shared by `proxyHandlers`.
 *
 * These are tiny, security-flavoured helpers: anti-redirect-loop
 * counter reading, same-origin path enforcement, request-header
 * sanitisation, JWT claim coercion, and CR/LF stripping.
 */

import type { NextRequest } from 'next/server'

import type { ResolvedAuthProxyConfig } from '../createAuthProxy'
import {
  IDENTITY_HEADERS_BASELINE,
  REASON_EXPIRED,
  REASON_PARAM,
  REFRESH_ATTEMPT_PARAM
} from './constants'
import { isSafeSameOriginPath } from '../helpers/routeHandlerUtils'

/**
 * Read the `_r` counter query param off a request URL and clamp it
 * to `[0, maxAllowed]`.
 *
 * - Missing / unparseable values default to `0` so an attacker
 *   cannot bypass the retry cap by sending `_r=foo` or omitting the
 *   param.
 * - Arbitrarily large values are clamped to `maxAllowed` so a
 *   crafted `_r=9999999` cannot signal "infinite retries" and a
 *   value at or above the cap immediately breaks the loop on this
 *   request.
 * - Negative values are treated as `0`.
 */
export function readRefreshAttemptCounter(request: NextRequest, maxAllowed: number): number {
  const raw = request.nextUrl.searchParams.get(REFRESH_ATTEMPT_PARAM)
  if (raw === null) return 0
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || parsed < 0) return 0
  return Math.min(parsed, maxAllowed)
}

/** `true` when the current URL carries the `reason=expired` signal. */
export function isReasonExpired(request: NextRequest): boolean {
  return request.nextUrl.searchParams.get(REASON_PARAM) === REASON_EXPIRED
}

/**
 * Reject any redirect destination that is not a same-origin
 * pathname — defence-in-depth against a misconfigured
 * `getDefaultDashboard` that returns an absolute URL or a path
 * containing CR/LF/NUL/backslash. Returns the fallback when the
 * candidate is unsafe.
 */
export function safeRelativePath(candidate: string, fallback: string): string {
  return isSafeSameOriginPath(candidate) ? candidate : fallback
}

/**
 * Build the `destination` value that rides on
 * `silent-refresh?redirect=…`.
 *
 * - Uses the NORMALISED pathname (so `//` and `/./` sequences cannot
 *   escape the proxy's classification when the browser lands back).
 * - Drops any existing `_r` and `reason` params so the destination
 *   cannot be polluted by attacker-controlled values that later
 *   manipulate the loop-break guards.
 * - Re-attaches `_r` with the incremented value. Because this value
 *   lives on the DESTINATION (not just on the silent-refresh URL),
 *   the counter is preserved across the silent-refresh handler's
 *   redirect-back — which is what makes the counter guard functional.
 */
export function buildRefreshDestination(
  pathname: string,
  searchParams: URLSearchParams,
  nextCounter: number
): string {
  const cleaned = new URLSearchParams(searchParams)
  cleaned.delete(REFRESH_ATTEMPT_PARAM)
  cleaned.delete(REASON_PARAM)
  cleaned.set(REFRESH_ATTEMPT_PARAM, String(nextCounter))
  const query = cleaned.toString()
  // The `set(REFRESH_ATTEMPT_PARAM, ...)` call above guarantees the
  // query string is non-empty, so the `: pathname` branch is
  // unreachable — it exists only to make the ternary total.
  /* istanbul ignore next -- `_r` is always set above, so the empty-query branch is unreachable */
  return query.length > 0 ? `${pathname}?${query}` : pathname
}

/**
 * Copy the inbound request headers and remove every header slot we
 * expose to downstream server components. Doing this centrally —
 * once, at the top of the proxy — means a client-forged
 * `x-user-id: admin` header cannot reach a server component via any
 * response path, whether the proxy ends up returning `next`,
 * `rewrite`, or a redirect that later triggers a same-origin
 * navigation.
 *
 * Both the configured `userHeaders` names AND a hardcoded baseline
 * of well-known identity header variants are deleted. The hardcoded
 * list defends against a consumer who configures a non-default
 * header name — a client can still try the defaults to spoof state
 * that third-party middleware in the pipeline might read.
 */
export function buildSanitizedRequestHeaders(
  request: NextRequest,
  config: ResolvedAuthProxyConfig
): Headers {
  const headers = new Headers(request.headers)
  for (const name of IDENTITY_HEADERS_BASELINE) {
    headers.delete(name)
  }
  headers.delete(config.userHeaders.userId)
  headers.delete(config.userHeaders.role)
  headers.delete(config.userHeaders.tenantId)
  headers.delete(config.userHeaders.tenantDomain)
  return headers
}

/**
 * Set a header when the value is a non-empty string, otherwise
 * DELETE it from the header set. Explicit deletion is required
 * because the sanitised header set we start from only guarantees
 * the baseline names are missing; a consumer-configured name that
 * happens to coincide with an unrelated header would otherwise
 * survive from the inbound request.
 *
 * The value is passed through {@link sanitizeHeaderValue} so a
 * crafted claim cannot smuggle an extra header via CR/LF injection.
 */
export function setOrDeleteHeader(headers: Headers, name: string, value: string | undefined): void {
  if (value === undefined || value.length === 0) {
    headers.delete(name)
    return
  }
  headers.set(name, sanitizeHeaderValue(value))
}

/**
 * Strip CR, LF, and NUL bytes from a candidate HTTP header value.
 * The Edge Runtime's `Headers` implementation rejects these via the
 * Fetch spec, but we sanitise proactively so a compliant throw does
 * not surface as an uncaught error in the middleware hot path.
 */
export function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n\0]/g, '')
}

/**
 * Pull a string claim from a JWT payload, returning `undefined`
 * when the field is absent or non-string.
 */
export function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}
