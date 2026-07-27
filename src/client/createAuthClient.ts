/**
 * Typed authentication client for the @bymax-one/nest-auth library.
 *
 * Wraps {@link createAuthFetch} with method-shaped helpers for every
 * standard auth flow (login, register, logout, refresh, getMe, MFA
 * challenge, password reset). Designed for the cookie-mode default —
 * HttpOnly cookies do the actual authentication, the methods just
 * compose the right URL, body, and method verb.
 *
 * Zero runtime dependencies beyond `fetch` and the shared subpath.
 */

import {
  AUTH_ROUTES,
  type AuthErrorResponse,
  AuthClientError,
  type AuthUserClient,
  type LoginResult,
  type MfaChallengeResult,
  type AuthResult
} from '@bymax-one/nest-auth/shared'

import { type AuthFetch, type AuthFetchConfig, createAuthFetch } from './createAuthFetch'

/**
 * Configuration accepted by {@link createAuthClient}.
 *
 * Same surface as {@link AuthFetchConfig} plus a required `baseUrl` —
 * the typed client always issues requests to a known server origin so
 * the per-method URL composition is unambiguous.
 */
export interface AuthClientConfig extends Omit<AuthFetchConfig, 'baseUrl'> {
  /**
   * Absolute base URL of the @bymax-one/nest-auth server
   * (e.g. `'https://api.example.com'`). The trailing slash is
   * optional; both forms are normalized internally.
   */
  baseUrl: string

  /**
   * Optional route prefix mounted by the consumer's NestJS app. When
   * the server uses a non-default `routePrefix`, mirror it here so
   * that the client targets the right URLs. Default: `'auth'`.
   */
  routePrefix?: string

  /**
   * Optional pre-built fetch wrapper. When provided, the client uses
   * this wrapper instead of building one from `baseUrl`/`credentials`/
   * `defaultHeaders`. Useful for tests or for sharing a single
   * wrapper across multiple clients (dashboard + platform).
   */
  authFetch?: AuthFetch
}

/**
 * Payload accepted by {@link AuthClient.register}.
 *
 * Mirrors the `RegisterDto` exposed by the server controller. Field
 * names match exactly so consumers can spread an existing form state
 * into the call without renaming.
 */
export interface RegisterInput {
  /** User's primary email address. */
  email: string
  /** Plaintext password — server hashes immediately on receipt. */
  password: string
  /** Display name. */
  name: string
  /** Tenant identifier scoping the new account. */
  tenantId: string
}

/**
 * Payload accepted by {@link AuthClient.login}.
 *
 * `tenantId` is required because the server-side `LoginDto` enforces it
 * with `@IsNotEmpty()`. Multi-tenant deployments use it to scope the
 * credential lookup; single-tenant deployments must still supply a
 * stable identifier (commonly `'default'`).
 */
export interface LoginInput {
  /** User's primary email address. */
  email: string
  /** Plaintext password — server hashes immediately on receipt. */
  password: string
  /** Tenant identifier the login attempt is scoped to. */
  tenantId: string
}

/**
 * Fields shared by every reset-password flow.
 *
 * The wire-shape variants below extend this and add exactly one of
 * `token`, `otp`, or `verifiedToken` — TypeScript then rejects calls
 * that try to combine them.
 */
interface ResetPasswordBase {
  /** Email address of the account being reset. */
  email: string
  /** Tenant the account belongs to. */
  tenantId: string
  /** New plaintext password — server hashes immediately. Min 8 chars, max 128. */
  newPassword: string
}

/**
 * Payload accepted by {@link AuthClient.resetPassword}.
 *
 * Discriminated union: callers must supply exactly one of `token`,
 * `otp`, or `verifiedToken`. The server's `ResetPasswordDto`
 * cross-validates the choice; the union shape lifts that constraint
 * into the type system so misuse is caught at compile time rather
 * than as a runtime 400.
 */
export type ResetPasswordInput =
  | (ResetPasswordBase & { token: string; otp?: never; verifiedToken?: never })
  | (ResetPasswordBase & { otp: string; token?: never; verifiedToken?: never })
  | (ResetPasswordBase & { verifiedToken: string; token?: never; otp?: never })

/**
 * Public method surface of the typed auth client.
 */
export interface AuthClient {
  /**
   * Submit credentials and receive either a full {@link AuthResult}
   * or an {@link MfaChallengeResult} when the account requires MFA.
   *
   * @returns A discriminated {@link LoginResult} — branch on
   *   `'mfaRequired' in result` to handle the MFA case.
   */
  login(input: LoginInput): Promise<LoginResult>

  /**
   * Register a new local account. The server may auto-login on
   * success or require email verification before login is permitted,
   * depending on `emailVerification.required`.
   */
  register(data: RegisterInput): Promise<AuthResult>

  /** Revoke the current session and clear the auth cookies server-side. */
  logout(): Promise<void>

  /**
   * Manually rotate the refresh token. The auto-refresh in
   * {@link createAuthFetch} handles this automatically on 401, so
   * call this only for explicit refresh flows.
   */
  refresh(): Promise<AuthResult>

  /** Fetch the currently authenticated user. */
  getMe(): Promise<AuthUserClient>

  /**
   * Complete an MFA challenge by submitting the temp token returned
   * from `login` together with either a 6-digit TOTP code or a
   * recovery code in `xxxx-xxxx-xxxx` format.
   */
  mfaChallenge(tempToken: string, code: string): Promise<AuthResult>

  /**
   * Initiate a password reset. The server returns 200 regardless of
   * whether the email is registered — the response carries no signal
   * either way (anti-enumeration design). Both `email` and `tenantId`
   * are required by the server DTO.
   */
  forgotPassword(email: string, tenantId: string): Promise<void>

  /**
   * Submit a new password using one of the three reset flows:
   * token, OTP, or verified-token. See {@link ResetPasswordInput}
   * for the mutual-exclusivity rule.
   */
  resetPassword(input: ResetPasswordInput): Promise<void>
}

/**
 * Trim trailing slashes from `baseUrl` so concatenation with route
 * paths produces exactly one separator regardless of the input form.
 */
function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '')
}

/**
 * Trim trailing slashes from the optional route prefix and reject
 * leading slashes; the join routine adds the separator itself.
 */
function normalizeRoutePrefix(prefix: string): string {
  return prefix.replace(/^\/+|\/+$/g, '')
}

/**
 * Serialize a value to the JSON body wire format.
 *
 * Centralized so the serialization choice is consistent and so a
 * future migration (e.g. to a wire codec) only touches one place.
 */
function jsonBody(value: unknown): string {
  return JSON.stringify(value)
}

/**
 * Best-effort `AuthErrorResponse` extraction from a raw response body
 * string. Returns `undefined` when the text is empty, not JSON, or
 * does not match either recognized error shape. Centralized so the
 * happy and no-content paths produce identical error envelopes.
 *
 * The `response` is needed because the server's own error envelope
 * carries no status information in the body — see
 * {@link readErrorEnvelope}.
 */
function extractErrorBody(text: string, response: Response): AuthErrorResponse | undefined {
  // Stryker disable next-line ConditionalExpression: empty-body fast path is an optimization; an empty string also makes JSON.parse throw, which the surrounding try/catch turns into the same `undefined`
  if (text.length === 0) return undefined
  try {
    const parsed: unknown = JSON.parse(text)
    const fromEnvelope = readErrorEnvelope(parsed, response)
    if (fromEnvelope !== undefined) return fromEnvelope
    return isAuthErrorBody(parsed) ? parsed : undefined
  } catch {
    return undefined
  }
}

/**
 * Throw the canonical {@link AuthClientError} for a non-OK response,
 * carrying the parsed error body when present. Caller is responsible
 * for branching on `response.ok` first.
 */
function throwAuthError(response: Response, text: string): never {
  const body = extractErrorBody(text, response)
  const message = body?.message ?? `Request failed with status ${response.status}`
  throw new AuthClientError(message, response.status, body)
}

/**
 * Read the response body, parse it as JSON when present, and throw
 * an {@link AuthClientError} on non-2xx — the canonical translation
 * between HTTP transport and the typed client surface.
 *
 * `T` is asserted, not validated. Callers receive whatever the
 * server returned; if the server contract drifts, the burden of
 * detection is on integration tests, not this helper.
 *
 * An empty body on a 2xx response is treated as a protocol error —
 * callers that opted into `post<T>()` are expecting a JSON payload.
 * Void endpoints must route through {@link expectNoContent} instead.
 */
async function parseJsonOrThrow<T>(response: Response): Promise<T> {
  const text = await response.text()
  if (!response.ok) {
    throwAuthError(response, text)
  }

  if (text.length === 0) {
    throw new AuthClientError(
      `Response from ${response.url} was empty — expected a JSON body`,
      response.status
    )
  }
  try {
    return JSON.parse(text) as T
  } catch {
    throw new AuthClientError(`Response from ${response.url} is not valid JSON`, response.status)
  }
}

/**
 * Treat an empty/2xx response as success. Used by endpoints that
 * intentionally return no body (logout, forgot-password,
 * reset-password) — saves callers the boilerplate of awaiting the
 * body just to discard it.
 */
async function expectNoContent(response: Response): Promise<void> {
  if (!response.ok) {
    const text = await response.text()
    throwAuthError(response, text)
  }
  // Drain the body so the underlying connection is released in
  // runtimes that hold it open until the stream ends.
  await response.body?.cancel().catch(/* istanbul ignore next */ () => undefined)
}

/**
 * Fallback for `AuthErrorResponse.error` when the transport supplies
 * no reason phrase — HTTP/2 and HTTP/3 never send one, so an empty
 * `statusText` is the norm on modern deployments rather than an
 * anomaly.
 */
const UNKNOWN_STATUS_TEXT = 'Error'

/**
 * Lift the @bymax-one/nest-auth error envelope into the flat
 * {@link AuthErrorResponse} view exposed to consumers.
 *
 * The server's `AuthException` serializes to
 * `{ error: { code, message, details } }` — `details` being `null`
 * when the thrower supplied none. That body carries no status
 * information of its own, so `error` and `statusCode` are filled from
 * the HTTP response, keeping the consumer-facing shape identical to
 * the one produced by a flat NestJS exception body.
 *
 * Returns `undefined` for anything that is not that envelope (a
 * primitive, a flat NestJS body, an HTML error page already rejected
 * upstream by `JSON.parse`, or an envelope missing `code`/`message`),
 * letting the caller fall through to the flat-body guard.
 */
function readErrorEnvelope(value: unknown, response: Response): AuthErrorResponse | undefined {
  const envelope = (value as { error?: unknown } | null)?.error
  // Stryker disable next-line ConditionalExpression,LogicalOperator: object-type guard precedes the authoritative field checks; a non-object envelope also fails those (or the caller's catch swallows the null-deref), yielding the same `undefined`
  if (typeof envelope !== 'object' || envelope === null) return undefined

  const candidate = envelope as Record<string, unknown>
  const code = candidate['code']
  const message = candidate['message']
  if (typeof code !== 'string' || typeof message !== 'string') return undefined

  const details = candidate['details']
  return {
    message,
    error: response.statusText.length > 0 ? response.statusText : UNKNOWN_STATUS_TEXT,
    statusCode: response.status,
    code,
    // A non-object `details` is not something the server emits; treat
    // it as absent rather than propagating an unusable value under a
    // type that promises a record.
    // Stryker disable ConditionalExpression: equivalent — `typeof null` is `'object'`, so
    // dropping the null check casts `null` to the record type and yields the very `null` the
    // other branch returns. Block form because the mutant sits two lines below a wrapped
    // comment, where the per-line directive points at the comment's own continuation.
    details:
      typeof details === 'object' && details !== null ? (details as Record<string, unknown>) : null
    // Stryker restore ConditionalExpression
  }
}

/**
 * Type-guard for the flat NestJS error body shape.
 *
 * Conservative — checks for the three structural fields that a
 * built-in `HttpException` guarantees (a `ValidationPipe` 400, or any
 * non-auth exception thrown by the consumer's app). The library's own
 * errors do NOT take this path; they are handled by
 * {@link readErrorEnvelope}. The `code` field is optional so callers
 * cannot silently rely on it.
 */
function isAuthErrorBody(value: unknown): value is AuthErrorResponse {
  // Stryker disable next-line ConditionalExpression,LogicalOperator: object-type guard precedes the authoritative field checks; a non-object value also fails those checks (or the catch swallows the null-deref), yielding the same `false`
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Record<string, unknown>
  return (
    typeof candidate['message'] === 'string' &&
    typeof candidate['error'] === 'string' &&
    typeof candidate['statusCode'] === 'number'
  )
}

/**
 * Build the full URL for a given controller-relative route.
 *
 * Handles the common case (relative route under the prefix) and the
 * absolute-path case (proxy routes that already start with `/`,
 * e.g. `'/api/auth/client-refresh'`) without forcing the caller to
 * duplicate the prefix.
 */
function buildUrl(baseUrl: string, routePrefix: string, path: string): string {
  /* istanbul ignore next -- forward-compat: the current public API only
     composes relative AUTH_ROUTES values; the absolute-path branch keeps
     buildUrl correct if a future route is mounted at a non-prefixed path. */
  // Stryker disable next-line ConditionalExpression,MethodExpression,BlockStatement: forward-compat absolute-path branch; every route this builds is relative and none ends with '/', so startsWith('/') vs endsWith('/') vs false are indistinguishable
  if (path.startsWith('/')) {
    // Stryker disable next-line StringLiteral: unreachable — no route this builds is absolute, so the branch never returns
    return `${baseUrl}${path}`
  }
  return routePrefix.length > 0 ? `${baseUrl}/${routePrefix}/${path}` : `${baseUrl}/${path}`
}

/**
 * Build a typed {@link AuthClient} bound to a specific server.
 *
 * @example
 * ```ts
 * const auth = createAuthClient({
 *   baseUrl: 'https://api.example.com',
 *   onSessionExpired: () => router.push('/sign-in')
 * })
 *
 * const result = await auth.login({
 *   email: 'user@example.com',
 *   password: 'pw',
 *   tenantId: 'default'
 * })
 * if ('mfaRequired' in result) {
 *   const final = await auth.mfaChallenge(result.mfaTempToken, '123456')
 * }
 * ```
 */
export function createAuthClient(config: AuthClientConfig): AuthClient {
  const baseUrl = normalizeBaseUrl(config.baseUrl)
  const routePrefix = normalizeRoutePrefix(config.routePrefix ?? 'auth')

  // Build the underlying fetch wrapper with its own dedup state.
  // When the caller supplies `authFetch`, reuse it as-is so that
  // dashboard + platform clients can share a single dedup slot when
  // they share a backend.
  const authFetch: AuthFetch =
    config.authFetch ??
    createAuthFetch({
      baseUrl,
      routePrefix,
      // Stryker disable next-line ConditionalExpression: spreading `{ key: undefined }` vs omitting the key is identical — createAuthFetch coalesces each option with `??`/falsy checks downstream
      ...(config.refreshEndpoint !== undefined ? { refreshEndpoint: config.refreshEndpoint } : {}),
      // Stryker disable next-line ConditionalExpression: spreading `{ key: undefined }` vs omitting the key is identical — the consumer coalesces this option downstream
      ...(config.credentials !== undefined ? { credentials: config.credentials } : {}),
      // Stryker disable next-line ConditionalExpression: spreading `{ key: undefined }` vs omitting the key is identical — the consumer coalesces this option downstream
      ...(config.defaultHeaders !== undefined ? { defaultHeaders: config.defaultHeaders } : {}),
      // Stryker disable next-line ConditionalExpression: spreading `{ key: undefined }` vs omitting the key is identical — the consumer coalesces this option downstream
      ...(config.onSessionExpired !== undefined
        ? { onSessionExpired: config.onSessionExpired }
        : {}),
      // Stryker disable next-line ConditionalExpression: spreading `{ key: undefined }` vs omitting the key is identical — the consumer coalesces this option downstream
      ...(config.timeout !== undefined ? { timeout: config.timeout } : {})
    })

  // When the caller supplies a custom `authFetch`, that wrapper is
  // expected to know its own base URL — so the per-method calls
  // pass relative paths and let the wrapper resolve them. When the
  // wrapper was built here, it also has the base URL configured, so
  // relative paths work in both branches.
  const url = (path: string): string => buildUrl(baseUrl, routePrefix, path)

  async function post<T>(path: string, body: unknown): Promise<T> {
    const response = await authFetch(url(path), {
      method: 'POST',
      body: jsonBody(body)
    })
    return parseJsonOrThrow<T>(response)
  }

  async function postNoContent(path: string, body: unknown): Promise<void> {
    const response = await authFetch(url(path), {
      method: 'POST',
      body: jsonBody(body)
    })
    await expectNoContent(response)
  }

  async function get<T>(path: string): Promise<T> {
    const response = await authFetch(url(path), { method: 'GET' })
    return parseJsonOrThrow<T>(response)
  }

  return {
    async login(input): Promise<LoginResult> {
      return post<LoginResult>(AUTH_ROUTES.dashboard.login, input)
    },

    async register(data): Promise<AuthResult> {
      return post<AuthResult>(AUTH_ROUTES.dashboard.register, data)
    },

    async logout(): Promise<void> {
      return postNoContent(AUTH_ROUTES.dashboard.logout, {})
    },

    async refresh(): Promise<AuthResult> {
      return post<AuthResult>(AUTH_ROUTES.dashboard.refresh, {})
    },

    async getMe(): Promise<AuthUserClient> {
      return get<AuthUserClient>(AUTH_ROUTES.dashboard.me)
    },

    async mfaChallenge(tempToken, code): Promise<AuthResult> {
      const result = await post<AuthResult | MfaChallengeResult>(AUTH_ROUTES.mfa.challenge, {
        mfaTempToken: tempToken,
        code
      })
      if ('mfaRequired' in result) {
        // The server should never return a fresh challenge in
        // response to a challenge submission. Treat it as a
        // protocol error so the caller sees an actionable failure
        // rather than receiving a malformed `AuthResult`.
        throw new AuthClientError(
          'MFA challenge endpoint returned another challenge — server contract mismatch',
          502
        )
      }
      return result
    },

    async forgotPassword(email, tenantId): Promise<void> {
      return postNoContent(AUTH_ROUTES.password.forgotPassword, { email, tenantId })
    },

    async resetPassword(input): Promise<void> {
      // The server requires exactly one of token/otp/verifiedToken;
      // the typed surface enforces presence of the surrounding
      // fields, mutual-exclusivity is checked server-side and
      // surfaced as an AuthClientError when violated.
      const payload: Record<string, string> = {
        email: input.email,
        tenantId: input.tenantId,
        newPassword: input.newPassword
      }
      if (input.token !== undefined) payload['token'] = input.token
      if (input.otp !== undefined) payload['otp'] = input.otp
      if (input.verifiedToken !== undefined) payload['verifiedToken'] = input.verifiedToken
      return postNoContent(AUTH_ROUTES.password.resetPassword, payload)
    }
  }
}
