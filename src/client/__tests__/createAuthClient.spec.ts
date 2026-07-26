/**
 * Unit tests for `createAuthClient` — the typed authentication client
 * that composes the fetch wrapper with method-shaped helpers for
 * every standard auth flow.
 *
 * Strategy: every test injects a custom `authFetch` mock instead of
 * letting the factory build one with `createAuthFetch`. This keeps
 * the assertions focused on URL/body/method composition (the client's
 * actual responsibility) and avoids re-testing the wrapper's 401 +
 * refresh logic, which is already covered by `createAuthFetch.spec.ts`.
 *
 * All credential-shaped strings (passwords, tokens) are intentionally
 * scoped with `__test_only_*` / `mock-*` prefixes so secret-scanning
 * tooling and log scrapers can ignore them on sight — they are NOT
 * real credentials.
 */

import { AuthClientError } from '../../shared'
import { createAuthClient } from '../createAuthClient'
import type { AuthFetch } from '../createAuthFetch'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

interface CapturedCall {
  url: string
  method: string | undefined
  body: unknown
}

/**
 * Build an `AuthFetch` mock that returns a configurable response and
 * captures every invocation for assertion. Centralized so every test
 * uses the same pattern.
 */
function makeAuthFetchMock(responder: () => Response | Promise<Response>): {
  authFetch: AuthFetch
  calls: CapturedCall[]
  spy: jest.Mock
} {
  const calls: CapturedCall[] = []
  const spy = jest.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString()
    let parsedBody: unknown
    if (typeof init?.body === 'string') {
      try {
        parsedBody = JSON.parse(init.body)
      } catch {
        parsedBody = init.body
      }
    } else {
      parsedBody = init?.body ?? undefined
    }
    calls.push({
      url,
      method: init?.method,
      body: parsedBody
    })
    return responder()
  })
  return { authFetch: spy as unknown as AuthFetch, calls, spy }
}

/**
 * Build a JSON Response — the cookie-mode server flow returns 200
 * with the JSON body for GET/POST endpoints alike. A `null` body
 * argument is used for the canonical "no content" responses (204);
 * the `Response` constructor disallows a body for null-body statuses
 * (204, 205, 304) so we must pass `null` rather than `''` to avoid
 * a TypeError at construction time.
 */
function jsonResponse(status: number, body: unknown): Response {
  const isNullBodyStatus = status === 204 || status === 205 || status === 304
  const init: ResponseInit = isNullBodyStatus
    ? { status }
    : { status, headers: { 'Content-Type': 'application/json' } }
  const responseBody = isNullBodyStatus || body === undefined ? null : JSON.stringify(body)
  return new Response(responseBody, init)
}

/**
 * Build a non-JSON Response — exercises the parse-failure branch in
 * `extractErrorBody`.
 */
function textResponse(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html' } })
}

/**
 * Build a Response carrying the server's own error envelope —
 * `{ error: { code, message, details } }`, the exact body
 * `AuthException` serializes once NestJS's exception filter runs.
 *
 * `statusText` is a parameter because the envelope carries no status
 * text of its own: the client fills `AuthErrorResponse.error` from the
 * response's reason phrase, which HTTP/2 always leaves empty. Omitting
 * the argument reproduces that empty-reason-phrase case.
 */
function envelopeResponse(status: number, error: unknown, statusText?: string): Response {
  const headers = { 'Content-Type': 'application/json' }
  const init: ResponseInit =
    statusText === undefined ? { status, headers } : { status, statusText, headers }
  return new Response(JSON.stringify({ error }), init)
}

// ---------------------------------------------------------------------------
// createAuthClient — login flow
// ---------------------------------------------------------------------------

describe('createAuthClient — login', () => {
  // B1: validates URL composition (`/auth/login`), HTTP verb (POST),
  // and that the entire LoginInput payload is forwarded to the server.
  it('posts the LoginInput payload to /auth/login', async () => {
    const userPayload = {
      user: {
        id: 'u1',
        email: 'a@b.c',
        name: 'Alice',
        role: 'admin',
        tenantId: 't1',
        status: 'active',
        mfaEnabled: false
      },
      accessToken: ''
    }
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(200, userPayload))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    expect(calls.length).toBe(1)
    expect(calls[0]?.url).toBe('https://api.example.com/auth/login')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.body).toEqual({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })
  })

  // B2: success path returns the parsed AuthResult unchanged so
  // consumers can use it directly for state hydration.
  it('returns the AuthResult on success', async () => {
    const expected = {
      user: {
        id: 'u1',
        email: 'a@b.c',
        name: 'Alice',
        role: 'admin',
        tenantId: 't1',
        status: 'active',
        mfaEnabled: false
      },
      accessToken: 'mock-access-token'
    }
    const { authFetch } = makeAuthFetchMock(() => jsonResponse(200, expected))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    const result = await client.login({
      email: 'a@b.c',
      password: '__test_only_pw__',
      tenantId: 't1'
    })

    expect(result).toEqual(expected)
  })

  // B3: when the account requires MFA the server responds with the
  // challenge-shaped body; the client surfaces it as a discriminated
  // union so callers can branch on `'mfaRequired' in result`.
  it('returns the MFA challenge result when the server escalates to MFA', async () => {
    const challenge = { mfaRequired: true, mfaTempToken: 'temp-token' }
    const { authFetch } = makeAuthFetchMock(() => jsonResponse(200, challenge))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    const result = await client.login({
      email: 'a@b.c',
      password: '__test_only_pw__',
      tenantId: 't1'
    })

    expect('mfaRequired' in result).toBe(true)
    if ('mfaRequired' in result) {
      expect(result.mfaTempToken).toBe('temp-token')
    }
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — register flow
// ---------------------------------------------------------------------------

describe('createAuthClient — register', () => {
  // B4: register hits /auth/register and forwards the entire payload
  // — keep the field names matching the server `RegisterDto`.
  it('posts the RegisterInput payload to /auth/register', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() =>
      jsonResponse(201, { user: {}, accessToken: '' })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.register({
      email: 'a@b.c',
      password: '__test_only_pw_long__',
      name: 'Alice',
      tenantId: 't1'
    })

    expect(calls[0]?.url).toBe('https://api.example.com/auth/register')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.body).toEqual({
      email: 'a@b.c',
      password: '__test_only_pw_long__',
      name: 'Alice',
      tenantId: 't1'
    })
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — logout, refresh, getMe
// ---------------------------------------------------------------------------

describe('createAuthClient — session lifecycle', () => {
  // B5: logout posts an empty body; the helper resolves to void on 2xx.
  it('logout posts an empty object to /auth/logout and resolves to void', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(204, undefined))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(client.logout()).resolves.toBeUndefined()
    expect(calls[0]?.url).toBe('https://api.example.com/auth/logout')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.body).toEqual({})
  })

  // B6: explicit refresh — the wrapper auto-refreshes on 401, but
  // some flows (token rotation diagnostics, manual session probes)
  // need an imperative call.
  it('refresh posts to /auth/refresh and returns the AuthResult', async () => {
    const expected = {
      user: {
        id: 'u1',
        email: 'a@b.c',
        name: 'Alice',
        role: 'admin',
        tenantId: 't1',
        status: 'active',
        mfaEnabled: false
      },
      accessToken: ''
    }
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(200, expected))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    const result = await client.refresh()

    expect(calls[0]?.url).toBe('https://api.example.com/auth/refresh')
    expect(calls[0]?.method).toBe('POST')
    expect(result).toEqual(expected)
  })

  // B7: getMe issues GET (not POST) so the verb is what the
  // controller expects. The body is undefined — JSON content-type
  // still rides along but no body is sent.
  it('getMe issues GET /auth/me and returns the AuthUserClient', async () => {
    const expected = {
      id: 'u1',
      email: 'a@b.c',
      name: 'Alice',
      role: 'admin',
      tenantId: 't1',
      status: 'active',
      mfaEnabled: false
    }
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(200, expected))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    const me = await client.getMe()

    expect(calls[0]?.url).toBe('https://api.example.com/auth/me')
    expect(calls[0]?.method).toBe('GET')
    expect(me).toEqual(expected)
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — MFA challenge
// ---------------------------------------------------------------------------

describe('createAuthClient — mfaChallenge', () => {
  // B8: the wire payload uses `mfaTempToken` (matches MfaChallengeDto)
  // and `code` — both with the server-defined names.
  it('posts mfaTempToken and code to /auth/mfa/challenge', async () => {
    const expected = {
      user: {
        id: 'u1',
        email: 'a@b.c',
        name: 'Alice',
        role: 'admin',
        tenantId: 't1',
        status: 'active',
        mfaEnabled: true
      },
      accessToken: ''
    }
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(200, expected))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.mfaChallenge('temp-token', '123456')

    expect(calls[0]?.url).toBe('https://api.example.com/auth/mfa/challenge')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.body).toEqual({ mfaTempToken: 'temp-token', code: '123456' })
  })

  // B9: defensive branch — if the server responded to a challenge
  // with another challenge, the client throws `AuthClientError(502)`
  // so the caller does not end up with an invalid AuthResult. The
  // message is pinned so blanking the contract-mismatch string is
  // caught — consumers surface it for diagnostics.
  it('throws AuthClientError(502) when the server returns another challenge', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      jsonResponse(200, { mfaRequired: true, mfaTempToken: 'temp-token-2' })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(client.mfaChallenge('temp-token', '123456')).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 502,
      message: expect.stringContaining('another challenge')
    })
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — password reset flows
// ---------------------------------------------------------------------------

describe('createAuthClient — forgotPassword', () => {
  // B10: tenantId is required by the server DTO; the client surface
  // makes it required so a missing value cannot reach the wire.
  it('posts email + tenantId to /auth/password/forgot-password', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(204, undefined))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.forgotPassword('user@example.com', 'tenant-1')

    expect(calls[0]?.url).toBe('https://api.example.com/auth/password/forgot-password')
    expect(calls[0]?.method).toBe('POST')
    expect(calls[0]?.body).toEqual({ email: 'user@example.com', tenantId: 'tenant-1' })
  })
})

describe('createAuthClient — resetPassword', () => {
  // B11: token-based flow — only `token` is set among the three
  // mutually-exclusive fields.
  it('token flow forwards email/tenantId/newPassword/token', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(204, undefined))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.resetPassword({
      email: 'a@b.c',
      tenantId: 't1',
      newPassword: '__test_only_new_pw__',
      token: 'reset-token'
    })

    expect(calls[0]?.body).toEqual({
      email: 'a@b.c',
      tenantId: 't1',
      newPassword: '__test_only_new_pw__',
      token: 'reset-token'
    })
  })

  // B12: OTP-based flow — `otp` replaces `token`. The discriminated
  // union prevents callers from setting both at compile time, but
  // the runtime composition still has to leave `token` out of the
  // wire payload.
  it('otp flow forwards otp and omits token / verifiedToken', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(204, undefined))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.resetPassword({
      email: 'a@b.c',
      tenantId: 't1',
      newPassword: '__test_only_new_pw__',
      otp: '123456'
    })

    expect(calls[0]?.body).toEqual({
      email: 'a@b.c',
      tenantId: 't1',
      newPassword: '__test_only_new_pw__',
      otp: '123456'
    })
  })

  // B13: verifiedToken-based flow — `verifiedToken` replaces both
  // `token` and `otp`.
  it('verifiedToken flow forwards verifiedToken and omits token / otp', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() => jsonResponse(204, undefined))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.resetPassword({
      email: 'a@b.c',
      tenantId: 't1',
      newPassword: '__test_only_new_pw__',
      verifiedToken: 'a'.repeat(64)
    })

    expect(calls[0]?.body).toEqual({
      email: 'a@b.c',
      tenantId: 't1',
      newPassword: '__test_only_new_pw__',
      verifiedToken: 'a'.repeat(64)
    })
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — error handling
// ---------------------------------------------------------------------------

describe('createAuthClient — error handling', () => {
  // B14: the canonical error envelope reaches the caller intact —
  // status, code, and the parsed body all surface on the thrown
  // AuthClientError.
  it('throws AuthClientError with status, code, and parsed body for non-2xx responses', async () => {
    const errorBody = {
      message: 'invalid creds',
      error: 'Unauthorized',
      statusCode: 401,
      code: 'auth.invalid_credentials'
    }
    const { authFetch } = makeAuthFetchMock(() => jsonResponse(401, errorBody))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(
      client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })
    ).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 401,
      code: 'auth.invalid_credentials',
      body: errorBody
    })
  })

  // B15: when the server returns a non-JSON body (proxy 502, edge
  // worker 504, etc.), the client falls back to a generic message
  // and reports `body` as undefined so consumers can detect the
  // protocol mismatch.
  it('throws AuthClientError with generic message when the body is not JSON', async () => {
    const { authFetch } = makeAuthFetchMock(() => textResponse(502, '<html>upstream down</html>'))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client
      .login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })
      .catch((err: unknown) => {
        caught = err
      })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(502)
      expect(caught.body).toBeUndefined()
      expect(caught.message).toMatch(/Request failed with status 502/)
    }
  })

  // B16: the thrown error must satisfy both `instanceof Error` and
  // `instanceof AuthClientError` so consumers can use either check.
  it('thrown error satisfies instanceof checks for both AuthClientError and Error', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      jsonResponse(403, { message: 'denied', error: 'Forbidden', statusCode: 403 })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client
      .login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })
      .catch((err: unknown) => {
        caught = err
      })

    expect(caught).toBeInstanceOf(Error)
    expect(caught).toBeInstanceOf(AuthClientError)
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — server error envelope
// ---------------------------------------------------------------------------

describe('createAuthClient — server error envelope', () => {
  // The library's own server serializes every AuthException as
  // `{ error: { code, message, details } }` (see
  // src/server/errors/auth-exception.ts). This is the primary path:
  // the stable `code`, the end-user `message`, and the structured
  // `details` (e.g. the lockout's `retryAfterSeconds`) must all reach
  // the caller, with `error`/`statusCode` filled from the HTTP
  // response since the envelope does not repeat them.
  it('surfaces code, message, and details from the server error envelope', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      envelopeResponse(
        429,
        {
          code: 'auth.account_locked',
          message: 'Account temporarily locked',
          details: { retryAfterSeconds: 300 }
        },
        'Too Many Requests'
      )
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client
      .login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })
      .catch((err: unknown) => {
        caught = err
      })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(429)
      expect(caught.code).toBe('auth.account_locked')
      expect(caught.message).toBe('Account temporarily locked')
      expect(caught.body).toEqual({
        message: 'Account temporarily locked',
        error: 'Too Many Requests',
        statusCode: 429,
        code: 'auth.account_locked',
        details: { retryAfterSeconds: 300 }
      })
    }
  })

  // The common envelope has `details: null` (AuthException defaults it
  // when the thrower supplies none), and HTTP/2 never sends a reason
  // phrase — so `statusText` is empty. Pins both defaults: `details`
  // stays `null` and `error` falls back to the generic `'Error'`
  // rather than leaking an empty string into consumer logs.
  it('normalizes an envelope with null details and no reason phrase', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      envelopeResponse(401, {
        code: 'auth.invalid_credentials',
        message: 'Invalid email or password',
        details: null
      })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(
      client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })
    ).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 401,
      code: 'auth.invalid_credentials',
      message: 'Invalid email or password',
      body: {
        message: 'Invalid email or password',
        error: 'Error',
        statusCode: 401,
        details: null
      }
    })
  })

  // The envelope reaches the void endpoints through `expectNoContent`,
  // a different call path than `parseJsonOrThrow`. Verifies logout
  // surfaces the same normalized body rather than a generic failure.
  it('surfaces the envelope on endpoints that expect no content', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      envelopeResponse(
        403,
        { code: 'auth.forbidden', message: 'Forbidden', details: null },
        'Forbidden'
      )
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(client.logout()).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 403,
      code: 'auth.forbidden',
      message: 'Forbidden'
    })
  })

  // `details` is typed as a record; a gateway that rewrites it into a
  // scalar must not leak an unusable value under that type. Pins the
  // record check — the code and message still surface, only `details`
  // degrades to `null`.
  it('drops a details payload that is not an object', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      envelopeResponse(401, {
        code: 'auth.invalid_credentials',
        message: 'Invalid email or password',
        details: 'unexpected-scalar'
      })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.code).toBe('auth.invalid_credentials')
      expect(caught.body?.details).toBeNull()
    }
  })

  // A JSON body shaped like the envelope but whose `code` is not a
  // string is not the server's envelope. Pins the `code` typeof clause
  // independently: the client must degrade to the generic error rather
  // than publishing a non-string as a branchable `code`.
  it('rejects an envelope whose code is not a string', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      envelopeResponse(401, { code: 42, message: 'Invalid email or password', details: null })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(401)
      expect(caught.code).toBeUndefined()
      expect(caught.body).toBeUndefined()
      expect(caught.message).toMatch(/Request failed with status 401/)
    }
  })

  // Same for `message`: pins the `message` typeof clause independently
  // of `code`, so a guard that checks only one of the two is caught.
  it('rejects an envelope whose message is missing', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      envelopeResponse(401, { code: 'auth.invalid_credentials', details: null })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.body).toBeUndefined()
      expect(caught.message).toMatch(/Request failed with status 401/)
    }
  })

  // A JSON body that is neither the envelope nor a flat NestJS body —
  // e.g. an API gateway with its own error format nesting an unrelated
  // object under `error`. Must degrade to the generic error instead of
  // publishing a half-parsed body.
  it('rejects a JSON body that is neither the envelope nor a flat NestJS body', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      envelopeResponse(502, { reason: 'upstream refused', retryable: true })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(502)
      expect(caught.body).toBeUndefined()
      expect(caught.message).toMatch(/Request failed with status 502/)
    }
  })

  // Regression guard for the flat NestJS shape: a `ValidationPipe` 400
  // carries `error` as a STRING, not as the envelope object. Envelope
  // support must not shadow that path — the flat body still passes
  // through verbatim.
  it('still parses a flat NestJS body whose error field is a status string', async () => {
    const flatBody = {
      message: 'email must be an email',
      error: 'Bad Request',
      statusCode: 400
    }
    const { authFetch } = makeAuthFetchMock(() => jsonResponse(400, flatBody))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(
      client.login({ email: 'not-an-email', password: '__test_only_pw__', tenantId: 't1' })
    ).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 400,
      message: 'email must be an email',
      body: flatBody
    })
  })

  // A proxy or gateway between client and server can answer with HTML
  // or plain text. Pins the void-endpoint path (`expectNoContent`)
  // specifically: parsing must not throw a SyntaxError, it must
  // degrade to the generic AuthClientError with no body.
  it('degrades to a generic error when a proxy returns a non-JSON body', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      textResponse(503, '<html><body>Service Unavailable</body></html>')
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.logout().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(503)
      expect(caught.body).toBeUndefined()
      expect(caught.message).toMatch(/Request failed with status 503/)
    }
  })

  // An error response with no body at all (some load balancers strip
  // it on 5xx) must reach the caller as the generic AuthClientError —
  // pinned here on the JSON-parsing path (`getMe`) so the empty-body
  // short-circuit is exercised for both response helpers.
  it('degrades to a generic error when the error response body is empty', async () => {
    const { authFetch } = makeAuthFetchMock(() => new Response('', { status: 502 }))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.getMe().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(502)
      expect(caught.code).toBeUndefined()
      expect(caught.body).toBeUndefined()
      expect(caught.message).toMatch(/Request failed with status 502/)
    }
  })

  // A transport failure (DNS, TLS, offline) never produces a Response,
  // so there is no envelope to read. It must stay distinguishable from
  // a server-sent auth error: the original rejection propagates
  // untouched instead of being repackaged as an AuthClientError.
  it('propagates a network-layer failure without wrapping it as an AuthClientError', async () => {
    const networkError = new TypeError('Failed to fetch')
    const { authFetch } = makeAuthFetchMock(() => Promise.reject<Response>(networkError))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client
      .login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })
      .catch((err: unknown) => {
        caught = err
      })

    expect(caught).toBe(networkError)
    expect(caught).not.toBeInstanceOf(AuthClientError)
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — config knobs
// ---------------------------------------------------------------------------

describe('createAuthClient — configuration', () => {
  // B17: a non-default routePrefix changes URL composition for every
  // method — verifying via login is sufficient because all helpers
  // use the same `buildUrl` routine.
  it('honors a custom routePrefix in URL composition', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() =>
      jsonResponse(200, { user: {}, accessToken: '' })
    )
    const client = createAuthClient({
      baseUrl: 'https://api.example.com',
      routePrefix: 'api/v1/auth',
      authFetch
    })

    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    expect(calls[0]?.url).toBe('https://api.example.com/api/v1/auth/login')
  })

  // The routePrefix normalizer strips ALL leading and ALL trailing
  // slashes (`/^\/+|\/+$/g`) and replaces them with the empty string,
  // so the join routine controls the separators. A prefix wrapped in
  // multiple slashes on both sides must collapse to a single clean
  // segment. Pins both the `+` quantifiers (one-or-more slashes, not
  // exactly one) and the empty-string replacement: a regex that strips
  // only a single slash would leave `//auth//login`, and a non-empty
  // replacement would inject junk into the URL.
  it('strips multiple leading and trailing slashes from routePrefix', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() =>
      jsonResponse(200, { user: {}, accessToken: '' })
    )
    const client = createAuthClient({
      baseUrl: 'https://api.example.com',
      routePrefix: '///auth///',
      authFetch
    })

    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    expect(calls[0]?.url).toBe('https://api.example.com/auth/login')
  })

  // B18: trailing slashes on baseUrl are normalized so URLs do not
  // contain `//` segments — important because some HTTP servers
  // 301-redirect those, breaking the cookie attachment.
  it('normalizes trailing slashes on baseUrl', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() =>
      jsonResponse(200, { user: {}, accessToken: '' })
    )
    const client = createAuthClient({
      baseUrl: 'https://api.example.com///',
      authFetch
    })

    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    expect(calls[0]?.url).toBe('https://api.example.com/auth/login')
  })

  // B19: a caller-supplied authFetch is used directly so consumers
  // can plug in their own instrumented or pre-configured wrapper
  // without losing the typed method surface.
  it('uses a caller-supplied authFetch verbatim', async () => {
    const { authFetch, spy } = makeAuthFetchMock(() =>
      jsonResponse(200, { user: {}, accessToken: '' })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    expect(spy).toHaveBeenCalledTimes(1)
  })

  // Covers the `routePrefix === ''` branch of `buildUrl`. A consumer
  // that mounts the auth controllers directly at the root (no
  // prefix) must still reach them — the URL must be `${baseUrl}/login`,
  // not `${baseUrl}//login`.
  it('omits the prefix segment when routePrefix is empty', async () => {
    const { authFetch, calls } = makeAuthFetchMock(() =>
      jsonResponse(200, { user: {}, accessToken: '' })
    )
    const client = createAuthClient({
      baseUrl: 'https://api.example.com',
      routePrefix: '',
      authFetch
    })

    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    expect(calls[0]?.url).toBe('https://api.example.com/login')
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — response parsing edge cases
// ---------------------------------------------------------------------------

describe('createAuthClient — response parsing edge cases', () => {
  // Covers `parseJsonOrThrow` empty-body 2xx branch. A 2xx with no
  // body on a typed endpoint (`post<T>` / `get<T>`) is a protocol
  // error — callers expecting a JSON payload must NOT silently
  // receive `undefined` masquerading as `T`. Void endpoints route
  // through `expectNoContent` instead. We craft the response
  // manually so `text` length is zero while the status remains 200
  // (jsonResponse only returns null bodies for 204/205/304).
  it('throws AuthClientError when a 2xx response has an empty body', async () => {
    const { authFetch } = makeAuthFetchMock(
      () => new Response('', { status: 200, headers: { 'Content-Type': 'application/json' } })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(client.refresh()).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 200,
      message: expect.stringContaining('was empty')
    })
  })

  // Covers the JSON.parse failure branch in `parseJsonOrThrow`. A
  // 2xx with a non-JSON body indicates an upstream proxy or
  // misconfigured server; the helper throws AuthClientError so
  // callers can detect and surface the protocol mismatch.
  it('throws AuthClientError when a 2xx response carries malformed JSON', async () => {
    const { authFetch } = makeAuthFetchMock(
      () =>
        new Response('{not valid json', {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(client.refresh()).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 200,
      message: expect.stringContaining('is not valid JSON')
    })
  })

  // Covers the non-ok branch of `expectNoContent`. logout() uses
  // expectNoContent; a 4xx must surface as AuthClientError carrying
  // the parsed body, exactly like the JSON-returning helpers.
  it('expectNoContent throws AuthClientError when the response is non-ok', async () => {
    const errorBody = {
      message: 'session expired',
      error: 'Unauthorized',
      statusCode: 401,
      code: 'auth.session_expired'
    }
    const { authFetch } = makeAuthFetchMock(() => jsonResponse(401, errorBody))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(client.logout()).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 401,
      code: 'auth.session_expired'
    })
  })

  // Covers the `text.length === 0` short-circuit in `extractErrorBody`.
  // A non-ok response with no body (some upstreams strip the body on
  // 5xx) must still throw AuthClientError, just without a parsed body.
  it('throws AuthClientError with undefined body when an error response has no body', async () => {
    const { authFetch } = makeAuthFetchMock(() => new Response('', { status: 503 }))
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(503)
      expect(caught.body).toBeUndefined()
    }
  })

  // Covers the non-object branch of `isAuthErrorBody`. A server (or
  // a misbehaving proxy) that returns a primitive JSON value as the
  // error body — `null`, a number, a string — must NOT crash the
  // type guard. The thrown error has no `body` payload in this case.
  it('treats a non-object JSON error body as no body', async () => {
    const { authFetch } = makeAuthFetchMock(
      () =>
        new Response('"just a string"', {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(500)
      expect(caught.body).toBeUndefined()
    }
  })

  // Covers the `null` early-return inside `isAuthErrorBody` —
  // `typeof null === 'object'` so the guard's first check would
  // otherwise pass. The branch protects against `JSON.parse('null')`
  // producing a value that fails property reads.
  it('treats a JSON null body as no body', async () => {
    const { authFetch } = makeAuthFetchMock(
      () =>
        new Response('null', {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    await expect(client.refresh()).rejects.toMatchObject({
      name: 'AuthClientError',
      status: 500,
      body: undefined
    })
  })

  // `isAuthErrorBody` requires `message` to be a STRING. An object
  // that has the right keys but a non-string `message` is NOT the
  // canonical envelope, so no parsed body must be attached and the
  // message falls back to the generic status text. Pins the `message`
  // typeof clause: a guard that always treats `message` as valid (or
  // collapses the conjunction) would wrongly surface this object as
  // the error body.
  it('rejects an error body whose message field is not a string', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      jsonResponse(400, { message: 123, error: 'Bad Request', statusCode: 400 })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.status).toBe(400)
      expect(caught.body).toBeUndefined()
      expect(caught.message).toMatch(/Request failed with status 400/)
    }
  })

  // `isAuthErrorBody` requires `error` to be a STRING. Pins the
  // `error` typeof clause independently of the other two so a mutant
  // that drops or loosens just this conjunct is caught.
  it('rejects an error body whose error field is not a string', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      jsonResponse(400, { message: 'bad', error: 42, statusCode: 400 })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.body).toBeUndefined()
    }
  })

  // `isAuthErrorBody` requires `statusCode` to be a NUMBER. Pins the
  // `statusCode` typeof clause independently so a mutant that drops or
  // loosens just this conjunct is caught.
  it('rejects an error body whose statusCode field is not a number', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      jsonResponse(400, { message: 'bad', error: 'Bad Request', statusCode: '400' })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.body).toBeUndefined()
    }
  })

  // A generic object that carries NONE of the canonical fields must
  // not be mistaken for an error envelope. Pins the conjunction as a
  // whole: a guard collapsed to `true` would attach this arbitrary
  // object as the parsed error body.
  it('rejects an arbitrary object that lacks the canonical error fields', async () => {
    const { authFetch } = makeAuthFetchMock(() =>
      jsonResponse(400, { foo: 'bar', nested: { a: 1 } })
    )
    const client = createAuthClient({ baseUrl: 'https://api.example.com', authFetch })

    let caught: unknown
    await client.refresh().catch((err: unknown) => {
      caught = err
    })

    expect(caught).toBeInstanceOf(AuthClientError)
    if (caught instanceof AuthClientError) {
      expect(caught.body).toBeUndefined()
    }
  })
})

// ---------------------------------------------------------------------------
// createAuthClient — internal authFetch fallback
// ---------------------------------------------------------------------------

describe('createAuthClient — built-in authFetch fallback', () => {
  // Captures the original global so we can restore it after the
  // suite. Required because these tests bypass makeAuthFetchMock and
  // exercise the createAuthFetch construction branch — that wrapper
  // calls the real `globalThis.fetch`.
  const originalFetch = globalThis.fetch
  afterAll(() => {
    globalThis.fetch = originalFetch
  })

  // Covers the `config.authFetch ?? createAuthFetch(...)` branch when
  // no custom authFetch is supplied. Every config knob is left at its
  // default to also exercise the `... !== undefined` ternaries (each
  // of which produces a no-op spread). The test asserts the
  // resulting wrapper actually issues a request — i.e. the internal
  // wrapper was constructed correctly.
  it('builds a default authFetch when none is supplied', async () => {
    const fetchSpy = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ user: {}, accessToken: '' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      })
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    const client = createAuthClient({ baseUrl: 'https://api.example.com' })
    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(fetchSpy.mock.calls[0]?.[0]).toBe('https://api.example.com/auth/login')
  })

  // Covers the truthy side of EVERY conditional spread inside the
  // createAuthFetch fallback (refreshEndpoint, credentials,
  // defaultHeaders, onSessionExpired, timeout). Setting all five
  // ensures none of those ternaries default to the empty-object
  // branch, exercising the alternate side and hardening the
  // configuration plumbing.
  it('forwards every optional config knob to the built-in authFetch', async () => {
    const fetchSpy = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ user: {}, accessToken: '' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      })
    )
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    const client = createAuthClient({
      baseUrl: 'https://api.example.com',
      refreshEndpoint: '/custom/refresh',
      credentials: 'same-origin',
      defaultHeaders: { 'X-Test': 'true' },
      onSessionExpired: () => {},
      timeout: 5000
    })

    await client.login({ email: 'a@b.c', password: '__test_only_pw__', tenantId: 't1' })

    const init = fetchSpy.mock.calls[0]?.[1] as RequestInit
    expect(init.credentials).toBe('same-origin')
    const headers = init.headers as Record<string, string>
    expect(headers['X-Test']).toBe('true')
    expect(headers['Content-Type']).toBe('application/json')
  })

  // The `refreshEndpoint` knob must actually reach the built-in
  // wrapper, not just be carried in the config object. We observe its
  // EFFECT: a 401 on a non-skip-listed endpoint (`/auth/me`) triggers
  // a refresh, and that refresh POST must hit the custom endpoint.
  // Pins the conditional spread for `refreshEndpoint`: a mutation that
  // drops it (false branch / empty object) falls back to the default
  // `/api/auth/client-refresh` and this assertion fails.
  it('forwards a custom refreshEndpoint into the built-in wrapper refresh call', async () => {
    const fetchSpy = jest
      .fn()
      .mockResolvedValueOnce(new Response('', { status: 401 })) // original /auth/me
      .mockResolvedValueOnce(new Response('', { status: 200 })) // refresh
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 'u1' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        })
      ) // retry
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    const client = createAuthClient({
      baseUrl: 'https://api.example.com',
      refreshEndpoint: '/custom/refresh'
    })

    await client.getMe()

    expect(fetchSpy.mock.calls[1]?.[0]).toBe('/custom/refresh')
    expect((fetchSpy.mock.calls[1]?.[1] as RequestInit).method).toBe('POST')
  })

  // The `onSessionExpired` knob must actually reach the built-in
  // wrapper. We observe its EFFECT: when a refresh fails, the wrapper
  // invokes the callback. Pins the conditional spread for
  // `onSessionExpired`: a mutation that drops it (false branch / empty
  // object) means the wrapper never receives the callback and it is
  // never called.
  it('forwards onSessionExpired into the built-in wrapper and invokes it on failed refresh', async () => {
    const fetchSpy = jest
      .fn()
      .mockResolvedValueOnce(new Response('', { status: 401 })) // original /auth/me
      .mockResolvedValueOnce(new Response('', { status: 401 })) // refresh fails
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    const onSessionExpired = jest.fn()
    const client = createAuthClient({
      baseUrl: 'https://api.example.com',
      onSessionExpired
    })

    await client.getMe().catch(() => undefined)

    expect(onSessionExpired).toHaveBeenCalledTimes(1)
  })

  // The `timeout` knob must actually reach the built-in wrapper. We
  // observe its EFFECT: with a small custom timeout and a fetch that
  // hangs until aborted, advancing fake timers past the configured
  // timeout aborts the request. Pins the conditional spread for
  // `timeout`: a mutation that drops it falls back to the 30s default,
  // so advancing 60ms would NOT abort and the request would hang.
  it('forwards a custom timeout into the built-in wrapper', async () => {
    const fetchSpy = jest.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'))
        })
      })
    })
    globalThis.fetch = fetchSpy as unknown as typeof fetch

    jest.useFakeTimers()
    try {
      const client = createAuthClient({ baseUrl: 'https://api.example.com', timeout: 50 })
      const promise = client.getMe()
      // Attach the rejection handler before advancing timers so the
      // abort rejection is observed and not flagged as unhandled.
      const assertion = expect(promise).rejects.toThrow('Aborted')

      jest.advanceTimersByTime(60)

      await assertion
    } finally {
      jest.useRealTimers()
    }
  })
})
