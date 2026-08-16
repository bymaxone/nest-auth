/**
 * Unit tests for `createAuthFetch` — the cookie- and refresh-aware
 * fetch wrapper used by the @bymax-one/nest-auth client subpath.
 *
 * Strategy: replace `globalThis.fetch` with a controllable jest mock,
 * exercise every branch (header merge variants, 401 + refresh + retry,
 * skip-list, single-flight dedup, timeout, abort), and assert on the
 * captured arguments. No real network calls, no test interdependence.
 *
 * The factory is created fresh per test so that the per-instance
 * dedup slot starts clean — this matches how a host application
 * would typically use it (one wrapper per app boot).
 */

import { createAuthFetch } from '../createAuthFetch'

// ---------------------------------------------------------------------------
// Test-only fetch mock helpers
// ---------------------------------------------------------------------------

// Captures the resolved init for the most recent call so individual
// tests can assert against it without juggling positional indices.
type FetchSpy = jest.SpiedFunction<typeof fetch>

/**
 * Replace `globalThis.fetch` with a fresh spy and return it. Tests
 * call this in `beforeEach` to keep state isolated.
 */
function installFetchSpy(): FetchSpy {
  const spy = jest.fn() as unknown as FetchSpy
  // Direct assignment — `globalThis.fetch` is writable in Node 18+.
  globalThis.fetch = spy as unknown as typeof fetch
  return spy
}

/**
 * Build a minimal `Response` from a status + optional JSON body. We
 * avoid the real `Response` constructor's stream semantics for speed
 * and to make `body?.cancel()` callable in `performRefresh`.
 */
function makeResponse(status: number, jsonBody?: unknown): Response {
  const body = jsonBody === undefined ? '' : JSON.stringify(jsonBody)
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'application/json' }
  })
}

/**
 * Create a manually-resolvable promise. Used by single-flight tests so
 * the test controls when the refresh "completes" and can fan out
 * multiple concurrent waiters in between.
 */
function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
} {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

/**
 * Read the merged headers off a captured fetch init. The wrapper
 * always emits `Record<string, string>` so we cast accordingly.
 */
function getHeaders(init: RequestInit | undefined): Record<string, string> {
  const headers = init?.headers
  if (headers === undefined) return {}
  return headers as Record<string, string>
}

// Capture the original `globalThis.fetch` so the `afterAll` hook can
// restore it. Jest's `restoreMocks: true` only resets `jest.spyOn`
// spies — it does not undo direct property assignment, which is the
// pattern used by `installFetchSpy` to remain framework-agnostic.
const originalFetch = globalThis.fetch
afterAll(() => {
  globalThis.fetch = originalFetch
})

// ---------------------------------------------------------------------------
// createAuthFetch — header and credentials defaults
// ---------------------------------------------------------------------------

describe('createAuthFetch — defaults', () => {
  let spy: FetchSpy

  beforeEach(() => {
    spy = installFetchSpy()
    spy.mockResolvedValue(makeResponse(200))
  })

  // A1: cookie-mode deployments depend on JSON Content-Type being
  // present by default — the server's class-validator pipes only run
  // when the request body is parsed as JSON.
  it('attaches Content-Type: application/json by default', async () => {
    const authFetch = createAuthFetch()
    await authFetch('/api/users')

    const init = spy.mock.calls[0]?.[1]
    expect(getHeaders(init)['Content-Type']).toBe('application/json')
  })

  // A2: HttpOnly auth cookies cannot be attached to cross-origin
  // requests unless `credentials: 'include'` is set — this is the
  // wrapper's main reason to exist.
  it('uses credentials: include by default', async () => {
    const authFetch = createAuthFetch()
    await authFetch('/api/users')

    const init = spy.mock.calls[0]?.[1]
    expect(init?.credentials).toBe('include')
  })

  // A19: a deployment that proxies refresh through a non-default
  // path must be able to redirect the wrapper without monkey-patching.
  it('honors a custom refreshEndpoint', async () => {
    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockResolvedValueOnce(makeResponse(200)) // refresh
    spy.mockResolvedValueOnce(makeResponse(200)) // retry

    const authFetch = createAuthFetch({ refreshEndpoint: '/custom/refresh' })
    await authFetch('/api/users')

    const refreshCall = spy.mock.calls[1]
    expect(refreshCall?.[0]).toBe('/custom/refresh')
    expect(refreshCall?.[1]?.method).toBe('POST')
  })
})

// ---------------------------------------------------------------------------
// createAuthFetch — header merging
// ---------------------------------------------------------------------------

describe('createAuthFetch — header merging', () => {
  let spy: FetchSpy

  beforeEach(() => {
    spy = installFetchSpy()
    spy.mockResolvedValue(makeResponse(200))
  })

  // A3: defaultHeaders extend (do not replace) the built-in defaults
  // so consumer-supplied tracing or correlation headers stick on
  // every request without having to reattach them.
  it('merges custom defaultHeaders with the built-in defaults', async () => {
    const authFetch = createAuthFetch({ defaultHeaders: { 'X-App': 'tests' } })
    await authFetch('/api/users')

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    expect(headers['Content-Type']).toBe('application/json')
    expect(headers['X-App']).toBe('tests')
  })

  // A4: per-request headers must win over defaults — required so
  // callers can opt out of `Content-Type: application/json` when
  // sending FormData or no body.
  it('lets per-request headers override factory defaults', async () => {
    const authFetch = createAuthFetch()
    await authFetch('/api/upload', { headers: { 'Content-Type': 'multipart/form-data' } })

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    expect(headers['Content-Type']).toBe('multipart/form-data')
  })

  // A5: array form `[[k, v], ...]` is one of the legal HeadersInit
  // shapes the spec accepts; the wrapper must walk it without
  // calling `.entries()`-only helpers that would crash on an array.
  it('merges headers passed as an array of tuples', async () => {
    const authFetch = createAuthFetch()
    await authFetch('/api/users', {
      headers: [
        ['X-Foo', 'bar'],
        ['X-Baz', 'qux']
      ]
    })

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    expect(headers['X-Foo']).toBe('bar')
    expect(headers['X-Baz']).toBe('qux')
  })

  // A6: callers in browser code typically build `Headers` instances —
  // the wrapper must iterate them with `.forEach`, not assume an
  // object literal.
  it('merges headers passed as a Headers instance', async () => {
    const authFetch = createAuthFetch()
    const headersInit = new Headers()
    headersInit.set('X-Custom', 'value')
    await authFetch('/api/users', { headers: headersInit })

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    // Headers normalises keys to lowercase — assert against the
    // lowercase form so the test does not depend on insertion case.
    expect(headers['x-custom']).toBe('value')
  })

  // A7: prototype-pollution guard. An attacker-controlled HeadersInit
  // must NOT be able to write `__proto__` / `constructor` / `prototype`
  // onto the merged object — those keys are silently dropped.
  it('rejects __proto__, constructor, and prototype keys in headers', async () => {
    const authFetch = createAuthFetch()
    await authFetch('/api/users', {
      headers: {
        __proto__: 'evil',
        constructor: 'evil',
        prototype: 'evil',
        'X-Safe': 'ok'
      } as unknown as Record<string, string>
    })

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    // Use hasOwn so we ignore the always-present `__proto__`,
    // `constructor`, and `prototype` *prototype* properties; the
    // guard only needs to keep them off as own keys of the merged
    // record.
    expect(Object.prototype.hasOwnProperty.call(headers, '__proto__')).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(headers, 'constructor')).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(headers, 'prototype')).toBe(false)
    expect(headers['X-Safe']).toBe('ok')
  })

  // Covers the prototype-pollution guard inside the array branch of
  // mergeHeaders. The Object.entries branch is verified above; this
  // one ensures the same protection holds when callers pass headers
  // as `[[k, v], ...]` tuples.
  it('rejects unsafe keys passed as array tuples', async () => {
    const authFetch = createAuthFetch()
    await authFetch('/api/users', {
      headers: [
        ['__proto__', 'evil'],
        ['constructor', 'evil'],
        ['X-Safe', 'ok']
      ]
    })

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    expect(Object.prototype.hasOwnProperty.call(headers, '__proto__')).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(headers, 'constructor')).toBe(false)
    expect(headers['X-Safe']).toBe('ok')
  })

  // The `__proto__` clause of the unsafe-name guard specifically
  // blocks prototype pollution. The array branch assigns values with
  // no type check, so a malicious `['__proto__', <object>]` tuple
  // would re-parent the merged headers object if `__proto__` were not
  // rejected. Pins the `__proto__` literal/clause: a guard that no
  // longer recognises `__proto__` lets the assignment run and mutates
  // the merged object's prototype. EDGE: object-valued header.
  it('does not let an object-valued __proto__ tuple pollute the merged headers prototype', async () => {
    const authFetch = createAuthFetch()
    await authFetch('/api/users', {
      headers: [
        ['__proto__', { injected: 'polluted' } as unknown as string],
        ['X-Safe', 'ok']
      ]
    })

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    expect(Object.getPrototypeOf(headers)).toBe(Object.prototype)
    expect((headers as Record<string, unknown>)['injected']).toBeUndefined()
    expect(headers['X-Safe']).toBe('ok')
  })

  // Covers the prototype-pollution guard inside the `Headers`
  // instance branch of mergeHeaders. The platform `Headers` class
  // lowercases the names; this also exercises the `return` early
  // exit on unsafe names inside the forEach callback.
  it('rejects unsafe keys passed via a Headers instance', async () => {
    const authFetch = createAuthFetch()
    const headersInit = new Headers()
    headersInit.set('__proto__', 'evil')
    headersInit.set('constructor', 'evil')
    headersInit.set('X-Safe', 'ok')
    await authFetch('/api/users', { headers: headersInit })

    const headers = getHeaders(spy.mock.calls[0]?.[1])
    expect(Object.prototype.hasOwnProperty.call(headers, '__proto__')).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(headers, 'constructor')).toBe(false)
    expect(headers['x-safe']).toBe('ok')
  })
})

// ---------------------------------------------------------------------------
// createAuthFetch — 401 + refresh interception
// ---------------------------------------------------------------------------

describe('createAuthFetch — refresh on 401', () => {
  let spy: FetchSpy

  beforeEach(() => {
    spy = installFetchSpy()
  })

  // A8: a 200 response must short-circuit the entire refresh path.
  // The mock proves it by counting calls — only the original request.
  it('passes non-401 responses straight through without a refresh', async () => {
    spy.mockResolvedValue(makeResponse(200))
    const authFetch = createAuthFetch()

    const res = await authFetch('/api/users')

    expect(res.status).toBe(200)
    expect(spy).toHaveBeenCalledTimes(1)
  })

  // A9: the canonical refresh-and-retry happy path. First call gets
  // 401, refresh succeeds with 200, retry returns 200 → caller sees 200.
  it('refreshes and retries on a 401 from a regular endpoint', async () => {
    spy.mockResolvedValueOnce(makeResponse(401)) // original
    spy.mockResolvedValueOnce(makeResponse(200)) // refresh
    spy.mockResolvedValueOnce(makeResponse(200, { ok: true })) // retry

    const authFetch = createAuthFetch()
    const res = await authFetch('/api/users')

    expect(res.status).toBe(200)
    expect(spy).toHaveBeenCalledTimes(3)
    expect(spy.mock.calls[1]?.[0]).toBe('/api/auth/client-refresh')
  })

  // Verifies the refresh completes when the refresh response's drain never settles.
  //
  // This is the path the PR is about and the one the client-side test does NOT reach: the drain in
  // `performRefresh` is a second call site, and the `createAuthClient` test only exercises
  // `expectNoContent`. Restoring the `await` there leaves this red and that one green, which is
  // why both exist.
  //
  // `/auth/refresh` answers 200 **with a body** — the rotated `{accessToken, refreshToken}` or the
  // `{user}` shape depending on delivery mode — so the drain runs on every successful rotation,
  // not on an error edge. Under request interception (MSW, undici in jsdom) `body.cancel()` never
  // settles, so awaiting it hung the refresh and, with it, every request waiting on the
  // single-flight slot. With the `await` restored this times out rather than failing an
  // assertion, which is exactly how the defect presented to the consumer who found it.
  it('completes the refresh when the refresh response drain never settles', async () => {
    const refreshResponse = makeResponse(200, { accessToken: 'rotated' })
    Object.defineProperty(refreshResponse, 'body', {
      value: { cancel: () => new Promise<void>(() => undefined) }
    })

    spy.mockResolvedValueOnce(makeResponse(401)) // original
    spy.mockResolvedValueOnce(refreshResponse) // refresh — its drain never settles
    spy.mockResolvedValueOnce(makeResponse(200, { ok: true })) // retry

    const authFetch = createAuthFetch()
    const res = await authFetch('/api/users')

    expect(res.status).toBe(200)
    expect(spy).toHaveBeenCalledTimes(3)
  })

  // A10: when the 401 comes from an auth-issuing endpoint (e.g.
  // /auth/login with bad credentials), refreshing would mask the
  // real error and infinite-loop. The skip-list prevents this.
  it('does NOT refresh on a 401 from a skip-listed endpoint', async () => {
    spy.mockResolvedValueOnce(makeResponse(401))

    const authFetch = createAuthFetch()
    const res = await authFetch('/auth/login')

    expect(res.status).toBe(401)
    expect(spy).toHaveBeenCalledTimes(1) // no refresh attempt
  })

  // The skip-list matches on the END of the pathname (`endsWith`),
  // not the start — so a layered deployment that mounts the auth
  // controllers under a longer prefix (`/api/v1/auth/login`) is still
  // recognised as auth-issuing and must NOT trigger a refresh. Pins
  // the suffix-match direction so a `startsWith` mutation (which would
  // fail to match the trailing `/auth/login` and wrongly refresh) is
  // caught. EDGE: prefix where the suffix is not also a prefix.
  it('does NOT refresh on a 401 from a layered path whose suffix is skip-listed', async () => {
    spy.mockResolvedValueOnce(makeResponse(401))

    const authFetch = createAuthFetch()
    const res = await authFetch('/api/v1/auth/login')

    expect(res.status).toBe(401)
    expect(spy).toHaveBeenCalledTimes(1) // no refresh attempt
  })

  // The refresh POST must carry `Content-Type: application/json` so
  // the upstream NestJS pipeline parses the (empty) body and the
  // server-side validators run. Pins both the header name/value and
  // its presence so emptying the headers object or blanking the value
  // is caught.
  it('sends Content-Type: application/json on the refresh request', async () => {
    spy.mockResolvedValueOnce(makeResponse(401)) // original
    spy.mockResolvedValueOnce(makeResponse(200)) // refresh
    spy.mockResolvedValueOnce(makeResponse(200)) // retry

    const authFetch = createAuthFetch()
    await authFetch('/api/users')

    const refreshHeaders = getHeaders(spy.mock.calls[1]?.[1])
    expect(refreshHeaders['Content-Type']).toBe('application/json')
  })

  // A11: when the refresh fails the wrapper still returns the
  // ORIGINAL 401 to the caller (no exception) and notifies the host
  // app via `onSessionExpired` so it can route to a sign-in screen.
  it('invokes onSessionExpired and returns the original 401 when refresh fails', async () => {
    spy.mockResolvedValueOnce(makeResponse(401)) // original
    spy.mockResolvedValueOnce(makeResponse(401)) // refresh failed

    const onSessionExpired = jest.fn()
    const authFetch = createAuthFetch({ onSessionExpired })
    const res = await authFetch('/api/users')

    expect(res.status).toBe(401)
    expect(onSessionExpired).toHaveBeenCalledTimes(1)
    // Only original + refresh, no retry.
    expect(spy).toHaveBeenCalledTimes(2)
  })

  // A12: a buggy onSessionExpired callback must not turn a recoverable
  // 401 into an unhandled rejection — the contract says the wrapper
  // always returns the 401 Response when refresh fails.
  it('swallows errors from onSessionExpired and still returns the 401', async () => {
    // The wrapper logs a `console.warn` when the callback throws
    // (see `createAuthFetch.ts`). Silence it here so the test output
    // stays clean — the assertion below verifies the 401 is still
    // returned, which is the real contract.
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      spy.mockResolvedValueOnce(makeResponse(401))
      spy.mockResolvedValueOnce(makeResponse(401))

      const onSessionExpired = jest.fn(() => {
        throw new Error('boom')
      })
      const authFetch = createAuthFetch({ onSessionExpired })

      const res = await authFetch('/api/users')
      expect(res.status).toBe(401)
      expect(onSessionExpired).toHaveBeenCalledTimes(1)
      // Swallowed, but not silently: the warning is the only trace a consumer has that their
      // callback is broken, and the error it carries is the only way to find out how.
      expect(warnSpy).toHaveBeenCalledWith(
        '[nest-auth] onSessionExpired callback threw:',
        expect.objectContaining({ message: 'boom' })
      )
    } finally {
      warnSpy.mockRestore()
    }
  })
})

// ---------------------------------------------------------------------------
// createAuthFetch — single-flight refresh dedup
// ---------------------------------------------------------------------------

describe('createAuthFetch — a 401 that is not an expiry', () => {
  let spy: FetchSpy

  beforeEach(() => {
    spy = installFetchSpy()
  })

  // The defect this exists for, measured by a consumer against a live instance: a wrong
  // `currentPassword` on `POST {prefix}/password/change` answers 401, the client read that as an
  // expiry and refreshed, and ten typos inside a minute exhausted the refresh limiter. The client
  // then read the 429 as an irrecoverable expiry and called `onSessionExpired` — discarding a
  // session the server still honoured (`GET {prefix}/me` answered 200 throughout).
  //
  // The path could not fix it: that route is behind the JWT guard, so an expired token 401s there
  // too. Only the code separates them.
  it('does not refresh when the 401 names a credential failure', async () => {
    spy.mockResolvedValue(
      makeResponse(401, { error: { code: 'auth.invalid_credentials', message: 'Invalid' } })
    )
    const onSessionExpired = jest.fn()
    const authFetch = createAuthFetch({ onSessionExpired })

    const res = await authFetch('/auth/password/change')

    expect(res.status).toBe(401)
    // One call: the original. No refresh, no retry.
    expect(spy).toHaveBeenCalledTimes(1)
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // The other half of the same pair, on the SAME kind of route. Without it, the case above is
  // also satisfied by a client that stopped refreshing on 401 altogether.
  it('still refreshes when the 401 names an unusable token', async () => {
    spy.mockResolvedValueOnce(makeResponse(401, { error: { code: 'auth.token_invalid' } }))
    spy.mockResolvedValueOnce(makeResponse(200))
    spy.mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const res = await createAuthFetch()('/auth/password/change')

    expect(res.status).toBe(200)
    expect(spy).toHaveBeenCalledTimes(3)
  })

  // A derived backend on `@bymax-one/nest-core` answers the flat envelope, so the code sits at
  // the top level rather than under `error`. The client cannot tell which backend it is talking
  // to, so it reads both — and a consumer whose backend composes the two libraries would
  // otherwise get the pre-fix behaviour with no way to notice.
  it('reads the code from the flat envelope a nest-core backend answers', async () => {
    spy.mockResolvedValue(
      makeResponse(401, {
        statusCode: 401,
        code: 'auth.mfa_invalid_code',
        path: '/auth/mfa/disable'
      })
    )

    const res = await createAuthFetch()('/auth/mfa/disable')

    expect(res.status).toBe(401)
    expect(spy).toHaveBeenCalledTimes(1)
  })

  // Compatibility, and the reason the narrowing is safe to ship: this wrapper is a general fetch,
  // and an application's own API answering a bare 401 must behave exactly as it did before. Every
  // shape that carries no readable code still refreshes.
  it.each([
    ['an empty body', undefined],
    ['a JSON body that is not an object', 'nope'],
    ['a null body', null],
    ['an envelope whose code is not a string', { error: { code: 42 } }],
    ['an object with no code at all', { message: 'Unauthorized' }]
  ])('still refreshes on a 401 carrying %s', async (_why, body) => {
    spy.mockResolvedValueOnce(makeResponse(401, body))
    spy.mockResolvedValueOnce(makeResponse(200))
    spy.mockResolvedValueOnce(makeResponse(200, { ok: true }))

    const res = await createAuthFetch()('/api/users')

    expect(res.status).toBe(200)
    expect(spy).toHaveBeenCalledTimes(3)
  })

  // The bound. A 401 whose body never terminates must not hang the wrapper: the request has
  // already completed and its timeout has already been cleared, so without a bound here the
  // caller waits forever — and a deployment that disables `timeout` for long-polling would have
  // no protection at all. On expiry the classification gives up and the pre-existing behaviour
  // applies, which is the safe direction: this step may narrow what refreshes, never suspend it.
  it('gives up on a body that never arrives and refreshes as before', async () => {
    jest.useFakeTimers()

    try {
      // A body that never closes: `json()` on it never settles.
      const hanging = new Response(
        new ReadableStream({
          start() {
            /* deliberately never enqueues and never closes */
          }
        }),
        { status: 401, headers: { 'Content-Type': 'application/json' } }
      )

      spy.mockResolvedValueOnce(hanging)
      spy.mockResolvedValueOnce(makeResponse(200))
      spy.mockResolvedValueOnce(makeResponse(200, { ok: true }))

      const pending = createAuthFetch()('/api/users')

      await jest.advanceTimersByTimeAsync(2_000)

      const res = await pending

      expect(res.status).toBe(200)
      expect(spy).toHaveBeenCalledTimes(3)
    } finally {
      jest.useRealTimers()
    }
  })

  // A platform route, which is the case the code check must NOT be allowed to answer. Every
  // protected platform endpoint is JWT-PLATFORM-guarded, so an expired platform token answers
  // `auth.token_invalid` — the very code that means "refresh me" on the dashboard plane. A
  // dashboard refresh cannot fix another plane's credential: it spends the budget and can call
  // `onSessionExpired` for a session that is perfectly healthy.
  //
  // `platform/mfa/setup` specifically, because it was one of the five protected platform routes
  // the first draft of the skip list left out while claiming the list covered the plane.
  it('does not refresh on a platform route, even for auth.token_invalid', async () => {
    spy.mockResolvedValue(makeResponse(401, { error: { code: 'auth.token_invalid' } }))
    const onSessionExpired = jest.fn()

    const res = await createAuthFetch({ onSessionExpired })('/auth/platform/mfa/setup')

    expect(res.status).toBe(401)
    expect(spy).toHaveBeenCalledTimes(1)
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // Verifies the check does not consume the response the caller receives. It reads a CLONE, and
  // if it read the original instead every consumer parsing the error body would get
  // `TypeError: body already used` — trading one defect for a worse one, on the path that
  // reports failures.
  it('leaves the response body readable by the caller', async () => {
    spy.mockResolvedValue(
      makeResponse(401, { error: { code: 'auth.invalid_credentials', message: 'Invalid' } })
    )

    const res = await createAuthFetch()('/auth/password/change')
    const body = (await res.json()) as { error: { message: string } }

    expect(body.error.message).toBe('Invalid')
  })
})

describe('createAuthFetch — single-flight refresh dedup', () => {
  let spy: FetchSpy

  beforeEach(() => {
    spy = installFetchSpy()
  })

  // A13: the core single-flight contract — five concurrent 401s must
  // produce exactly ONE refresh round-trip, then five retries.
  // We hold the refresh open with a deferred so all five callers
  // queue against the same promise before resolution.
  it('coalesces 5 concurrent 401s into a single refresh round-trip', async () => {
    const refreshDeferred = deferred<Response>()
    let refreshSettled = false
    void refreshDeferred.promise.then(() => {
      refreshSettled = true
    })

    // Coordination: each original 401 invocation flips its slot in
    // this array. The driver awaits until all 5 are flipped before
    // resolving the refresh, removing the dependence on a fixed
    // number of microtask ticks (which would be implementation-
    // dependent and flaky).
    const originalCalls: number[] = []

    spy.mockImplementation(((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.endsWith('/api/auth/client-refresh')) {
        return refreshDeferred.promise
      }
      if (!refreshSettled) {
        originalCalls.push(originalCalls.length + 1)
        return Promise.resolve(makeResponse(401))
      }
      return Promise.resolve(makeResponse(200, { retried: true }))
    }) as unknown as typeof fetch)

    const authFetch = createAuthFetch()

    // Fire 5 concurrent requests against the regular endpoint.
    const inflight = Promise.all([
      authFetch('/api/users'),
      authFetch('/api/users'),
      authFetch('/api/users'),
      authFetch('/api/users'),
      authFetch('/api/users')
    ])

    // Wait until all 5 originals have hit the mock (and therefore
    // queued their await on the shared refresh promise) before
    // resolving the refresh. Polling on `setImmediate` is robust
    // against any implementation-internal microtask depth.
    while (originalCalls.length < 5) {
      await new Promise((resolve) => setImmediate(resolve))
    }

    refreshDeferred.resolve(makeResponse(200))
    const responses = await inflight

    expect(responses.every((r) => r.status === 200)).toBe(true)

    const refreshCalls = spy.mock.calls.filter(([input]) =>
      typeof input === 'string'
        ? input.endsWith('/api/auth/client-refresh')
        : input.toString().endsWith('/api/auth/client-refresh')
    )
    expect(refreshCalls.length).toBe(1)
  })

  // A14: after the refresh promise settles, the dedup slot resets so
  // a future 401 (next user action) starts a new refresh — without
  // this, the second refresh would silently no-op.
  it('resets the dedup slot after refresh completes so future 401s start a new refresh', async () => {
    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockResolvedValueOnce(makeResponse(200)) // refresh #1
    spy.mockResolvedValueOnce(makeResponse(200)) // retry #1

    const authFetch = createAuthFetch()
    const r1 = await authFetch('/api/users')
    expect(r1.status).toBe(200)

    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockResolvedValueOnce(makeResponse(200)) // refresh #2
    spy.mockResolvedValueOnce(makeResponse(200)) // retry #2

    const r2 = await authFetch('/api/users')
    expect(r2.status).toBe(200)

    const refreshCalls = spy.mock.calls.filter(
      ([input]) => typeof input === 'string' && input.endsWith('/api/auth/client-refresh')
    )
    expect(refreshCalls.length).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// createAuthFetch — URL composition
// ---------------------------------------------------------------------------

describe('createAuthFetch — URL composition', () => {
  let spy: FetchSpy

  beforeEach(() => {
    spy = installFetchSpy()
    spy.mockResolvedValue(makeResponse(200))
  })

  // A15: when baseUrl is configured, relative paths from the consumer
  // are concatenated with it before being passed to fetch — the
  // typical SaaS dashboard / API server setup.
  it('prepends baseUrl to relative request URLs', async () => {
    const authFetch = createAuthFetch({ baseUrl: 'https://api.example.com' })
    await authFetch('/api/users')

    expect(spy.mock.calls[0]?.[0]).toBe('https://api.example.com/api/users')
  })

  // A16: an absolute URL given by the caller must reach fetch
  // unchanged — important so callers can target third-party
  // endpoints without disabling the wrapper.
  it('passes absolute http(s) URLs through without prepending baseUrl', async () => {
    const authFetch = createAuthFetch({ baseUrl: 'https://api.example.com' })
    await authFetch('https://other.example.com/v2')

    expect(spy.mock.calls[0]?.[0]).toBe('https://other.example.com/v2')
  })

  // The absolute-URL detector matches BOTH `http://` and `https://`
  // (the `s?` quantifier). A plain `http://` absolute URL must pass
  // through untouched — pins the optional `s` so a regex that drops
  // it (`/^https:\/\//`) and wrongly prepends baseUrl is caught.
  it('passes an absolute http:// (non-TLS) URL through without prepending baseUrl', async () => {
    const authFetch = createAuthFetch({ baseUrl: 'https://api.example.com' })
    await authFetch('http://other.example.com/v2')

    expect(spy.mock.calls[0]?.[0]).toBe('http://other.example.com/v2')
  })

  // The absolute-URL detector is ANCHORED at the start (`^`) — only a
  // URL that BEGINS with a scheme is "absolute". A relative path that
  // merely embeds `http://` inside a query string must still get the
  // baseUrl prepended; pins the `^` anchor so an unanchored regex
  // (which would treat the embedded scheme as absolute and skip the
  // prepend) is caught.
  it('prepends baseUrl to a relative URL that embeds http:// in a query parameter', async () => {
    const authFetch = createAuthFetch({ baseUrl: 'https://api.example.com' })
    await authFetch('/redirect?next=http://evil.example.com')

    expect(spy.mock.calls[0]?.[0]).toBe(
      'https://api.example.com/redirect?next=http://evil.example.com'
    )
  })

  // The fetch target keeps a non-string input (here a `URL`) as the
  // ORIGINAL object only when it is NOT a relative string — the guard
  // is `baseUrl !== undefined && typeof input === 'string'`. With a
  // baseUrl set AND a URL instance, the wrapper must still forward the
  // URL object (not a stringified copy). Pins the `&&`/`typeof` arm so
  // mutations to `||` or `&& true` (which would stringify the input)
  // are caught.
  it('forwards a URL instance unchanged even when a baseUrl is configured', async () => {
    const authFetch = createAuthFetch({ baseUrl: 'https://api.example.com' })
    await authFetch(new URL('https://api.example.com/api/users'))

    expect(spy.mock.calls[0]?.[0]).toBeInstanceOf(URL)
  })
})

// ---------------------------------------------------------------------------
// createAuthFetch — input shape variants
// ---------------------------------------------------------------------------

describe('createAuthFetch — request input shapes', () => {
  let spy: FetchSpy

  beforeEach(() => {
    spy = installFetchSpy()
    spy.mockResolvedValue(makeResponse(200))
  })

  // Covers the `URL` instance branch in `resolveRequestUrl` —
  // browser code commonly constructs URLs with `new URL(...)` rather
  // than passing strings, so the wrapper must honor that shape too.
  it('accepts a URL instance as the request input', async () => {
    const authFetch = createAuthFetch()
    await authFetch(new URL('https://api.example.com/api/users'))

    expect(spy.mock.calls[0]?.[0]).toBeInstanceOf(URL)
  })

  // Covers the `Request` object branch in `resolveRequestUrl`. The
  // skip-list logic still needs to read the URL out of the Request,
  // which goes through the `.url` property accessor.
  it('accepts a pre-built Request as the request input', async () => {
    const authFetch = createAuthFetch()
    const req = new Request('https://api.example.com/api/users')
    await authFetch(req)

    const sent = spy.mock.calls[0]?.[0]
    expect(sent).toBeInstanceOf(Request)
  })
})

// ---------------------------------------------------------------------------
// createAuthFetch — refresh failure paths
// ---------------------------------------------------------------------------

describe('createAuthFetch — refresh failure paths', () => {
  // The `catch` branch in `performRefresh`: the network rejected the refresh entirely — offline,
  // DNS, CORS, an aborted request. The caller still gets its 401, and the wrapper must not crash.
  //
  // It must ALSO not report the session as expired, and that is the assertion that changed. A
  // dropped connection says nothing about the credential; ending the session on it logs a user
  // out for a lost wifi signal and makes the next attempt, which would have worked, impossible.
  it('does not end the session when the refresh never reached the server', async () => {
    const spy = installFetchSpy()
    spy.mockResolvedValueOnce(makeResponse(401)) // original
    spy.mockRejectedValueOnce(new TypeError('network failure')) // refresh throws

    const onSessionExpired = jest.fn()
    const authFetch = createAuthFetch({ onSessionExpired })
    const res = await authFetch('/api/users')

    expect(res.status).toBe(401)
    expect(onSessionExpired).not.toHaveBeenCalled()
    expect(spy).toHaveBeenCalledTimes(2)
  })

  // The measured defect, as a test. A rate limiter answers `429`; the boolean this replaced made
  // that identical to `401`, so the wrapper signed the user out of a session whose credential was
  // still valid — and did it precisely when retrying would have worked.
  //
  // 5xx and a 404 from a mistyped `routePrefix` are the same shape: the server answered, and what
  // it answered says nothing about the credential.
  it.each([
    ['rate limited', 429],
    ['a server fault', 503],
    ['a misrouted refresh endpoint', 404]
  ])('does not end the session on %s', async (_why, status) => {
    const spy = installFetchSpy()
    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockResolvedValueOnce(makeResponse(status))

    const onSessionExpired = jest.fn()
    const authFetch = createAuthFetch({ onSessionExpired })
    const res = await authFetch('/api/users')

    expect(res.status).toBe(401)
    expect(onSessionExpired).not.toHaveBeenCalled()
    // Not retried either: the request failed and stays failed. What the caller no longer receives
    // is a claim that the session is over.
    expect(spy).toHaveBeenCalledTimes(2)
  })

  // The reason reaches the consumer, which is what makes it an answer rather than an internal
  // detail. Each of the three arrives with the status behind it, and `unreachable` with `null`
  // because there was no answer to take one from.
  it.each([
    ['a rate limit', 429, 'unavailable', 429],
    ['a refused credential', 401, 'rejected', 401],
    ['an origin guard', 403, 'unavailable', 403]
  ])('reports %s to onRefreshFailed', async (_why, status, reason, reported) => {
    const spy = installFetchSpy()
    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockResolvedValueOnce(makeResponse(status))

    const onRefreshFailed = jest.fn()
    const authFetch = createAuthFetch({ onRefreshFailed })
    await authFetch('/api/users')

    expect(onRefreshFailed).toHaveBeenCalledWith({ ok: false, reason, status: reported })
  })

  // No answer at all carries no status, and `null` says that rather than a made-up zero.
  it('reports a thrown refresh as unreachable with no status', async () => {
    const spy = installFetchSpy()
    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockRejectedValueOnce(new TypeError('offline'))

    const onRefreshFailed = jest.fn()
    const authFetch = createAuthFetch({ onRefreshFailed })
    await authFetch('/api/users')

    expect(onRefreshFailed).toHaveBeenCalledWith({
      ok: false,
      reason: 'unreachable',
      status: null
    })
  })

  // A broken consumer callback must not mask the response the caller is waiting for — the same
  // contract `onSessionExpired` already had, and worth pinning on the new one before someone
  // assumes it throws through.
  it('swallows a throwing onRefreshFailed and still returns the response', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined)
    const spy = installFetchSpy()
    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockResolvedValueOnce(makeResponse(429))

    const authFetch = createAuthFetch({
      onRefreshFailed: () => {
        throw new Error('consumer bug')
      }
    })
    const res = await authFetch('/api/users')

    expect(res.status).toBe(401)
    expect(warn).toHaveBeenCalledWith(
      '[nest-auth] onRefreshFailed callback threw:',
      expect.any(Error)
    )
    warn.mockRestore()
  })

  // 403 is NOT expiry, and the reason is specific rather than cautious: `TrustedOriginGuard` sits
  // on the whole `AuthController`, `/refresh` included, and answers `auth.untrusted_origin` with
  // 403. Classifying that as a refused credential would sign out every user of a deployment whose
  // `trustedOrigins` is wrong — the same defect this whole change removes, one status over.
  it('does not end the session on a 403 from an origin guard', async () => {
    const spy = installFetchSpy()
    spy.mockResolvedValueOnce(makeResponse(401))
    spy.mockResolvedValueOnce(makeResponse(403))

    const onSessionExpired = jest.fn()
    const authFetch = createAuthFetch({ onSessionExpired })
    const res = await authFetch('/api/users')

    expect(res.status).toBe(401)
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // The other half, and the one that keeps the change from being a blanket "never sign out". A
  // 401 from the refresh route is the server saying it looked at the credential and refused it.
  it.each([['the credential was refused', 401]])(
    'ends the session when %s',
    async (_why, status) => {
      const spy = installFetchSpy()
      spy.mockResolvedValueOnce(makeResponse(401))
      spy.mockResolvedValueOnce(makeResponse(status))

      const onSessionExpired = jest.fn()
      const authFetch = createAuthFetch({ onSessionExpired })
      const res = await authFetch('/api/users')

      expect(res.status).toBe(401)
      expect(onSessionExpired).toHaveBeenCalledTimes(1)
    }
  )
})

// ---------------------------------------------------------------------------
// createAuthFetch — timeout and abort
// ---------------------------------------------------------------------------

describe('createAuthFetch — timeout and abort', () => {
  // A17: the configured timeout must abort the underlying fetch via
  // AbortController, surfacing the abort to the caller. We capture
  // the signal that fetch received and trip it manually so the
  // assertion does not depend on real timing.
  it('aborts the request when the timeout elapses', async () => {
    const spy = installFetchSpy()
    spy.mockImplementation((_input, init) => {
      return new Promise((_resolve, reject) => {
        const signal = init?.signal
        if (signal === undefined || signal === null) {
          reject(new Error('signal missing'))
          return
        }
        signal.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'))
        })
      })
    })

    jest.useFakeTimers()
    const authFetch = createAuthFetch({ timeout: 50 })
    const promise = authFetch('/api/slow')

    jest.advanceTimersByTime(60)

    await expect(promise).rejects.toThrow('Aborted')
    jest.useRealTimers()
  })

  // A18: the user-supplied AbortSignal composes with the timeout —
  // an external abort cancels the request before any refresh logic
  // gets a chance to interpret the result.
  it('respects a user-supplied AbortSignal that aborts before the timeout', async () => {
    const spy = installFetchSpy()
    spy.mockImplementation((_input, init) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'))
        })
      })
    })

    const controller = new AbortController()
    const authFetch = createAuthFetch({ timeout: 5000 })
    const promise = authFetch('/api/slow', { signal: controller.signal })

    controller.abort()

    await expect(promise).rejects.toThrow('Aborted')
  })

  // Covers the `timeout: 0` short-circuit branch in `attachTimeout`.
  // A consumer that opts out of the timeout (long-poll / SSE) must
  // see the request go through with NO controller wrapping the
  // signal — verified indirectly via the request resolving normally.
  it('skips timeout wiring entirely when timeout is set to 0', async () => {
    const spy = installFetchSpy()
    spy.mockResolvedValue(makeResponse(200))

    const authFetch = createAuthFetch({ timeout: 0 })
    const res = await authFetch('/api/long-poll')

    expect(res.status).toBe(200)
    // The init forwarded to fetch has no signal because no
    // AbortController is created in the disabled-timeout branch.
    expect(spy.mock.calls[0]?.[1]?.signal).toBeUndefined()
  })

  // Covers the `userSignal.aborted === true` branch in
  // `attachTimeout`: an already-aborted signal must abort the
  // composed controller immediately so fetch never starts.
  it('aborts immediately when the user signal is already aborted on entry', async () => {
    const spy = installFetchSpy()
    spy.mockImplementation((_input, init) => {
      return new Promise((_resolve, reject) => {
        const signal = init?.signal
        if (signal?.aborted === true) {
          reject(new DOMException('Aborted', 'AbortError'))
          return
        }
        signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'))
        })
      })
    })

    const controller = new AbortController()
    controller.abort() // pre-abort BEFORE the call

    const authFetch = createAuthFetch({ timeout: 5000 })
    await expect(authFetch('/api/slow', { signal: controller.signal })).rejects.toThrow('Aborted')
  })

  // After a request resolves, the timeout timer must be cleared so it
  // never fires against a settled request (and so the process can exit
  // cleanly). With fake timers, a successful fetch must leave ZERO
  // pending timers — pins the `clearTimeout(timer)` cleanup and the
  // `finally { firstAttempt.cleanup() }` call: dropping either leaks
  // the timer and the count stays at 1.
  it('clears the timeout timer after a successful request', async () => {
    const spy = installFetchSpy()
    spy.mockResolvedValue(makeResponse(200))

    jest.useFakeTimers()
    try {
      const authFetch = createAuthFetch({ timeout: 30_000 })
      await authFetch('/api/users')

      expect(jest.getTimerCount()).toBe(0)
    } finally {
      jest.useRealTimers()
    }
  })

  // The retry leg has its own timeout that must also be cleared once
  // the retry resolves. After a full 401 → refresh → retry flow, no
  // timers may remain pending — pins the `finally { retryAttempt.cleanup() }`
  // call on the retry path (the refresh fetch itself attaches no
  // timeout, so only the original + retry create timers).
  it('clears the retry timeout timer after a refresh-and-retry flow', async () => {
    const spy = installFetchSpy()
    spy.mockResolvedValueOnce(makeResponse(401)) // original
    spy.mockResolvedValueOnce(makeResponse(200)) // refresh
    spy.mockResolvedValueOnce(makeResponse(200)) // retry

    jest.useFakeTimers()
    try {
      const authFetch = createAuthFetch({ timeout: 30_000 })
      await authFetch('/api/users')

      expect(jest.getTimerCount()).toBe(0)
    } finally {
      jest.useRealTimers()
    }
  })
})
