/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * Unit tests for {@link AuthProvider} — the React component that owns
 * the auth-session state machine and bridges the typed AuthClient into
 * a React context tree.
 *
 * Test strategy
 * -------------
 * - The AuthClient is fully mocked via {@link createMockClient}. No
 *   real network, no real timers beyond jest's fake-timer mode.
 * - Assertions target the context value as observed by a consumer
 *   via `useContext(AuthContext)`, rather than reaching into provider
 *   internals. This keeps the suite anchored on the public contract
 *   and immune to reducer/ref refactors that preserve behavior.
 * - Async provider work (initial mount probe, login handler) is
 *   driven through `act()` so React batching and effect flushing
 *   stay deterministic.
 * - Timer-based behavior (the revalidation interval) uses
 *   `jest.useFakeTimers()` inside the relevant describe block so
 *   effect-timer intrusion into other tests is impossible.
 */

import { act, render, renderHook } from '@testing-library/react'
import { useContext, type ReactNode } from 'react'

import { AuthClientError, type LoginResult } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { AuthContext, type AuthContextValue } from '../context'

import {
  createMockClient,
  MOCK_AUTH_RESULT,
  MOCK_MFA_RESULT,
  MOCK_USER,
  type MockAuthClient
} from './_testHelpers'

// Helper: wrap `renderHook(useContext(AuthContext))` in a provider so
// each test reads the live context value via a predictable hook. The
// wrapper factory takes the mock client and the optional
// `onSessionExpired` + `revalidateInterval` props so one call site
// covers every provider configuration the tests need.
function renderContext(
  client: MockAuthClient,
  options: { onSessionExpired?: () => void; revalidateInterval?: number } = {}
): ReturnType<typeof renderHook<AuthContextValue | null, unknown>> {
  const { onSessionExpired, revalidateInterval } = options
  return renderHook(() => useContext(AuthContext), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <AuthProvider
        client={client}
        {...(onSessionExpired ? { onSessionExpired } : {})}
        {...(revalidateInterval !== undefined ? { revalidateInterval } : {})}
      >
        {children}
      </AuthProvider>
    )
  })
}

// Props the rerender-driven harness can vary between renders. Mirrors
// the subset of AuthProviderProps the freshness/dependency-array tests
// flip (a fresh `client`, a fresh `onSessionExpired`, a new interval).
interface HarnessProps {
  client: MockAuthClient
  onSessionExpired?: () => void
  revalidateInterval?: number
}

// Latest context value captured by the in-tree consumer. Reset by
// `renderProvider` on each setup so reads never bleed across tests.
let capturedContext: AuthContextValue | null = null

// In-tree consumer that mirrors the live context into `capturedContext`.
// Using a real child (rather than renderHook) lets the surrounding
// `render(...).rerender(...)` swap provider PROPS between renders, which
// is exactly what the ref-freshness and dependency-array mutants need.
function ContextProbe(): null {
  capturedContext = useContext(AuthContext)
  return null
}

// Render an <AuthProvider> with a real child probe and return the
// `rerender` handle so a test can hand the provider a different
// `client` / `onSessionExpired` / `revalidateInterval` on a later
// render and observe how the effects react.
function renderProvider(props: HarnessProps): { rerender: (next: HarnessProps) => void } {
  capturedContext = null
  const element = (next: HarnessProps): ReactNode => (
    <AuthProvider
      client={next.client}
      {...(next.onSessionExpired ? { onSessionExpired: next.onSessionExpired } : {})}
      {...(next.revalidateInterval !== undefined
        ? { revalidateInterval: next.revalidateInterval }
        : {})}
    >
      <ContextProbe />
    </AuthProvider>
  )
  const view = render(element(props))
  return {
    rerender: (next: HarnessProps): void => {
      view.rerender(element(next))
    }
  }
}

// ---------------------------------------------------------------------------
// AuthProvider — children rendering and initial mount probe
// ---------------------------------------------------------------------------

describe('AuthProvider — initial mount', () => {
  // Children must always render. This is the baseline contract for a
  // React provider: it may not swallow its subtree or gate rendering
  // on the session state.
  it('renders children', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    const { getByText } = render(
      <AuthProvider client={client}>
        <div>child-content</div>
      </AuthProvider>
    )
    expect(getByText('child-content')).toBeDefined()
    // Drain the pending initial-mount effect so React does not warn.
    await act(async () => {
      await Promise.resolve()
    })
  })

  // The provider must immediately probe the server for an existing
  // session — otherwise a reload with a valid refresh cookie would
  // leave the UI stuck in `loading` or `unauthenticated`.
  it('calls client.getMe() on mount', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    await act(async () => {
      renderContext(client)
    })
    expect(client.getMe).toHaveBeenCalledTimes(1)
  })

  // Successful getMe transitions status loading → authenticated and
  // publishes the returned user to the context.
  it('transitions to authenticated when getMe resolves', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.status).toBe('authenticated')
    expect(result.current?.user).toEqual(MOCK_USER)
    expect(result.current?.isLoading).toBe(false)
    expect(result.current?.lastValidation).toBeInstanceOf(Date)
  })

  // A 401 on initial probe is a "not signed in" signal, not a session
  // expiration — we must land in unauthenticated WITHOUT invoking the
  // consumer's onSessionExpired callback (nothing had expired).
  it('transitions to unauthenticated when getMe returns 401', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    const onSessionExpired = jest.fn()
    const { result } = renderContext(client, { onSessionExpired })
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // Non-401 failures (network outage, 500) also end in unauthenticated
  // but land through the SET_ERROR action. `lastValidation` is NOT
  // cleared — a prior successful validation is still information the
  // consumer may want to show.
  it('transitions to unauthenticated when getMe throws a non-401 error', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new Error('network failure'))
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()
  })

  // SET_ERROR branch behavior contract: when a previously authenticated
  // session hits a non-401 error during revalidation, the reducer
  // preserves `lastValidation` rather than clearing it. This is the
  // documented distinction between `CLEAR_SESSION` (resets timestamp)
  // and `SET_ERROR` (preserves it) — a regression that made SET_ERROR
  // null out `lastValidation` would silently break consumers that show
  // "last checked" UI during transient server errors.
  it('preserves lastValidation when revalidation hits a non-401 error', async () => {
    jest.useFakeTimers()
    try {
      jest.setSystemTime(new Date('2026-04-18T10:00:00.000Z'))
      const client = createMockClient()
      client.getMe.mockResolvedValueOnce(MOCK_USER)
      client.getMe.mockRejectedValueOnce(new Error('transient 500'))
      let result: { current: AuthContextValue | null } | undefined
      await act(async () => {
        result = renderContext(client, { revalidateInterval: 1000 }).result
      })
      const firstValidation = result?.current?.lastValidation?.getTime()
      expect(firstValidation).toBeDefined()
      jest.setSystemTime(new Date('2026-04-18T10:00:05.000Z'))
      await act(async () => {
        jest.advanceTimersByTime(1000)
        await Promise.resolve()
      })
      expect(result?.current?.status).toBe('unauthenticated')
      expect(result?.current?.user).toBeNull()
      expect(result?.current?.lastValidation?.getTime()).toBe(firstValidation)
    } finally {
      jest.useRealTimers()
    }
  })
})

// ---------------------------------------------------------------------------
// AuthProvider — login flow (success, MFA, failure)
// ---------------------------------------------------------------------------

describe('AuthProvider — login', () => {
  // Successful login forwards the credentials to client.login with
  // the default tenant id, then commits the returned user to context.
  it('sets the authenticated user on successful login and uses default tenantId', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.login.mockResolvedValue(MOCK_AUTH_RESULT)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current?.login('a@b.test', 'pw')
    })
    expect(client.login).toHaveBeenCalledWith({
      email: 'a@b.test',
      password: 'pw',
      tenantId: 'default'
    })
    expect(result.current?.status).toBe('authenticated')
    expect(result.current?.user).toEqual(MOCK_USER)
  })

  // Explicit tenantId on the options bag must be forwarded verbatim so
  // multi-tenant apps can pass a tenant picked from the URL.
  it('forwards an explicit tenantId to client.login', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.login.mockResolvedValue(MOCK_AUTH_RESULT)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current?.login('a@b.test', 'pw', { tenantId: 'acme' })
    })
    expect(client.login).toHaveBeenCalledWith({
      email: 'a@b.test',
      password: 'pw',
      tenantId: 'acme'
    })
  })

  // MFA challenge: the provider must NOT mark the session authenticated
  // (since the user has not yet proved the second factor) and must
  // return the MfaChallengeResult so the caller can render the OTP UI.
  it('keeps status unauthenticated and returns the MfaChallengeResult on MFA', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.login.mockResolvedValue(MOCK_MFA_RESULT)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    let returned: unknown
    await act(async () => {
      returned = await result.current?.login('a@b.test', 'pw')
    })
    expect(returned).toEqual(MOCK_MFA_RESULT)
    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()
  })

  // Login failure must land the state in unauthenticated AND re-throw
  // so the caller can branch on error.code in their submit handler.
  it('dispatches SET_ERROR and re-throws on login failure', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.login.mockRejectedValue(new AuthClientError('bad credentials', 401))
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await expect(result.current?.login('a@b.test', 'wrong')).rejects.toBeInstanceOf(
        AuthClientError
      )
    })
    expect(result.current?.status).toBe('unauthenticated')
  })

  // While a login request is in flight the reducer's SET_LOADING action
  // must surface status === 'loading' (isLoading === true) so consumers
  // can render a spinner. Pinning the intermediate loading state guards
  // the SET_LOADING reducer arm: if it were dropped (falling through to
  // the next case), the status would read 'unauthenticated' mid-request
  // instead of 'loading'. We hold client.login on a deferred promise to
  // freeze the in-flight window and assert it deterministically.
  it('exposes loading status while a login request is in flight', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    let resolveLogin!: (value: LoginResult) => void
    client.login.mockReturnValue(
      new Promise<LoginResult>((resolve) => {
        resolveLogin = resolve
      })
    )
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.status).toBe('unauthenticated')
    let loginPromise: Promise<unknown> | undefined
    act(() => {
      loginPromise = result.current?.login('a@b.test', 'pw')
    })
    expect(result.current?.status).toBe('loading')
    expect(result.current?.isLoading).toBe(true)
    await act(async () => {
      resolveLogin(MOCK_AUTH_RESULT)
      await loginPromise
    })
    expect(result.current?.status).toBe('authenticated')
  })
})

// ---------------------------------------------------------------------------
// AuthProvider — register, logout, refresh, password methods
// ---------------------------------------------------------------------------

describe('AuthProvider — imperative methods', () => {
  // register forwards the input, commits the resulting user, and
  // lands the state in authenticated on success.
  it('sets the authenticated user on successful register', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.register.mockResolvedValue(MOCK_AUTH_RESULT)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current?.register({
        email: 'new@example.test',
        password: 'pw',
        name: 'New User',
        tenantId: 'default'
      })
    })
    expect(client.register).toHaveBeenCalledTimes(1)
    expect(result.current?.status).toBe('authenticated')
  })

  // register failure mirrors login failure — re-throw and land in
  // unauthenticated so the caller can handle the validation error.
  it('dispatches SET_ERROR and re-throws on register failure', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.register.mockRejectedValue(new AuthClientError('email taken', 409))
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await expect(
        result.current?.register({
          email: 'new@example.test',
          password: 'pw',
          name: 'New User',
          tenantId: 'default'
        })
      ).rejects.toBeInstanceOf(AuthClientError)
    })
    expect(result.current?.status).toBe('unauthenticated')
  })

  // logout clears the session state regardless of whether the network
  // call succeeds. The `finally` branch is critical — if we only
  // cleared on success, a transient outage would leave the UI showing
  // authenticated state for a user that explicitly signed out. The
  // underlying rejection then propagates to the caller by design (see
  // the JSDoc contract on `AuthContextValue.logout`), so a consumer
  // can surface "signed out locally, server call failed" UX — this
  // test pins both halves of that contract.
  it('clears session state even when client.logout rejects', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    client.logout.mockRejectedValue(new Error('network down'))
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.status).toBe('authenticated')
    await act(async () => {
      await expect(result.current?.logout()).rejects.toThrow('network down')
    })
    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()
  })

  // Happy-path logout also clears state and resolves cleanly.
  it('clears session state on successful logout', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    client.logout.mockResolvedValue(undefined)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current?.logout()
    })
    expect(client.logout).toHaveBeenCalledTimes(1)
    expect(result.current?.status).toBe('unauthenticated')
  })

  // logout dispatches CLEAR_SESSION, which is the ONE transition that
  // resets `lastValidation` to null — distinct from SET_ERROR, which
  // preserves it. After authenticating (so lastValidation is a Date),
  // logging out must wipe the timestamp. This pins the CLEAR_SESSION
  // reducer arm specifically: if it fell through to SET_ERROR, status
  // would still flip to 'unauthenticated' but the stale timestamp would
  // linger, so we assert on lastValidation (status alone can't tell the
  // two arms apart).
  it('clears lastValidation on logout', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    client.logout.mockResolvedValue(undefined)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.lastValidation).toBeInstanceOf(Date)
    await act(async () => {
      await result.current?.logout()
    })
    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.lastValidation).toBeNull()
  })

  // Explicit refresh re-probes the server. A successful response
  // refreshes `lastValidation` — we control the clock via fake timers
  // and `setSystemTime` so the second timestamp is strictly later
  // regardless of the host machine's speed. Without the controlled
  // clock the assertion could pass by coincidence on a fast CI box
  // where both `new Date()` calls fall inside the same millisecond.
  it('refresh calls getMe again and updates lastValidation on success', async () => {
    jest.useFakeTimers()
    try {
      jest.setSystemTime(new Date('2026-04-18T10:00:00.000Z'))
      const client = createMockClient()
      client.getMe.mockResolvedValue(MOCK_USER)
      const { result } = renderContext(client)
      await act(async () => {
        await Promise.resolve()
      })
      const firstValidation = result.current?.lastValidation?.getTime()
      // Advance the virtual clock by 1s so the post-refresh timestamp
      // is deterministically later than the initial one.
      jest.setSystemTime(new Date('2026-04-18T10:00:01.000Z'))
      await act(async () => {
        await result.current?.refresh()
      })
      expect(client.getMe).toHaveBeenCalledTimes(2)
      expect(result.current?.lastValidation?.getTime()).toBeGreaterThan(firstValidation ?? 0)
    } finally {
      jest.useRealTimers()
    }
  })

  // refresh() must revalidate as a NON-initial probe: an explicit
  // refresh that hits a 401 on a previously authenticated session is a
  // genuine expiry and MUST fire onSessionExpired. This pins the
  // `revalidate(false)` argument inside refresh — were it `true`, the
  // call would be treated as an initial mount probe and the
  // onSessionExpired callback would be suppressed, silently swallowing
  // the expiry signal for manual refreshes.
  it('refresh fires onSessionExpired when the session has expired', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    client.getMe.mockRejectedValueOnce(new AuthClientError('unauthorized', 401))
    const onSessionExpired = jest.fn()
    const { result } = renderContext(client, { revalidateInterval: 0, onSessionExpired })
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.status).toBe('authenticated')
    await act(async () => {
      await result.current?.refresh()
    })
    expect(onSessionExpired).toHaveBeenCalledTimes(1)
    expect(result.current?.status).toBe('unauthenticated')
  })

  // forgotPassword defaults the tenantId when the caller omits it,
  // matching the provider's single-tenant ergonomic promise.
  it('forgotPassword uses default tenantId when omitted', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.forgotPassword.mockResolvedValue(undefined)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current?.forgotPassword('a@b.test')
    })
    expect(client.forgotPassword).toHaveBeenCalledWith('a@b.test', 'default')
  })

  // forgotPassword forwards an explicit tenantId verbatim.
  it('forgotPassword forwards an explicit tenantId', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.forgotPassword.mockResolvedValue(undefined)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current?.forgotPassword('a@b.test', 'acme')
    })
    expect(client.forgotPassword).toHaveBeenCalledWith('a@b.test', 'acme')
  })

  // resetPassword is a pure pass-through to the client — the provider
  // does not own any state transition for it, but we assert the
  // payload reaches the client unmodified (discriminated-union shapes
  // are otherwise easy to mangle during refactors).
  it('resetPassword forwards the input to the client', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.resetPassword.mockResolvedValue(undefined)
    const { result } = renderContext(client)
    await act(async () => {
      await Promise.resolve()
    })
    const input = {
      email: 'a@b.test',
      tenantId: 'default',
      newPassword: 'newpw',
      token: 'reset-token'
    } as const
    await act(async () => {
      await result.current?.resetPassword(input)
    })
    expect(client.resetPassword).toHaveBeenCalledWith(input)
  })
})

// ---------------------------------------------------------------------------
// AuthProvider — revalidation interval and session-expiry callback
// ---------------------------------------------------------------------------

describe('AuthProvider — revalidation loop', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  // The background interval must fire at exactly the configured
  // cadence. We set a small interval (1s) so the test stays readable.
  it('calls getMe again after the configured interval', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    await act(async () => {
      renderContext(client, { revalidateInterval: 1000 })
    })
    expect(client.getMe).toHaveBeenCalledTimes(1)
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(client.getMe).toHaveBeenCalledTimes(2)
  })

  // A zero (or negative) interval must fully disable the loop so
  // short-lived flows (sign-up wizards) do not incur any background
  // work. We run the timer forward and assert no extra calls happen.
  it('disables the interval when revalidateInterval is 0', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    await act(async () => {
      renderContext(client, { revalidateInterval: 0 })
    })
    expect(client.getMe).toHaveBeenCalledTimes(1)
    jest.advanceTimersByTime(10_000)
    expect(client.getMe).toHaveBeenCalledTimes(1)
  })

  // Unmount must clear the interval — otherwise a long-lived test
  // environment (or consumer app that mounts/unmounts many providers)
  // would leak timers indefinitely. We assert by unmounting and then
  // verifying no further getMe calls occur.
  it('clears the interval on unmount', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    let unmount: (() => void) | undefined
    await act(async () => {
      const rendered = renderContext(client, { revalidateInterval: 1000 })
      unmount = rendered.unmount
    })
    expect(client.getMe).toHaveBeenCalledTimes(1)
    unmount?.()
    jest.advanceTimersByTime(10_000)
    expect(client.getMe).toHaveBeenCalledTimes(1)
  })

  // onSessionExpired must fire when the background revalidation
  // catches a 401 while the status was previously authenticated. This
  // is the core "detect revoked session" signal the provider offers.
  it('fires onSessionExpired when revalidation returns 401 after authentication', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    client.getMe.mockRejectedValueOnce(new AuthClientError('unauthorized', 401))
    const onSessionExpired = jest.fn()
    let result: { current: AuthContextValue | null } | undefined
    await act(async () => {
      result = renderContext(client, { revalidateInterval: 1000, onSessionExpired }).result
    })
    expect(result?.current?.status).toBe('authenticated')
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(onSessionExpired).toHaveBeenCalledTimes(1)
    expect(result?.current?.status).toBe('unauthenticated')
  })

  // onSessionExpired must NOT fire for the very first 401 on mount —
  // that's a "not signed in" state, not an expiration event. Firing
  // the callback here would push every anonymous visitor through a
  // sign-in-expired redirect.
  it('does not fire onSessionExpired on the initial unauthenticated mount', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    const onSessionExpired = jest.fn()
    await act(async () => {
      renderContext(client, { onSessionExpired })
    })
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // A throwing onSessionExpired callback must not abort the state
  // transition. The provider catches the callback error, logs a warn,
  // and still lands in unauthenticated — the broken callback must not
  // trap the UI in authenticated state.
  it('isolates a throwing onSessionExpired callback', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    client.getMe.mockRejectedValueOnce(new AuthClientError('unauthorized', 401))
    const onSessionExpired = jest.fn(() => {
      throw new Error('consumer bug')
    })
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined)
    let result: { current: AuthContextValue | null } | undefined
    await act(async () => {
      result = renderContext(client, { revalidateInterval: 1000, onSessionExpired }).result
    })
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(result?.current?.status).toBe('unauthenticated')
    // Pin the diagnostic prefix and the forwarded error so the warn
    // call stays debuggable: a mutant that blanks the message string
    // would still "have been called", so the bare toHaveBeenCalled()
    // above cannot catch it — the exact-args assertion does.
    expect(warnSpy).toHaveBeenCalledWith(
      '[nest-auth] onSessionExpired callback threw:',
      expect.any(Error)
    )
    warnSpy.mockRestore()
  })

  // A non-401 AuthClientError during revalidation (e.g. a 500) is NOT a
  // session expiry: it must route through SET_ERROR, leaving
  // `lastValidation` intact and NOT firing onSessionExpired. This pins
  // the `error.status === 401` half of isSessionExpiredError — if that
  // comparison were short-circuited to always-true, a 500 would be
  // misclassified as an expiry, firing the callback and clearing the
  // timestamp via CLEAR_SESSION.
  it('does not fire onSessionExpired for a non-401 AuthClientError during revalidation', async () => {
    jest.setSystemTime(new Date('2026-04-18T10:00:00.000Z'))
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    client.getMe.mockRejectedValueOnce(new AuthClientError('server error', 500))
    const onSessionExpired = jest.fn()
    let result: { current: AuthContextValue | null } | undefined
    await act(async () => {
      result = renderContext(client, { revalidateInterval: 1000, onSessionExpired }).result
    })
    const firstValidation = result?.current?.lastValidation?.getTime()
    expect(firstValidation).toBeDefined()
    jest.setSystemTime(new Date('2026-04-18T10:00:05.000Z'))
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(onSessionExpired).not.toHaveBeenCalled()
    expect(result?.current?.status).toBe('unauthenticated')
    expect(result?.current?.lastValidation?.getTime()).toBe(firstValidation)
  })

  // A 401 during a background tick while the session was NEVER
  // authenticated must NOT fire onSessionExpired — there is nothing to
  // "expire". This pins both the `wasAuthenticated` read (mutating it
  // to a constant `true` would fire the callback) and the `&&` join in
  // `!isInitial && wasAuthenticated` (an `||` would fire it on every
  // non-initial tick regardless of prior auth state).
  it('does not fire onSessionExpired when a tick 401s while never authenticated', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    const onSessionExpired = jest.fn()
    let result: { current: AuthContextValue | null } | undefined
    await act(async () => {
      result = renderContext(client, { revalidateInterval: 1000, onSessionExpired }).result
    })
    expect(result?.current?.status).toBe('unauthenticated')
    expect(onSessionExpired).not.toHaveBeenCalled()
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(client.getMe).toHaveBeenCalledTimes(2)
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // After an expiry fires once, the synced status mirror must move to
  // 'unauthenticated' so a SECOND consecutive 401 tick does NOT re-fire
  // onSessionExpired (the session is already known-gone). This pins the
  // CLEAR_SESSION/SET_ERROR arm of syncedDispatch that writes
  // statusRef = 'unauthenticated': if that write were dropped, the
  // mirror would stay 'authenticated' and the callback would fire again
  // on every subsequent tick.
  it('fires onSessionExpired only once across repeated 401 ticks', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    const onSessionExpired = jest.fn()
    let result: { current: AuthContextValue | null } | undefined
    await act(async () => {
      result = renderContext(client, { revalidateInterval: 1000, onSessionExpired }).result
    })
    expect(result?.current?.status).toBe('authenticated')
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(onSessionExpired).toHaveBeenCalledTimes(1)
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(client.getMe).toHaveBeenCalledTimes(3)
    expect(onSessionExpired).toHaveBeenCalledTimes(1)
  })

  // The synced status mirror must also reflect SET_LOADING: while a
  // login is in flight (status 'loading'), a concurrent revalidation
  // tick that 401s must treat the session as NOT authenticated and so
  // must NOT fire onSessionExpired. This pins the SET_LOADING arm of
  // syncedDispatch (statusRef = 'loading'): if dropped, the mirror would
  // retain the pre-login 'authenticated' value and the tick would
  // wrongly fire the expiry callback.
  it('does not fire onSessionExpired for a tick 401 while a login is in flight', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    let resolveLogin!: (value: LoginResult) => void
    client.login.mockReturnValue(
      new Promise<LoginResult>((resolve) => {
        resolveLogin = resolve
      })
    )
    const onSessionExpired = jest.fn()
    let result: { current: AuthContextValue | null } | undefined
    await act(async () => {
      result = renderContext(client, { revalidateInterval: 1000, onSessionExpired }).result
    })
    expect(result?.current?.status).toBe('authenticated')
    let loginPromise: Promise<unknown> | undefined
    act(() => {
      loginPromise = result?.current?.login('a@b.test', 'pw')
    })
    expect(result?.current?.status).toBe('loading')
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(onSessionExpired).not.toHaveBeenCalled()
    await act(async () => {
      resolveLogin(MOCK_AUTH_RESULT)
      await loginPromise
    })
  })

  // The revalidation interval effect depends on `revalidateInterval`:
  // toggling the prop from disabled (0) to a live cadence must rebuild
  // the loop. This pins that dependency — if the effect's dep array were
  // emptied, the effect would run once at mount (disabled) and never
  // re-subscribe, so the interval would stay dead after the prop change.
  it('starts the interval when revalidateInterval changes from 0 to a positive value', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    let harness: { rerender: (next: HarnessProps) => void } | undefined
    await act(async () => {
      harness = renderProvider({ client, revalidateInterval: 0 })
    })
    expect(client.getMe).toHaveBeenCalledTimes(1)
    jest.advanceTimersByTime(5000)
    expect(client.getMe).toHaveBeenCalledTimes(1)
    await act(async () => {
      harness?.rerender({ client, revalidateInterval: 1000 })
    })
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(client.getMe).toHaveBeenCalledTimes(2)
  })

  // The provider keeps the latest onSessionExpired in a ref and refreshes
  // it via an effect keyed on the prop. When the parent re-renders with a
  // NEW callback, an expiry must invoke the new one and never the stale
  // one. This pins both the ref-sync effect body and its dependency
  // array: dropping either would leave the first callback wired up.
  it('invokes the latest onSessionExpired after the prop changes', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    const firstCallback = jest.fn()
    const secondCallback = jest.fn()
    let harness: { rerender: (next: HarnessProps) => void } | undefined
    await act(async () => {
      harness = renderProvider({
        client,
        revalidateInterval: 1000,
        onSessionExpired: firstCallback
      })
    })
    expect(capturedContext?.status).toBe('authenticated')
    await act(async () => {
      harness?.rerender({ client, revalidateInterval: 1000, onSessionExpired: secondCallback })
    })
    await act(async () => {
      jest.advanceTimersByTime(1000)
      await Promise.resolve()
    })
    expect(secondCallback).toHaveBeenCalledTimes(1)
    expect(firstCallback).not.toHaveBeenCalled()
  })

  // The provider keeps the latest client in a ref and refreshes it via an
  // effect keyed on the `client` prop. When the parent swaps in a NEW
  // client, subsequent revalidations must call the new client's getMe,
  // not the original's. This pins both the client-sync effect body and
  // its dependency array: dropping either would keep calling the old
  // client after the swap.
  it('uses the latest client after the client prop changes', async () => {
    const firstClient = createMockClient()
    firstClient.getMe.mockResolvedValue(MOCK_USER)
    const secondClient = createMockClient()
    secondClient.getMe.mockResolvedValue(MOCK_USER)
    let harness: { rerender: (next: HarnessProps) => void } | undefined
    await act(async () => {
      harness = renderProvider({ client: firstClient, revalidateInterval: 0 })
    })
    expect(firstClient.getMe).toHaveBeenCalledTimes(1)
    await act(async () => {
      harness?.rerender({ client: secondClient, revalidateInterval: 0 })
    })
    await act(async () => {
      await capturedContext?.refresh()
    })
    expect(secondClient.getMe).toHaveBeenCalledTimes(1)
    expect(firstClient.getMe).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// A deliberate transition beats an in-flight revalidation
// ---------------------------------------------------------------------------

describe('session generation', () => {
  // Scenario: the 5-minute tick (or a focus-triggered `refresh()`) starts `getMe()`, the user
  // clicks Log out, and the `getMe()` resolves 200 afterwards — a legitimate response, issued
  // before the server revoked anything.
  //
  // Expected: the response is discarded. Why: it used to be applied unconditionally, so
  // `status` flipped back to `authenticated`, the profile returned to context, and
  // `useAuthStatus().isAuthenticated` — which this library's own JSDoc calls safe to gate
  // protected routes on — answered `true` again after a sign-out. On a shared or kiosk machine
  // that renders the previous person's account to the next one. Server calls would 401, but
  // nothing in the provider reacted until the next tick.
  //
  // The window is one round trip and needs no unusual user behaviour to open.
  it('discards a getMe that resolves after logout', async () => {
    const client = createMockClient()
    let resolveGetMe: ((user: typeof MOCK_USER) => void) | undefined
    // First call settles the initial mount; the second is the one held open across the logout.
    client.getMe.mockResolvedValueOnce(MOCK_USER).mockImplementationOnce(
      async () =>
        new Promise((resolve) => {
          resolveGetMe = resolve
        })
    )

    const { result } = renderContext(client, { revalidateInterval: 0 })
    await act(async () => {})
    expect(result.current?.status).toBe('authenticated')

    // Start the revalidation and leave it hanging.
    let refreshing: Promise<void> | undefined
    await act(async () => {
      refreshing = result.current?.refresh()
    })

    await act(async () => {
      await result.current?.logout()
    })
    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()

    // The in-flight request now answers 200 for the session that just ended.
    await act(async () => {
      resolveGetMe?.(MOCK_USER)
      await refreshing
    })

    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()
  })

  // The mirror image: a 401 arriving for a session the caller already ended must not fire
  // `onSessionExpired`. The user signed out deliberately; telling the app their session
  // expired sends them through a "you were signed out" flow they did not experience.
  //
  // This one already held before the generation counter, because `wasAuthenticated` reads
  // `statusRef` AFTER the await and logout has already set it to `unauthenticated`. It is
  // pinned here anyway: the property is what matters, and it currently depends on the ordering
  // of two unrelated pieces of state rather than on one explicit rule.
  it('does not fire onSessionExpired for a 401 that lands after logout', async () => {
    const client = createMockClient()
    const onSessionExpired = jest.fn()
    let rejectGetMe: ((error: unknown) => void) | undefined
    client.getMe.mockResolvedValueOnce(MOCK_USER).mockImplementationOnce(
      async () =>
        new Promise((_resolve, reject) => {
          rejectGetMe = reject
        })
    )

    const { result } = renderContext(client, { revalidateInterval: 0, onSessionExpired })
    await act(async () => {})

    let refreshing: Promise<void> | undefined
    await act(async () => {
      refreshing = result.current?.refresh()
    })

    await act(async () => {
      await result.current?.logout()
    })

    await act(async () => {
      rejectGetMe?.(new AuthClientError('Unauthorized', 401))
      await refreshing
    })

    expect(onSessionExpired).not.toHaveBeenCalled()
    expect(result.current?.status).toBe('unauthenticated')
  })

  // Scenario: a revalidation is in flight, the user LOGS IN, and the earlier `getMe()` then
  // answers 401 — because the session it was issued against is the one the login replaced.
  //
  // Expected: nothing happens. Why: this is where the stale-result check in the failure arm
  // actually decides something. After a logout, `statusRef` is already `unauthenticated`, so
  // `wasAuthenticated` is false and the callback would be skipped anyway — the logout case
  // cannot pin the guard. After a LOGIN the status is `authenticated`, so without the check the
  // 401 for the PREVIOUS session fires `onSessionExpired` and dispatches `CLEAR_SESSION`,
  // signing the user out of the session they just established and sending the app through a
  // "you were signed out" flow one round trip after signing in.
  it('ignores a 401 from the previous session when a login has landed', async () => {
    const client = createMockClient()
    client.login.mockResolvedValue(MOCK_AUTH_RESULT)
    const onSessionExpired = jest.fn()
    let rejectGetMe: ((error: unknown) => void) | undefined
    client.getMe.mockResolvedValueOnce(MOCK_USER).mockImplementationOnce(
      async () =>
        new Promise((_resolve, reject) => {
          rejectGetMe = reject
        })
    )

    const { result } = renderContext(client, { revalidateInterval: 0, onSessionExpired })
    await act(async () => {})

    let refreshing: Promise<void> | undefined
    await act(async () => {
      refreshing = result.current?.refresh()
    })

    await act(async () => {
      await result.current?.login('new@example.com', '__test_only_password')
    })
    expect(result.current?.status).toBe('authenticated')

    await act(async () => {
      rejectGetMe?.(new AuthClientError('Unauthorized', 401))
      await refreshing
    })

    expect(onSessionExpired).not.toHaveBeenCalled()
    expect(result.current?.status).toBe('authenticated')
    expect(result.current?.user?.id).toBe(MOCK_AUTH_RESULT.user.id)
  })

  // Scenario: a revalidation is in flight, the user submits credentials, and the server answers
  // with an MFA challenge rather than a session. Expected: the earlier `getMe()` is discarded.
  //
  // Why this branch specifically: it is the one transition that clears the session WITHOUT
  // establishing a new one, so the "a login replaced the identity" reasoning does not cover it
  // — and it was the one path the generation token was not moved on. A stale `getMe()` landing
  // here puts the PREVIOUS user back into context while the app is blocking on an OTP prompt,
  // and `useAuthStatus().isAuthenticated` — documented as safe to gate protected routes on —
  // answers `true` again. The route guards reopen on the very session the second factor was
  // meant to stand in front of.
  it('discards a getMe that resolves after a login answered with an MFA challenge', async () => {
    const client = createMockClient()
    client.login.mockResolvedValue(MOCK_MFA_RESULT)
    let resolveGetMe: ((user: typeof MOCK_USER) => void) | undefined
    client.getMe.mockResolvedValueOnce(MOCK_USER).mockImplementationOnce(
      async () =>
        new Promise((resolve) => {
          resolveGetMe = resolve
        })
    )

    const { result } = renderContext(client, { revalidateInterval: 0 })
    await act(async () => {})
    expect(result.current?.status).toBe('authenticated')

    let refreshing: Promise<void> | undefined
    await act(async () => {
      refreshing = result.current?.refresh()
    })

    await act(async () => {
      await result.current?.login('user@example.com', '__test_only_password')
    })
    // The MFA gate: no session, and the guards must deny.
    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()

    await act(async () => {
      resolveGetMe?.(MOCK_USER)
      await refreshing
    })

    expect(result.current?.status).toBe('unauthenticated')
    expect(result.current?.user).toBeNull()
  })

  // A login also supersedes an in-flight revalidation: the earlier `getMe()` answers for the
  // PREVIOUS session, and applying it would overwrite the identity just established.
  it('discards a getMe that resolves after a login', async () => {
    const client = createMockClient()
    client.login.mockResolvedValue(MOCK_AUTH_RESULT)
    const previousUser = { ...MOCK_USER, id: 'previous-user', email: 'previous@example.com' }
    let resolveGetMe: ((user: typeof MOCK_USER) => void) | undefined
    client.getMe.mockResolvedValueOnce(MOCK_USER).mockImplementationOnce(
      async () =>
        new Promise((resolve) => {
          resolveGetMe = resolve
        })
    )

    const { result } = renderContext(client, { revalidateInterval: 0 })
    await act(async () => {})

    let refreshing: Promise<void> | undefined
    await act(async () => {
      refreshing = result.current?.refresh()
    })

    await act(async () => {
      await result.current?.login('new@example.com', '__test_only_password')
    })
    expect(result.current?.user?.id).toBe(MOCK_AUTH_RESULT.user.id)

    await act(async () => {
      resolveGetMe?.(previousUser)
      await refreshing
    })

    expect(result.current?.user?.id).toBe(MOCK_AUTH_RESULT.user.id)
  })
})
