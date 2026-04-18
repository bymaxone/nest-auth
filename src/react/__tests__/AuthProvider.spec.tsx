/**
 * @jest-environment jsdom
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

import { AuthClientError } from '../../shared'
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
    expect(warnSpy).toHaveBeenCalled()
    warnSpy.mockRestore()
  })
})
