/**
 * React provider for @bymax-one/nest-auth.
 *
 * Owns the session state machine (`loading` → `authenticated` /
 * `unauthenticated`), bridges the typed {@link AuthClient} into
 * {@link AuthContext}, and schedules a best-effort revalidation loop
 * so long-lived UIs surface role/status changes without requiring the
 * user to refresh manually.
 *
 * The provider is deliberately thin: it does not parse tokens, touch
 * storage, or decide how the server delivers credentials. Every
 * transport detail lives in the `client` subpath; this file only
 * coordinates state and React plumbing.
 */

import { useCallback, useEffect, useMemo, useReducer, useRef, type ReactNode } from 'react'

import type { AuthClient, RegisterInput, ResetPasswordInput } from '../client'
import { AuthClientError, type AuthUserClient, type LoginResult } from '../shared'
import { AuthContext, type AuthContextValue, type AuthStatus } from './context'

/**
 * Default revalidation cadence — 5 minutes.
 *
 * Balances "detect revoked sessions quickly" against "do not burn
 * battery on an idle tab". Tune via the `revalidateInterval` prop when
 * a deployment has different freshness requirements.
 */
const DEFAULT_REVALIDATE_INTERVAL_MS = 300_000

/**
 * Fallback tenant identifier applied when the consumer omits the
 * `tenantId` option on the {@link AuthContextValue.login} convenience
 * signature. Single-tenant apps can therefore call `login(email, pw)`
 * without threading a tenant constant through every component.
 */
const DEFAULT_TENANT_ID = 'default'

/**
 * Props accepted by {@link AuthProvider}.
 */
export interface AuthProviderProps {
  /** Rendered inside the provider once state is initialized. */
  children: ReactNode

  /**
   * Authentication client built via `createAuthClient`. The provider
   * never constructs one itself so test harnesses and SSR shells can
   * inject a mock or a pre-configured instance.
   */
  client: AuthClient

  /**
   * Fired when the provider detects that the session has expired —
   * i.e. a prior `authenticated` state transitions to
   * `unauthenticated` because `getMe()` or `refresh()` failed with a
   * 401. Typical wiring: redirect to the sign-in page.
   *
   * Not called on the initial mount when no session exists to begin
   * with (that is "not signed in", not "session expired"), nor on
   * explicit {@link AuthContextValue.logout} calls.
   */
  onSessionExpired?: () => void

  /**
   * Interval (in milliseconds) between automatic revalidations.
   * Default: {@link DEFAULT_REVALIDATE_INTERVAL_MS} (5 minutes).
   *
   * Set to `0` to disable the loop entirely — useful for short-lived
   * flows (sign-up wizards, kiosk screens) where the overhead of a
   * background poll is not worth the freshness guarantee.
   */
  revalidateInterval?: number
}

/**
 * Internal shape of the reducer state.
 *
 * Separate from {@link AuthContextValue} because the context surface
 * carries bound methods and boolean conveniences that are derived
 * rather than stored.
 */
interface AuthState {
  user: AuthUserClient | null
  status: AuthStatus
  lastValidation: Date | null
}

/**
 * Reducer actions. Kept intentionally small: four transitions cover
 * every observable state change and adding another action tends to be
 * a design-smell signal that the caller should compose existing ones.
 */
type AuthAction =
  | { type: 'SET_USER'; payload: { user: AuthUserClient; timestamp: Date } }
  | { type: 'SET_LOADING' }
  | { type: 'CLEAR_SESSION' }
  | { type: 'SET_ERROR' }

const INITIAL_STATE: AuthState = {
  user: null,
  status: 'loading',
  lastValidation: null
}

/**
 * Pure state-transition function for the provider's reducer.
 *
 * `CLEAR_SESSION` and `SET_ERROR` both land in `unauthenticated` but
 * are kept distinct so logging / analytics downstream can tell an
 * explicit logout apart from a failed revalidation.
 */
function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'SET_USER':
      return {
        user: action.payload.user,
        status: 'authenticated',
        lastValidation: action.payload.timestamp
      }
    case 'SET_LOADING':
      return { ...state, status: 'loading' }
    case 'CLEAR_SESSION':
      return { user: null, status: 'unauthenticated', lastValidation: null }
    case 'SET_ERROR':
      return { user: null, status: 'unauthenticated', lastValidation: state.lastValidation }
  }
}

/**
 * Type guard for "the request failed because the session is missing
 * or invalid". Any non-401 AuthClientError (e.g. a 500) leaves us in
 * an error state that is not worth triggering `onSessionExpired` for.
 */
function isSessionExpiredError(error: unknown): boolean {
  return error instanceof AuthClientError && error.status === 401
}

/**
 * Top-level React provider that wires the auth state machine into the
 * {@link AuthContext}.
 *
 * @example
 * ```tsx
 * const client = createAuthClient({ baseUrl: '/api' })
 *
 * export function App() {
 *   return (
 *     <AuthProvider client={client} onSessionExpired={() => router.push('/sign-in')}>
 *       <Routes />
 *     </AuthProvider>
 *   )
 * }
 * ```
 */
export function AuthProvider({
  children,
  client,
  onSessionExpired,
  revalidateInterval = DEFAULT_REVALIDATE_INTERVAL_MS
}: AuthProviderProps): ReactNode {
  const [state, dispatch] = useReducer(authReducer, INITIAL_STATE)

  // Keep the latest `onSessionExpired` in a ref so the revalidation
  // effect does not tear down and rebuild the interval each time the
  // parent re-renders with a fresh inline callback. Same treatment for
  // `client` — a consumer that rebuilds the client reference between
  // renders (common when config flags flip) should not cancel the
  // running interval mid-tick.
  const onSessionExpiredRef = useRef(onSessionExpired)
  const clientRef = useRef(client)
  // Mirror of `state.status` updated SYNCHRONOUSLY alongside every
  // dispatch via `syncedDispatch`, so async callers (interval ticks,
  // user-initiated `refresh()` immediately after `logout()`) see the
  // latest transition without waiting for React's commit-then-effect
  // cycle to flush. A plain `useEffect` sync lags by one tick and
  // masked a race where `onSessionExpired` could fire spuriously.
  const statusRef = useRef<AuthStatus>(INITIAL_STATE.status)

  useEffect(() => {
    onSessionExpiredRef.current = onSessionExpired
  }, [onSessionExpired])

  useEffect(() => {
    clientRef.current = client
  }, [client])

  /**
   * Dispatch wrapper that mirrors the reducer's terminal status into
   * `statusRef.current` in the same synchronous step. Any caller that
   * reads `statusRef` immediately after awaiting this function sees
   * the post-dispatch status, not the pre-dispatch one.
   */
  const syncedDispatch = useCallback((action: AuthAction): void => {
    dispatch(action)
    switch (action.type) {
      case 'SET_USER':
        statusRef.current = 'authenticated'
        return
      case 'SET_LOADING':
        statusRef.current = 'loading'
        return
      case 'CLEAR_SESSION':
      case 'SET_ERROR':
        statusRef.current = 'unauthenticated'
        return
    }
  }, [])

  /**
   * Revalidate the session by calling `getMe()` on the active client.
   *
   * The caller controls whether this counts as an initial fetch
   * (where a 401 means "not signed in") or a revalidation
   * (where a 401 after a prior `authenticated` status means
   * "session expired" and should fire `onSessionExpired`).
   */
  const revalidate = useCallback(
    async (isInitial: boolean): Promise<void> => {
      try {
        const user = await clientRef.current.getMe()
        syncedDispatch({ type: 'SET_USER', payload: { user, timestamp: new Date() } })
      } catch (error) {
        const wasAuthenticated = statusRef.current === 'authenticated'
        if (isSessionExpiredError(error)) {
          if (!isInitial && wasAuthenticated) {
            try {
              onSessionExpiredRef.current?.()
            } catch (callbackError) {
              // Consumer-side errors must not mask the session-state
              // transition; surface to the console so the broken
              // handler is debuggable without breaking auth flow.
              console.warn('[nest-auth] onSessionExpired callback threw:', callbackError)
            }
          }
          syncedDispatch({ type: 'CLEAR_SESSION' })
          return
        }
        syncedDispatch({ type: 'SET_ERROR' })
      }
    },
    [syncedDispatch]
  )

  // Initial mount: probe the server for an existing session.
  useEffect(() => {
    void revalidate(true)
  }, [revalidate])

  // Background revalidation loop.
  useEffect(() => {
    if (revalidateInterval <= 0) {
      return undefined
    }
    const handle = setInterval(() => {
      void revalidate(false)
    }, revalidateInterval)
    return (): void => {
      clearInterval(handle)
    }
  }, [revalidate, revalidateInterval])

  const login = useCallback<AuthContextValue['login']>(
    async (email, password, options) => {
      const tenantId = options?.tenantId ?? DEFAULT_TENANT_ID
      syncedDispatch({ type: 'SET_LOADING' })
      try {
        const result: LoginResult = await clientRef.current.login({ email, password, tenantId })
        if ('mfaRequired' in result) {
          // MFA gate — roll status back to `unauthenticated` so guards
          // checking `status === 'authenticated'` continue to deny
          // access while the challenge is pending. Consumers rendering
          // a spinner via `isLoading` see that flip back to `false`
          // here, which is the intended signal to prompt for the OTP.
          //
          // NOTE: the thrown error from a subsequent `mfaChallenge` is
          // not intercepted here — that call is on the `AuthClient`
          // directly and is expected to route through the caller's
          // component-local error state.
          syncedDispatch({ type: 'CLEAR_SESSION' })
          return result
        }
        syncedDispatch({ type: 'SET_USER', payload: { user: result.user, timestamp: new Date() } })
        return result
      } catch (error) {
        syncedDispatch({ type: 'SET_ERROR' })
        // Re-throw so the calling component can branch on the error's
        // `code` (e.g. `auth.invalid_credentials`). Callers should
        // read `error.message` / `error.code` and avoid logging
        // `error.body` directly — the server's ValidationPipe can
        // echo submitted DTO fields there.
        throw error
      }
    },
    [syncedDispatch]
  )

  const register = useCallback<AuthContextValue['register']>(
    async (data: RegisterInput) => {
      syncedDispatch({ type: 'SET_LOADING' })
      try {
        const result = await clientRef.current.register(data)
        syncedDispatch({ type: 'SET_USER', payload: { user: result.user, timestamp: new Date() } })
        return result
      } catch (error) {
        syncedDispatch({ type: 'SET_ERROR' })
        throw error
      }
    },
    [syncedDispatch]
  )

  const logout = useCallback<AuthContextValue['logout']>(async () => {
    try {
      await clientRef.current.logout()
    } finally {
      // Always clear local state even when the network call fails —
      // the user has asked to sign out and keeping stale state here
      // would be worse than losing the server-side revocation signal
      // (the server-side refresh rotation already invalidates the
      // refresh token on the next attempt in that scenario).
      //
      // Rejections from `client.logout()` intentionally propagate
      // after this `finally` runs so the caller learns the server
      // call did not complete. See `AuthContextValue.logout` JSDoc
      // for the documented throw contract.
      syncedDispatch({ type: 'CLEAR_SESSION' })
    }
  }, [syncedDispatch])

  const refresh = useCallback<AuthContextValue['refresh']>(async () => {
    await revalidate(false)
  }, [revalidate])

  // Empty dep arrays below are intentional: both callbacks access the
  // client via `clientRef.current` (evaluated lazily at call time, not
  // captured) and no other reactive value is closed over. Adding
  // `clientRef` to the array would be a no-op — refs have stable
  // identity — but would also mislead readers into expecting a
  // reactive dependency. If either callback is ever extended to read
  // state or props, the dep array MUST be revisited.
  const forgotPassword = useCallback<AuthContextValue['forgotPassword']>(
    async (email, tenantId) => {
      await clientRef.current.forgotPassword(email, tenantId ?? DEFAULT_TENANT_ID)
    },
    []
  )

  const resetPassword = useCallback<AuthContextValue['resetPassword']>(
    async (input: ResetPasswordInput) => {
      await clientRef.current.resetPassword(input)
    },
    []
  )

  const value = useMemo<AuthContextValue>(
    () => ({
      user: state.user,
      status: state.status,
      isLoading: state.status === 'loading',
      lastValidation: state.lastValidation,
      login,
      register,
      logout,
      refresh,
      forgotPassword,
      resetPassword
    }),
    [
      state.user,
      state.status,
      state.lastValidation,
      login,
      register,
      logout,
      refresh,
      forgotPassword,
      resetPassword
    ]
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
