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

import React, { useCallback, useEffect, useMemo, useReducer, useRef, type ReactNode } from 'react'

import type { AuthClient, RegisterInput, ResetPasswordInput } from '@bymax-one/nest-auth/client'
import type { AuthUserClient, LoginResult } from '@bymax-one/nest-auth/shared'

import { AuthContext, type AuthContextValue, type AuthStatus } from './context'

/**
 * Default revalidation cadence — 5 minutes.
 *
 * Balances "detect revoked sessions quickly" against "do not burn
 * battery on an idle tab". Tune via the `revalidateInterval` prop when
 * a deployment has different freshness requirements.
 */
const DEFAULT_REVALIDATE_INTERVAL_MS = 300_000

/** The lowest status the provider takes for an HTTP answer. */
const HTTP_STATUS_MIN = 100

/**
 * The HTTP status of a client error, or `undefined` when `error` is not one.
 *
 * A client error is an object named `AuthClientError` whose `status` is an integer of at least 100.
 * Anything else, such as a missing, fractional, non-finite, below-100 or non-numeric status, is not
 * a server answer, so no decision below acts on it. There is no upper bound: every decision below
 * treats a status of 500 or more as unconfirmed, so a bound there could not change one.
 *
 * It is recognized by name, not by `instanceof`: a client and a provider loaded as different
 * module formats of the package (the ESM and the CJS build) hold different copies of the class, and
 * `instanceof` is false across them. Every decision that reads a status goes through here, so none
 * of them depends on which copy raised the error.
 */
function clientErrorStatus(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const { name, status } = error as { name?: unknown; status?: unknown }
  if (name !== 'AuthClientError' || !Number.isInteger(status)) return undefined
  const code = status as number
  return code >= HTTP_STATUS_MIN ? code : undefined
}

/**
 * Whether a rejected `client.logout()` carries a final server answer: a client error with a
 * status below 500 other than 429. The status 429 is the logout route's throttle, which answers
 * before anything is revoked, so the session is still alive. Anything else (a 5xx, a 429, a
 * network failure, an abort) leaves the logout unconfirmed.
 */
function isFinalAnswer(error: unknown): boolean {
  const status = clientErrorStatus(error)
  return status !== undefined && status < 500 && status !== 429
}

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
  return clientErrorStatus(error) === 401
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
  // Bumped by every DELIBERATE session transition — logout, login, register. `revalidate`
  // reads it before its request and drops its own result if it moved while the request was in
  // flight.
  //
  // A fresh OBJECT rather than a counter: the value's whole meaning is its identity, and
  // nothing reads it as a number. An incrementing counter invites the question of what a
  // decrement or a wrap would mean — questions with no answer here, and which no test can
  // settle, because any change to the value works equally well.
  //
  // Without it, a `getMe()` started before a logout and answered after it resurrected the
  // session: `logout()` dispatched `CLEAR_SESSION`, the UI showed signed-out, and then the
  // in-flight response — a legitimate 200, issued before the server revoked anything —
  // dispatched `SET_USER` unconditionally. `status` went back to `authenticated`, the profile
  // returned to context, and `useAuthStatus().isAuthenticated`, which this library's own
  // JSDoc calls safe to gate protected routes on, answered `true` again. On a shared or kiosk
  // machine that renders the previous person's account to the next one.
  //
  // The window is one round trip, and the five-minute interval tick and any focus-triggered
  // `refresh()` both open it without the user doing anything unusual.
  const sessionGenerationRef = useRef<object>({})

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
  // Stryker disable ArrayDeclaration: the dependency arrays below hold only referentially
  // stable values, so adding, removing or replacing an entry cannot change memoization or
  // how often an effect re-runs. The per-line form of this directive does not bind when the
  // array shares its line with the callback's closing brace, hence the block form.
  const syncedDispatch = useCallback((action: AuthAction): void => {
    dispatch(action)
    switch (action.type) {
      case 'SET_USER':
        statusRef.current = 'authenticated'
        return
      // Stryker disable next-line ConditionalExpression: reducer case label; the SET_LOADING and tick paths are exercised elsewhere and this case's presence does not change the dispatched-state outcome under test
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
      // Captured before the request; compared after it. A deliberate transition that lands in
      // between makes this result stale, and a stale result must not be applied in either
      // direction — not the user on success, and not `onSessionExpired` on a 401 for a
      // session the caller already ended.
      const generation = sessionGenerationRef.current
      try {
        const user = await clientRef.current.getMe()
        if (sessionGenerationRef.current !== generation) return
        syncedDispatch({ type: 'SET_USER', payload: { user, timestamp: new Date() } })
      } catch (error) {
        if (sessionGenerationRef.current !== generation) return
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
    // Stryker disable next-line BooleanLiteral: `isInitial` is only read via `!isInitial && wasAuthenticated`; at this mount call site wasAuthenticated is structurally false, so true vs false is unobservable
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
      syncedDispatch({ type: 'SET_LOADING' })
      try {
        // Spread rather than assign, so an omitted tenant is an absent KEY — the same rule
        // `createAuthClient` applies on `forgotPassword` and `resetPassword`. It is not
        // cosmetic: the server distinguishes "the caller named no tenant" from "the caller
        // named one", and a deployment configuring `tenantIdResolver` REFUSES the second with
        // `400 auth.validation`. A fallback here would name a tenant on the caller's behalf
        // and make every login under a resolver unanswerable.
        const result: LoginResult = await clientRef.current.login({
          email,
          password,
          ...(options?.tenantId !== undefined ? { tenantId: options.tenantId } : {})
        })
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
          //
          // The generation moves here for the same reason it moves on logout: this IS a
          // deliberate transition, and a `getMe()` issued before it answers for the session
          // that was live beforehand. Applying that answer while the challenge is pending puts
          // the PREVIOUS user back into context and flips `isAuthenticated` to `true` — which
          // this library's own JSDoc calls safe to gate protected routes on — so the route
          // guards reopen on the session the second factor was supposed to stand in front of.
          sessionGenerationRef.current = {}
          syncedDispatch({ type: 'CLEAR_SESSION' })
          return result
        }
        // Same reason as logout: a `getMe()` issued before this call answers for the PREVIOUS
        // session, and applying it would overwrite the identity just established.
        sessionGenerationRef.current = {}
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
        // Same reason as logout: a `getMe()` issued before this call answers for the PREVIOUS
        // session, and applying it would overwrite the identity just established.
        sessionGenerationRef.current = {}
        syncedDispatch({ type: 'SET_USER', payload: { user: result.user, timestamp: new Date() } })
        return result
      } catch (error) {
        syncedDispatch({ type: 'SET_ERROR' })
        throw error
      }
    },
    [syncedDispatch]
  )

  // A deliberate session transition: bumped BEFORE the dispatch so a `getMe()` already in flight
  // is discarded when it lands, or it re-authenticates a session the user just ended.
  const clearSession = useCallback((): void => {
    sessionGenerationRef.current = {}
    syncedDispatch({ type: 'CLEAR_SESSION' })
  }, [syncedDispatch])

  const logout = useCallback<AuthContextValue['logout']>(async () => {
    // Rule, by what `client.logout()` did:
    //   - resolved: the session is revoked, so the local state clears;
    //   - rejected with an `AuthClientError` whose status is below 500 and not 429: the server
    //     gave a final answer (the session is gone or was never valid, and the proxy has cleared
    //     the cookies), so the local state clears and the rejection propagates;
    //   - rejected with a 5xx (502 included), a 429 (the route's throttle, answered before
    //     anything is revoked) or with anything that is not an `AuthClientError` (a network
    //     failure, an abort): the server never confirmed the logout and the session
    //     may be alive, so the state stays authenticated and the rejection propagates for
    //     the caller to offer a retry. Showing signed-out there would be false on a shared
    //     machine, where the next person finds a live session.
    try {
      await clientRef.current.logout()
    } catch (error) {
      if (!isFinalAnswer(error)) throw error
      clearSession()
      throw error
    }
    clearSession()
  }, [clearSession])

  const refresh = useCallback<AuthContextValue['refresh']>(async () => {
    await revalidate(false)
  }, [revalidate])
  // Stryker restore ArrayDeclaration

  // Empty dep arrays below are intentional: both callbacks access the
  // client via `clientRef.current` (evaluated lazily at call time, not
  // captured) and no other reactive value is closed over. Adding
  // `clientRef` to the array would be a no-op — refs have stable
  // identity — but would also mislead readers into expecting a
  // reactive dependency. If either callback is ever extended to read
  // state or props, the dep array MUST be revisited.
  const forgotPassword = useCallback<AuthContextValue['forgotPassword']>(
    async (email, tenantId) => {
      // Passed through as-is for the reason `login` spells out: `createAuthClient` already
      // turns an absent tenant into an absent key, and defaulting one here would be refused
      // by any deployment that configures `tenantIdResolver`.
      await clientRef.current.forgotPassword(email, tenantId)
    },
    // Stryker disable next-line ArrayDeclaration: empty deps array with only stable references in scope; a constant-string array re-runs identically
    []
  )

  const resetPassword = useCallback<AuthContextValue['resetPassword']>(
    async (input: ResetPasswordInput) => {
      await clientRef.current.resetPassword(input)
    },
    // Stryker disable next-line ArrayDeclaration: empty deps array with only stable references in scope; a constant-string array re-runs identically
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
