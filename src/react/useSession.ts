/**
 * Read-only view of the auth session for the consuming component tree.
 *
 * Companion to {@link useAuth} — this hook exposes the state part of
 * {@link AuthContextValue} (user, status, loading, last revalidation
 * timestamp, and the explicit `refresh` trigger) while {@link useAuth}
 * exposes the action part (login, register, logout, password reset).
 *
 * Splitting the two surfaces means read-heavy components (navbars,
 * profile badges, route guards) can depend on just the subset they
 * actually need and do not get re-rendered by unrelated action churn.
 */

import { useContext } from 'react'

import type { AuthUserClient } from '../shared'
import { AuthContext, type AuthStatus } from './context'

/**
 * Shape returned by {@link useSession}.
 *
 * A deliberate subset of {@link AuthContextValue}: the method surface
 * stays with {@link useAuth} so consumers of session state do not
 * accidentally couple themselves to the login/logout imperative API.
 *
 * @remarks
 * The returned object identity is not stable across renders. Treat
 * the individual fields (`user`, `status`, `lastValidation`) as the
 * correct memoization keys — never the container object itself, or
 * downstream `useMemo` / `useEffect` dependency arrays will fire on
 * every render regardless of whether the session actually changed.
 */
export interface UseSessionResult {
  /** Authenticated user, or `null` when there is no session. */
  user: AuthUserClient | null

  /** Current lifecycle status of the session — see {@link AuthStatus}. */
  status: AuthStatus

  /**
   * Convenience boolean mirroring `status === 'loading'`. Exposed as
   * a discrete field so destructuring is ergonomic in components that
   * only branch on "are we still deciding?".
   */
  isLoading: boolean

  /**
   * Force a revalidation by calling `AuthClient.getMe()` through the
   * provider. Useful after an action that may have changed the user's
   * role server-side (e.g. tenant switch). Routine freshness is
   * already handled by the provider's interval — reach for this only
   * when you need a synchronous round-trip.
   */
  refresh: () => Promise<void>

  /**
   * Timestamp of the most recent successful `getMe()` round-trip, or
   * `null` when the provider has not yet completed its initial probe.
   */
  lastValidation: Date | null
}

/**
 * Read the current session state from the {@link AuthContext}.
 *
 * @throws When called outside of an {@link AuthProvider} subtree.
 *   The descriptive message points the developer to wrap their app
 *   rather than leaving them with a `null`-based runtime failure
 *   deeper in the call stack.
 *
 * @example
 * ```tsx
 * function Navbar(): ReactNode {
 *   const { user, isLoading } = useSession()
 *   if (isLoading) return <Spinner />
 *   return user ? <UserMenu user={user} /> : <SignInButton />
 * }
 * ```
 */
export function useSession(): UseSessionResult {
  const ctx = useContext(AuthContext)
  if (ctx === null) {
    throw new Error(
      'useSession must be called within an <AuthProvider> — wrap the consuming tree in a provider built from createAuthClient().'
    )
  }
  return {
    user: ctx.user,
    status: ctx.status,
    isLoading: ctx.isLoading,
    refresh: ctx.refresh,
    lastValidation: ctx.lastValidation
  }
}
