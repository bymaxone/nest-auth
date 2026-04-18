/**
 * Binary-flag convenience view of the auth session.
 *
 * Most route guards and conditional renders only need two pieces of
 * information: "are we still figuring it out?" and "is the user
 * signed in?". This hook collapses {@link useSession}'s status union
 * into those two booleans so consumers can skip the string-compare
 * boilerplate and so a future rename of the status union stays
 * contained inside {@link useSession}.
 */

import { useSession } from './useSession'

/**
 * Shape returned by {@link useAuthStatus}.
 *
 * The two booleans are mutually independent — it is legal (and
 * expected during the initial probe) to have both `isAuthenticated`
 * and `isLoading` be `false`, representing "not signed in, no probe
 * in flight".
 */
export interface UseAuthStatusResult {
  /**
   * `true` only when the session status is `'authenticated'`. Safe
   * to use as the gate for protected-route guards and "signed-in only"
   * UI — a `loading` or `unauthenticated` status correctly evaluates
   * to `false`.
   */
  isAuthenticated: boolean

  /**
   * `true` only when the session status is `'loading'`. Use it to
   * show a skeleton or spinner while the provider completes its
   * initial probe or an explicit `refresh()` — the `authenticated`
   * and `unauthenticated` states both evaluate to `false`.
   */
  isLoading: boolean
}

/**
 * Derive the two binary session flags from {@link useSession}.
 *
 * @throws When called outside of an {@link AuthProvider} subtree.
 *   The error propagates from {@link useSession}, so the same
 *   descriptive message applies.
 *
 * @example
 * ```tsx
 * function ProtectedRoute({ children }: { children: ReactNode }): ReactNode {
 *   const { isAuthenticated, isLoading } = useAuthStatus()
 *   if (isLoading) return <Spinner />
 *   if (!isAuthenticated) return <Navigate to="/sign-in" />
 *   return <>{children}</>
 * }
 * ```
 */
export function useAuthStatus(): UseAuthStatusResult {
  const { status, isLoading } = useSession()
  return {
    isAuthenticated: status === 'authenticated',
    isLoading
  }
}
