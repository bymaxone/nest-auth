/**
 * Imperative action surface of the auth session.
 *
 * Companion to {@link useSession} — this hook returns the mutating
 * methods that consumers call from event handlers (login, register,
 * logout, password-reset flows). State reading lives in
 * {@link useSession}, so forms can take `useAuth()` without
 * subscribing to `user` / `status` churn unless they really need it.
 */

import { useContext } from 'react'

import { AuthContext, type AuthContextValue } from './context'

/**
 * Shape returned by {@link useAuth}. Narrows {@link AuthContextValue}
 * to its method members — state-only consumers should use
 * {@link useSession} instead so they do not re-render when an unrelated
 * action runs.
 */
export type UseAuthResult = Pick<
  AuthContextValue,
  'login' | 'register' | 'logout' | 'forgotPassword' | 'resetPassword'
>

/**
 * Read the session-mutating methods from the {@link AuthContext}.
 *
 * @throws When called outside of an {@link AuthProvider} subtree. A
 *   typed error makes the misuse immediately actionable instead of
 *   surfacing as an undefined-method runtime failure inside a
 *   component handler.
 *
 * @example
 * ```tsx
 * function LoginForm(): ReactNode {
 *   const { login } = useAuth()
 *   return (
 *     <form
 *       onSubmit={async (event) => {
 *         event.preventDefault()
 *         await login(email, password)
 *       }}
 *     >
 *       ...
 *     </form>
 *   )
 * }
 * ```
 */
export function useAuth(): UseAuthResult {
  const ctx = useContext(AuthContext)
  if (ctx === null) {
    throw new Error(
      'useAuth must be called within an <AuthProvider> — wrap the consuming tree in a provider built from createAuthClient().'
    )
  }
  return {
    login: ctx.login,
    register: ctx.register,
    logout: ctx.logout,
    forgotPassword: ctx.forgotPassword,
    resetPassword: ctx.resetPassword
  }
}
