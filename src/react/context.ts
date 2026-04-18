/**
 * React context primitives for @bymax-one/nest-auth.
 *
 * Defines the {@link AuthStatus} discriminant, the {@link AuthContextValue}
 * surface exposed to consumers via hooks, and the {@link AuthContext}
 * instance that {@link AuthProvider} populates.
 *
 * This module is deliberately a pure context definition with no side
 * effects: the provider, hooks, and state machine live in sibling files
 * so a consumer can import types from here without pulling the runtime.
 */

import { createContext } from 'react'

import type { RegisterInput, ResetPasswordInput } from '@bymax-one/nest-auth/client'
import type { AuthResult, AuthUserClient, LoginResult } from '@bymax-one/nest-auth/shared'

/**
 * Lifecycle state of the authenticated session.
 *
 * - `'loading'`     — initial mount or in-flight revalidation; user is unknown.
 * - `'authenticated'` — a valid session exists and `user` is populated.
 * - `'unauthenticated'` — no session; `user` is `null`.
 */
export type AuthStatus = 'authenticated' | 'unauthenticated' | 'loading'

/**
 * Shape of the value published by {@link AuthContext}.
 *
 * Hooks ({@link useSession}, {@link useAuth}, {@link useAuthStatus}) read
 * from this surface. Method signatures mirror the typed client so callers
 * pass the same arguments they would to `createAuthClient` directly.
 */
export interface AuthContextValue {
  /** Authenticated user, or `null` when there is no session. */
  user: AuthUserClient | null

  /** Current lifecycle status of the session — see {@link AuthStatus}. */
  status: AuthStatus

  /**
   * Convenience flag that mirrors `status === 'loading'`. Kept as a
   * discrete field so consumers can destructure it without widening
   * their dependency on the full status union.
   */
  isLoading: boolean

  /**
   * Submit credentials to the server and update context state with the
   * resulting user on success.
   *
   * @param email    User's primary email address.
   * @param password Plaintext password — the server hashes on receipt.
   * @param options  Optional metadata. `tenantId` defaults to `'default'`
   *                 when omitted so single-tenant apps can skip it.
   *
   * @returns The discriminated {@link LoginResult} — branch on
   *   `'mfaRequired' in result` to handle the MFA challenge case.
   */
  login: (email: string, password: string, options?: { tenantId?: string }) => Promise<LoginResult>

  /**
   * Register a new account and, on success, commit the returned user
   * to the context as the active session.
   *
   * @param data Payload matching `AuthClient.register` — `email`,
   *   `password`, `name`, `tenantId` — forwarded to the server DTO
   *   unchanged.
   *
   * @returns The {@link AuthResult} returned by the server. In cookie
   *   mode `accessToken` is the empty string; in bearer mode callers
   *   must keep the token in memory only (never in storage).
   *
   * @throws {AuthClientError} When the server rejects the payload
   *   (e.g. `auth.email_already_registered`, validation failures).
   *   The context state lands in `unauthenticated` before the error
   *   is re-thrown so the caller's catch branch can update its own
   *   form-error UI.
   */
  register: (data: RegisterInput) => Promise<AuthResult>

  /**
   * Revoke the current session server-side and clear the local
   * context state.
   *
   * @throws The underlying error raised by `AuthClient.logout` when
   *   the network call fails. Local context state is STILL cleared
   *   before the error propagates — consumers can treat a rejection
   *   as "you are signed out locally, but the server revocation
   *   request did not complete" and decide whether to retry.
   *   Callers that do not care about the server-side outcome should
   *   wrap the call in a try/catch and ignore the error.
   */
  logout: () => Promise<void>

  /**
   * Force a session revalidation by calling `client.getMe()`.
   * Intended for explicit refresh flows (e.g. after an action that
   * may have changed the user's role server-side). Not required for
   * routine session maintenance — the provider handles that
   * automatically via the configured interval.
   */
  refresh: () => Promise<void>

  /**
   * Initiate a password reset. The server returns 200 regardless of
   * whether the email is registered (anti-enumeration) — treat a
   * resolved Promise as "request accepted", not "email known".
   */
  forgotPassword: (email: string, tenantId?: string) => Promise<void>

  /**
   * Submit a new password. Accepts the same discriminated-union shape
   * as `AuthClient.resetPassword` so callers can construct the input
   * with a single field — `token`, `otp`, or `verifiedToken`.
   */
  resetPassword: (input: ResetPasswordInput) => Promise<void>

  /**
   * Timestamp of the most recent successful `getMe()` call, or `null`
   * when the provider has not yet completed its initial mount.
   * Consumers can surface this to show a "last checked" indicator in
   * long-lived sessions (dashboards, admin tools).
   */
  lastValidation: Date | null
}

/**
 * The React context populated by {@link AuthProvider}.
 *
 * Default value is `null` so hooks can detect "no provider mounted" and
 * throw a descriptive error instead of handing the consumer an
 * undefined-shaped value that only explodes on first method call.
 */
export const AuthContext = createContext<AuthContextValue | null>(null)
