/**
 * @bymax-one/nest-auth/client — Public API of the client subpath.
 *
 * Fetch-based authentication client with cookie-aware refresh, single-
 * flight dedup, and a typed wrapper for every standard auth flow.
 * Zero runtime dependencies beyond the global `fetch` and the shared
 * subpath — runs in browser, edge, and Node 24+ identically.
 */

// ---------------------------------------------------------------------------
// Fetch wrapper
// ---------------------------------------------------------------------------

export { createAuthFetch } from './createAuthFetch'
export type { AuthFetch, AuthFetchConfig } from './createAuthFetch'

// ---------------------------------------------------------------------------
// Typed client
// ---------------------------------------------------------------------------

export { createAuthClient } from './createAuthClient'
export type {
  AuthClient,
  AuthClientConfig,
  LoginInput,
  RegisterInput,
  ResetPasswordInput
} from './createAuthClient'

// ---------------------------------------------------------------------------
// Re-exports from shared
// ---------------------------------------------------------------------------
//
// Intentionally narrow re-export — only the symbols a typical client
// consumer reaches for (the thrown error class plus the error-shape
// types). Constants like `AUTH_ERROR_CODES` and `AUTH_ROUTES` stay
// behind the `@bymax-one/nest-auth/shared` import path so callers
// who need the full surface go to a single, authoritative place.
export { AuthClientError } from '@bymax-one/nest-auth/shared'
export type { AuthErrorCode, AuthErrorResponse } from '@bymax-one/nest-auth/shared'
