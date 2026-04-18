/**
 * @bymax-one/nest-auth/react — Public API of the React subpath.
 *
 * AuthProvider + three hooks that wire the typed `AuthClient` from
 * `@bymax-one/nest-auth/client` into a React component tree. The
 * surface is narrow on purpose: everything a standard app needs for
 * session-aware rendering and auth flows, and nothing that would tie
 * consumers to implementation details of the provider.
 *
 * Peer dependency: `react ^19`. Zero other runtime dependencies.
 */

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export { AuthProvider } from './AuthProvider'
export type { AuthProviderProps } from './AuthProvider'

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export { useSession } from './useSession'
export type { UseSessionResult } from './useSession'

export { useAuth } from './useAuth'
export type { UseAuthResult } from './useAuth'

export { useAuthStatus } from './useAuthStatus'
export type { UseAuthStatusResult } from './useAuthStatus'

// ---------------------------------------------------------------------------
// Context types
// ---------------------------------------------------------------------------
//
// The `AuthContext` runtime value is intentionally NOT re-exported —
// consumers should always go through the hooks (which include the
// "used outside provider" guard). Only the shape types are public so
// that custom wrappers and higher-order components can annotate
// themselves against the provider's value.
export type { AuthContextValue, AuthStatus } from './context'
