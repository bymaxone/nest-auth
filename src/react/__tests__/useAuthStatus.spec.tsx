/**
 * @jest-environment jsdom
 */

/**
 * Unit tests for {@link useAuthStatus} — the binary-flag convenience
 * view built on top of {@link useSession}.
 *
 * Test strategy
 * -------------
 * - Exercised through the real {@link AuthProvider} with a mocked
 *   client, covering each of the three `AuthStatus` values once:
 *   `loading`, `authenticated`, `unauthenticated`. The truth table
 *   for the two derived booleans is verified in full so a future
 *   status-value addition fails the suite visibly.
 */

import { act, renderHook } from '@testing-library/react'
import { type ReactNode } from 'react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { useAuthStatus } from '../useAuthStatus'

import { createMockClient, MOCK_USER, type MockAuthClient } from './_testHelpers'

function wrap(client: MockAuthClient): ({ children }: { children: ReactNode }) => ReactNode {
  return ({ children }) => <AuthProvider client={client}>{children}</AuthProvider>
}

// ---------------------------------------------------------------------------
// useAuthStatus — binary flag truth table
// ---------------------------------------------------------------------------

describe('useAuthStatus — flag truth table', () => {
  // When the provider is still probing, isLoading is true and
  // isAuthenticated is false — the "still figuring it out" state
  // that route guards must show a skeleton for.
  it('reports isLoading=true, isAuthenticated=false while probing', () => {
    const client = createMockClient()
    client.getMe.mockReturnValue(new Promise(() => undefined))
    const { result } = renderHook(() => useAuthStatus(), { wrapper: wrap(client) })
    expect(result.current.isLoading).toBe(true)
    expect(result.current.isAuthenticated).toBe(false)
  })

  // Authenticated state flips isAuthenticated to true and keeps
  // isLoading false — the state route guards open access on.
  it('reports isLoading=false, isAuthenticated=true when authenticated', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    const { result } = renderHook(() => useAuthStatus(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.isAuthenticated).toBe(true)
  })

  // Unauthenticated state: both flags false. This is the steady
  // "signed out" view — guards redirect to sign-in.
  it('reports both flags false when unauthenticated', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    const { result } = renderHook(() => useAuthStatus(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current.isLoading).toBe(false)
    expect(result.current.isAuthenticated).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// useAuthStatus — delegation and provider guard
// ---------------------------------------------------------------------------

describe('useAuthStatus — misuse', () => {
  // useAuthStatus is built on useSession, so using it outside a
  // provider must inherit the same descriptive error. This guards
  // against a future implementation split that forgets to route
  // through the inner hook's guard.
  it('throws when used outside an AuthProvider (inherited from useSession)', () => {
    const { result } = renderHook(() => {
      try {
        return useAuthStatus()
      } catch (error) {
        return error as Error
      }
    })
    expect(result.current).toBeInstanceOf(Error)
    expect((result.current as Error).message).toContain('AuthProvider')
  })
})
