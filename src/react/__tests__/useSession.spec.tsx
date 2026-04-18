/**
 * @jest-environment jsdom
 */

/**
 * Unit tests for {@link useSession} — the read-only view of the
 * session surface.
 *
 * Test strategy
 * -------------
 * - The hook is exercised through the real {@link AuthProvider} with
 *   a mocked {@link AuthClient}, so the test covers the end-to-end
 *   wiring (context default → provider value → hook). A stub provider
 *   would pass even if the provider/hook pair drifted apart.
 * - The outside-provider guard is verified by calling
 *   {@link renderHook} WITHOUT a wrapper, so `useContext` resolves to
 *   the default `null` and the hook must throw.
 */

import { act, renderHook } from '@testing-library/react'
import { type ReactNode } from 'react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { useSession } from '../useSession'

import { createMockClient, MOCK_USER, type MockAuthClient } from './_testHelpers'

// Helper: build a wrapper that mounts AuthProvider around the hook
// being rendered. Each test creates its own client so mock state does
// not leak across tests — jest.clearMocks in jest.config.ts already
// resets counts, but a fresh client keeps the mental model simple.
function wrap(client: MockAuthClient): ({ children }: { children: ReactNode }) => ReactNode {
  return ({ children }) => <AuthProvider client={client}>{children}</AuthProvider>
}

// ---------------------------------------------------------------------------
// useSession — inside an AuthProvider
// ---------------------------------------------------------------------------

describe('useSession — inside an AuthProvider', () => {
  // Happy path: after the provider's initial getMe resolves, the
  // hook publishes the authenticated user and the derived flags.
  it('returns user, status, isLoading, and lastValidation when authenticated', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    const { result } = renderHook(() => useSession(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current.user).toEqual(MOCK_USER)
    expect(result.current.status).toBe('authenticated')
    expect(result.current.isLoading).toBe(false)
    expect(result.current.lastValidation).toBeInstanceOf(Date)
  })

  // Before the initial probe resolves, `isLoading` is true and user
  // is null. This asserts on the very first synchronous render where
  // the reducer's INITIAL_STATE is still the current value.
  it('reports isLoading true before the initial probe resolves', () => {
    const client = createMockClient()
    // getMe returns a pending promise so the provider never leaves
    // the `loading` state during this test.
    client.getMe.mockReturnValue(new Promise(() => undefined))
    const { result } = renderHook(() => useSession(), { wrapper: wrap(client) })
    expect(result.current.isLoading).toBe(true)
    expect(result.current.status).toBe('loading')
    expect(result.current.user).toBeNull()
  })

  // The hook's `refresh` must round-trip through the provider's
  // revalidate path. We verify that calling it triggers another
  // getMe invocation.
  it('refresh triggers a fresh client.getMe call', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    const { result } = renderHook(() => useSession(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    expect(client.getMe).toHaveBeenCalledTimes(1)
    await act(async () => {
      await result.current.refresh()
    })
    expect(client.getMe).toHaveBeenCalledTimes(2)
  })

  // Unauthenticated sessions must surface with user null and the
  // unambiguous `unauthenticated` status so route guards can branch
  // without having to interpret a falsy user.
  it('reports unauthenticated when getMe fails with 401', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    const { result } = renderHook(() => useSession(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current.status).toBe('unauthenticated')
    expect(result.current.user).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// useSession — outside an AuthProvider
// ---------------------------------------------------------------------------

describe('useSession — outside an AuthProvider', () => {
  // Calling the hook without a provider must throw a descriptive
  // error naming the provider, so the mistake is immediately clear
  // in the consumer's console stack trace.
  it('throws a descriptive error when no provider is mounted', () => {
    // renderHook catches the throw inside a React error boundary;
    // to observe it directly we check `result.error`.
    const { result } = renderHook(() => {
      try {
        return useSession()
      } catch (error) {
        return error as Error
      }
    })
    expect(result.current).toBeInstanceOf(Error)
    expect((result.current as Error).message).toContain('AuthProvider')
  })
})
