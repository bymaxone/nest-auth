/**
 * @jest-environment jsdom
 */

/**
 * Unit tests for {@link useAuth} — the action surface of the session.
 *
 * Test strategy
 * -------------
 * - Exercised through the real {@link AuthProvider} with a mocked
 *   client so each method's pass-through to the typed client is
 *   verified end-to-end.
 * - The outside-provider guard is tested with a `renderHook` call
 *   that has no wrapper, so the context defaults to `null` and the
 *   hook must throw.
 */

import { act, renderHook } from '@testing-library/react'
import { type ReactNode } from 'react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { useAuth } from '../useAuth'

import { createMockClient, MOCK_AUTH_RESULT, MOCK_USER, type MockAuthClient } from './_testHelpers'

// Wrapper factory. Mirrors the one in useSession.spec.tsx so the two
// suites stay symmetric.
function wrap(client: MockAuthClient): ({ children }: { children: ReactNode }) => ReactNode {
  return ({ children }) => <AuthProvider client={client}>{children}</AuthProvider>
}

// ---------------------------------------------------------------------------
// useAuth — inside an AuthProvider
// ---------------------------------------------------------------------------

describe('useAuth — inside an AuthProvider', () => {
  // Surface check: the hook exposes exactly the five action methods
  // from the context. If a future refactor adds/removes a method,
  // this assertion flags the shape change.
  it('returns the five action methods', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    const { result } = renderHook(() => useAuth(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    expect(typeof result.current.login).toBe('function')
    expect(typeof result.current.register).toBe('function')
    expect(typeof result.current.logout).toBe('function')
    expect(typeof result.current.forgotPassword).toBe('function')
    expect(typeof result.current.resetPassword).toBe('function')
  })

  // login pass-through: calling the hook's login must forward the
  // payload to client.login and resolve to the client's result.
  it('login delegates to client.login and returns the result', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.login.mockResolvedValue(MOCK_AUTH_RESULT)
    const { result } = renderHook(() => useAuth(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    let returned: unknown
    await act(async () => {
      returned = await result.current.login('a@b.test', 'pw', { tenantId: 'acme' })
    })
    expect(client.login).toHaveBeenCalledWith({
      email: 'a@b.test',
      password: 'pw',
      tenantId: 'acme'
    })
    expect(returned).toEqual(MOCK_AUTH_RESULT)
  })

  // logout pass-through: the hook must route through client.logout.
  // The provider's finally-always-clear semantics are covered by
  // AuthProvider.spec.tsx; here we only verify the dispatch.
  it('logout delegates to client.logout', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValue(MOCK_USER)
    client.logout.mockResolvedValue(undefined)
    const { result } = renderHook(() => useAuth(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current.logout()
    })
    expect(client.logout).toHaveBeenCalledTimes(1)
  })

  // register pass-through + return value.
  it('register delegates to client.register and returns the result', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.register.mockResolvedValue(MOCK_AUTH_RESULT)
    const { result } = renderHook(() => useAuth(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    const payload = {
      email: 'new@example.test',
      password: 'pw',
      name: 'New User',
      tenantId: 'default'
    }
    let returned: unknown
    await act(async () => {
      returned = await result.current.register(payload)
    })
    expect(client.register).toHaveBeenCalledWith(payload)
    expect(returned).toEqual(MOCK_AUTH_RESULT)
  })

  // forgotPassword pass-through with default tenant.
  it('forgotPassword delegates to client.forgotPassword', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.forgotPassword.mockResolvedValue(undefined)
    const { result } = renderHook(() => useAuth(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      await result.current.forgotPassword('a@b.test', 'acme')
    })
    expect(client.forgotPassword).toHaveBeenCalledWith('a@b.test', 'acme')
  })

  // resetPassword pass-through covers the OTP variant of the
  // discriminated-union input, guarding against a regression where
  // one of the three variants stops reaching the client.
  it('resetPassword delegates to client.resetPassword (OTP variant)', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new AuthClientError('unauthorized', 401))
    client.resetPassword.mockResolvedValue(undefined)
    const { result } = renderHook(() => useAuth(), { wrapper: wrap(client) })
    await act(async () => {
      await Promise.resolve()
    })
    const input = {
      email: 'a@b.test',
      tenantId: 'default',
      newPassword: 'newpw',
      otp: '123456'
    } as const
    await act(async () => {
      await result.current.resetPassword(input)
    })
    expect(client.resetPassword).toHaveBeenCalledWith(input)
  })
})

// ---------------------------------------------------------------------------
// useAuth — outside an AuthProvider
// ---------------------------------------------------------------------------

describe('useAuth — outside an AuthProvider', () => {
  // Using useAuth without a provider must fail early with a
  // descriptive error — the alternative (silently returning an
  // undefined surface) would surface as opaque method-on-undefined
  // crashes inside a component handler.
  it('throws a descriptive error when no provider is mounted', () => {
    const { result } = renderHook(() => {
      try {
        return useAuth()
      } catch (error) {
        return error as Error
      }
    })
    expect(result.current).toBeInstanceOf(Error)
    expect((result.current as Error).message).toContain('AuthProvider')
  })
})
