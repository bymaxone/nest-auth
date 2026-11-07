/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * `AuthProvider` — recognizing the client error when it comes from another copy of its class.
 *
 * The package ships an ESM and a CJS build, and an application that loads the client through one
 * and the provider through the other holds two copies of `AuthClientError`, so `instanceof` is
 * false between them. The provider decides by the error's name and numeric status, so a session
 * the server has ended is still reported as expired. Kept apart from `AuthProvider.spec.tsx`
 * because that file is over the size limit.
 */

import { act, renderHook } from '@testing-library/react'
import { useContext, type ReactNode } from 'react'

import { AuthProvider } from '../AuthProvider'
import { AuthContext, type AuthContextValue } from '../context'

import { createMockClient, MOCK_USER } from './_testHelpers'

/** An `AuthClientError` as another copy of the class makes it: same name and status, other identity. */
class ForeignAuthClientError extends Error {
  readonly status: number
  constructor(status: number) {
    super(`Request failed with status ${status}`)
    this.name = 'AuthClientError'
    this.status = status
  }
}

describe('AuthProvider — a revalidation that fails with a foreign-copy client error', () => {
  /** Mounts an authenticated provider whose next `getMe` fails with `failure`, then refreshes. */
  async function refreshFailingWith(failure: Error) {
    const onSessionExpired = jest.fn()
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    const { result } = renderHook<AuthContextValue | null, unknown>(() => useContext(AuthContext), {
      wrapper: ({ children }: { children: ReactNode }) => (
        <AuthProvider client={client} onSessionExpired={onSessionExpired}>
          {children}
        </AuthProvider>
      )
    })
    await act(async () => {
      await Promise.resolve()
    })
    expect(result.current?.status).toBe('authenticated')
    client.getMe.mockRejectedValueOnce(failure)
    await act(async () => {
      await result.current?.refresh()
    })
    return { result, onSessionExpired }
  }

  // Scenario: the session is gone and the 401 comes from another copy of the error class.
  // Expected: the context clears the session and `onSessionExpired` fires once. Why: with an
  // `instanceof` check the 401 reads as an unrelated failure and the host's sign-in redirect never
  // runs.
  it('reports a session expired by a 401 from another copy of the class', async () => {
    const { result, onSessionExpired } = await refreshFailingWith(new ForeignAuthClientError(401))

    expect(onSessionExpired).toHaveBeenCalledTimes(1)
    expect(result.current?.status).toBe('unauthenticated')
  })

  // Scenario: a 500 from another copy. Expected: no expiry callback, as for the same copy.
  it('does not report a session expired by a 500 from another copy of the class', async () => {
    const { onSessionExpired } = await refreshFailingWith(new ForeignAuthClientError(500))

    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // Scenario: a plain Error that happens to carry the status but not the name. Expected: it is not
  // taken for a client error, so no expiry callback.
  it('does not take an unrelated error with a status for a client error', async () => {
    const lookalike = Object.assign(new Error('boom'), { status: 401 })

    const { onSessionExpired } = await refreshFailingWith(lookalike)

    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // Scenario: an error carrying the client error's name but no numeric status (a string, or none).
  // Expected: it is not taken for a client error, so no expiry callback. Why: only a numeric status
  // can be compared against the statuses the provider acts on.
  it.each([
    ['a string status', { status: '401' }],
    ['no status', {}]
  ])('does not take a named error with %s for a client error', async (_label, extra) => {
    const named = Object.assign(new Error('boom'), { name: 'AuthClientError' }, extra)

    const { onSessionExpired } = await refreshFailingWith(named)

    expect(onSessionExpired).not.toHaveBeenCalled()
  })
})
