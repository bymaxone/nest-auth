/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * `AuthProvider.logout` — what the session state says when the server logout did not complete.
 *
 * A logout the server could not complete leaves the session alive, so the provider keeps the
 * authenticated state and rethrows: the UI must not read signed-out while the session persists,
 * and the caller needs the rejection to offer a retry. A final answer below 500 means the
 * session is gone (or was never valid), so the state clears. Kept apart from
 * `AuthProvider.spec.tsx` because that file is over the size limit.
 */

import { act, renderHook } from '@testing-library/react'
import { useContext, type ReactNode } from 'react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { AuthContext, type AuthContextValue } from '../context'

import { createMockClient, MOCK_USER, type MockAuthClient } from './_testHelpers'

/** Renders the provider and returns the live context after the initial probe settled. */
async function renderAuthenticated(client: MockAuthClient) {
  client.getMe.mockResolvedValue(MOCK_USER)
  const rendered = renderHook<AuthContextValue | null, unknown>(() => useContext(AuthContext), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <AuthProvider client={client}>{children}</AuthProvider>
    )
  })
  await act(async () => {
    await Promise.resolve()
  })
  expect(rendered.result.current?.status).toBe('authenticated')
  return rendered
}

/** A rejection the way `AuthClient.logout` raises one for a non-2xx answer. */
function answered(status: number): AuthClientError {
  return new AuthClientError(`Request failed with status ${status}`, status)
}

describe('AuthProvider.logout — a server logout that did not complete', () => {
  // Scenario: the proxy or server answers 5xx/502, or the request fails before any answer.
  // Expected: the caller gets the rejection and the context still says authenticated with the
  // same user. Why: the session is alive; showing signed-out would be false on a shared machine.
  it.each([
    ['a 500', answered(500)],
    ['a 502', answered(502)],
    ['a 503', answered(503)],
    ['a 429', answered(429)],
    ['a network failure', new TypeError('fetch failed')]
  ])('keeps the authenticated state and rethrows on %s', async (_label, failure) => {
    const client = createMockClient()
    client.logout.mockRejectedValue(failure)
    const { result } = await renderAuthenticated(client)

    await act(async () => {
      await expect(result.current?.logout()).rejects.toBe(failure)
    })

    expect(result.current?.status).toBe('authenticated')
    expect(result.current?.user).toEqual(MOCK_USER)
  })

  // Scenario: the answer is final and below 500. Expected: the state clears and the rejection
  // still reaches the caller. Why: the session is gone or was never valid, and the proxy has
  // cleared the cookies, so signed-out is the true state.
  it.each([400, 401, 403, 404, 428, 430, 499])(
    'clears the state and rethrows on a final %i answer',
    async (status) => {
      const client = createMockClient()
      const failure = answered(status)
      client.logout.mockRejectedValue(failure)
      const { result } = await renderAuthenticated(client)

      await act(async () => {
        await expect(result.current?.logout()).rejects.toBe(failure)
      })

      expect(result.current?.status).toBe('unauthenticated')
      expect(result.current?.user).toBeNull()
    }
  )

  // Scenario: the rejection comes from a second copy of the error class, as it does when the
  // client and the provider load different module formats of the package. Expected: the same
  // decision by name and status. Why: `instanceof` is false across copies, which would read every
  // 4xx as "unconfirmed" and keep a session the server has already ended.
  it.each([
    [401, 'unauthenticated'],
    [429, 'authenticated'],
    [503, 'authenticated']
  ] as const)(
    'decides a foreign-copy %i rejection by name and status',
    async (status, expected) => {
      class ForeignAuthClientError extends Error {
        readonly status: number
        constructor(code: number) {
          super(`Request failed with status ${code}`)
          this.name = 'AuthClientError'
          this.status = code
        }
      }
      const client = createMockClient()
      client.logout.mockRejectedValue(new ForeignAuthClientError(status))
      const { result } = await renderAuthenticated(client)

      await act(async () => {
        await expect(result.current?.logout()).rejects.toThrow()
      })

      expect(result.current?.status).toBe(expected)
    }
  )

  // Scenario: a rejection that carries the client error's name but no numeric status (a string,
  // or none). Expected: it is unconfirmed, so the context stays authenticated and the error is
  // rethrown. Why: only a numeric status can say the server gave a final answer.
  it.each([
    ['a string status', { status: '401' }],
    ['no status', {}]
  ])('keeps the authenticated state for a named error with %s', async (_label, extra) => {
    const named = Object.assign(new Error('boom'), { name: 'AuthClientError' }, extra)
    const client = createMockClient()
    client.logout.mockRejectedValue(named)
    const { result } = await renderAuthenticated(client)

    await act(async () => {
      await expect(result.current?.logout()).rejects.toBe(named)
    })

    expect(result.current?.status).toBe('authenticated')
  })

  // Scenario: a retry after the failure succeeds. Expected: the state clears and the call
  // resolves. Why: keeping the state on failure exists to make this retry possible.
  it('clears the state when a retry after a failed logout succeeds', async () => {
    const client = createMockClient()
    client.logout.mockRejectedValueOnce(answered(503)).mockResolvedValueOnce(undefined)
    const { result } = await renderAuthenticated(client)

    await act(async () => {
      await expect(result.current?.logout()).rejects.toThrow()
    })
    expect(result.current?.status).toBe('authenticated')
    await act(async () => {
      await result.current?.logout()
    })

    expect(result.current?.status).toBe('unauthenticated')
    expect(client.logout).toHaveBeenCalledTimes(2)
  })

  // Scenario: a session probe that was already in flight when the failed logout landed.
  // Expected: its answer is applied. Why: a failed logout is not a deliberate session
  // transition, and discarding the probe would leave the state stale for a whole interval.
  it('applies a probe that was in flight across a failed logout', async () => {
    const client = createMockClient()
    client.logout.mockRejectedValue(answered(503))
    const { result } = await renderAuthenticated(client)
    let resolveProbe: (user: typeof MOCK_USER) => void = () => undefined
    client.getMe.mockReturnValueOnce(
      new Promise<typeof MOCK_USER>((resolve) => {
        resolveProbe = resolve
      })
    )
    const refreshing = result.current?.refresh()

    await act(async () => {
      await expect(result.current?.logout()).rejects.toThrow()
      resolveProbe({ ...MOCK_USER, name: 'Renamed' })
      await refreshing
    })

    expect(result.current?.status).toBe('authenticated')
    expect(result.current?.user?.name).toBe('Renamed')
  })
})
