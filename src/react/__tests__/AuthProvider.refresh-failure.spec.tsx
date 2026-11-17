/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * What an explicit `refresh()` answers when the server could not confirm the session. A caller that
 * awaits it after an action that may have changed the account reads the state next, so a resolved
 * promise over a failed revalidation hands it a user it has no reason to distrust. A failure the
 * server did not decide rejects and leaves the state as it was; an answer the server did decide
 * (a 401 or another final answer) is a state change and resolves.
 */

import { act, renderHook } from '@testing-library/react'
import { useContext, type ReactNode } from 'react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { AuthContext, type AuthContextValue } from '../context'

import { createMockClient, MOCK_USER, type MockAuthClient } from './_testHelpers'

function mount(client: MockAuthClient, onSessionExpired?: () => void) {
  const wrapper = ({ children }: { children: ReactNode }): ReactNode => (
    <AuthProvider
      client={client}
      revalidateInterval={0}
      {...(onSessionExpired !== undefined ? { onSessionExpired } : {})}
    >
      {children}
    </AuthProvider>
  )
  return renderHook(() => useContext(AuthContext) as AuthContextValue, { wrapper })
}

/** Signs in through the mount probe, then makes the next `getMe` fail with `failure`. */
async function signedInThenFailing(failure: unknown, onSessionExpired?: () => void) {
  const client = createMockClient()
  client.getMe.mockResolvedValueOnce(MOCK_USER)
  const view = mount(client, onSessionExpired)
  await act(async () => {
    await Promise.resolve()
  })
  expect(view.result.current.status).toBe('authenticated')
  client.getMe.mockRejectedValueOnce(failure)
  return view
}

describe('AuthProvider refresh() when the server could not confirm', () => {
  // Scenario: a 5xx, a throttle, a network failure and an abort. Expected: the promise rejects with
  // that same error, the session stays authenticated with the same user, and no expiry is signalled.
  // Why: none of them says anything about the session, so the caller must be told it was not checked.
  it.each([
    ['a 503', new AuthClientError('unavailable', 503)],
    ['a 502', new AuthClientError('bad gateway', 502)],
    ['a 429', new AuthClientError('throttled', 429)],
    ['a network failure', new TypeError('Failed to fetch')],
    ['an abort', new DOMException('aborted', 'AbortError')]
  ])('rejects with the failure and keeps the session after %s', async (_label, failure) => {
    const onSessionExpired = jest.fn()
    const { result } = await signedInThenFailing(failure, onSessionExpired)

    let caught: unknown
    await act(async () => {
      await result.current.refresh().catch((error: unknown) => {
        caught = error
      })
    })

    expect(caught).toBe(failure)
    expect(result.current.status).toBe('authenticated')
    expect(result.current.user).toEqual(MOCK_USER)
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // Scenario: the server decided. Expected: refresh resolves and the state carries the answer.
  it('resolves and clears the session on a 401, signalling the expiry once', async () => {
    const onSessionExpired = jest.fn()
    const { result } = await signedInThenFailing(
      new AuthClientError('unauthorized', 401),
      onSessionExpired
    )

    await act(async () => {
      await result.current.refresh()
    })

    expect(result.current.status).toBe('unauthenticated')
    expect(onSessionExpired).toHaveBeenCalledTimes(1)
  })

  it('resolves and signs the user out on another final answer', async () => {
    const { result } = await signedInThenFailing(new AuthClientError('forbidden', 403))

    await act(async () => {
      await result.current.refresh()
    })

    expect(result.current.status).toBe('unauthenticated')
    expect(result.current.user).toBeNull()
  })

  it('resolves with the new user on success', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    const { result } = mount(client)
    await act(async () => {
      await Promise.resolve()
    })
    const fresh = { ...MOCK_USER, name: 'Renamed' }
    client.getMe.mockResolvedValueOnce(fresh)

    await act(async () => {
      await result.current.refresh()
    })

    expect(result.current.user).toEqual(fresh)
  })

  // Scenario: no session yet, and the probe cannot reach the server. Expected: refresh resolves, as
  // the state (`unauthenticated`) already says so. Why: nothing was left "as it was" to be fooled by.
  it('resolves when no session was established and the probe fails', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValue(new TypeError('Failed to fetch'))
    const { result } = mount(client)
    await act(async () => {
      await Promise.resolve()
    })

    await act(async () => {
      await result.current.refresh()
    })

    expect(result.current.status).toBe('unauthenticated')
  })

  // Scenario: the user ends the session while a refresh is in flight, and the refresh then fails.
  // Expected: it resolves. Why: the result is stale and applies to nothing the caller holds.
  it('resolves when the session was ended while the refresh was in flight', async () => {
    const client = createMockClient()
    client.getMe.mockResolvedValueOnce(MOCK_USER)
    const { result } = mount(client)
    await act(async () => {
      await Promise.resolve()
    })
    let fail: (error: unknown) => void = () => undefined
    client.getMe.mockReturnValueOnce(new Promise((_resolve, reject) => (fail = reject)))
    let pending: Promise<void> = Promise.resolve()
    await act(async () => {
      pending = result.current.refresh()
      await result.current.logout()
      fail(new TypeError('Failed to fetch'))
    })

    await expect(pending).resolves.toBeUndefined()
    expect(result.current.status).toBe('unauthenticated')
  })
})
