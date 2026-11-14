/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * What `AuthProvider` does when a background revalidation of a signed-in user fails.
 *
 * Only an answer that says this session is not valid signs the user out: a final answer, a 4xx
 * other than 429. A server that is down or restarting (503, 500, 502, 504), a throttle (429) and a
 * network failure (`fetch` rejecting with a `TypeError`) say nothing about the session, so the user
 * and the state stay and the next tick tries again. The first check of a page load has no
 * established session to retain, so a failure there reports `unauthenticated`.
 */

import { act, render } from '@testing-library/react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'
import { useSession } from '../useSession'

import { createMockClient, MOCK_USER } from './_testHelpers'

/** Renders the status and the user's email, so a test reads them from the DOM. */
function Probe() {
  const { status, user } = useSession()
  return <div data-testid="state">{`${status}:${user?.email ?? 'none'}`}</div>
}

/** Mounts a signed-in provider, then lets one revalidation tick fail with `error`. */
async function tickWith(error: unknown) {
  const client = createMockClient()
  client.getMe.mockResolvedValueOnce(MOCK_USER)
  const onSessionExpired = jest.fn()
  const view = render(
    <AuthProvider client={client} onSessionExpired={onSessionExpired} revalidateInterval={1000}>
      <Probe />
    </AuthProvider>
  )
  await act(async () => {
    await Promise.resolve()
  })
  client.getMe.mockRejectedValueOnce(error)
  await act(async () => {
    jest.advanceTimersByTime(1000)
    await Promise.resolve()
  })
  return { onSessionExpired, state: () => view.getByTestId('state').textContent }
}

describe('AuthProvider revalidation failures of a signed-in user', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })
  afterEach(() => {
    jest.useRealTimers()
  })

  // Scenario: a failure that says nothing about the session. Expected: the user stays signed in, the
  // host is not told the session expired, and the next tick can recover.
  it.each([
    ['a 503 from a server whose store is down', new AuthClientError('unavailable', 503)],
    ['a 500', new AuthClientError('boom', 500)],
    ['a 502 from a proxy in front of a restarting server', new AuthClientError('bad gateway', 502)],
    ['a 504', new AuthClientError('gateway timeout', 504)],
    ['a 429 throttle', new AuthClientError('slow down', 429)],
    ['a network failure', new TypeError('Failed to fetch')]
  ])('keeps the user signed in through %s', async (_label, error) => {
    const { onSessionExpired, state } = await tickWith(error)

    expect(state()).toBe(`authenticated:${MOCK_USER.email}`)
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // Scenario: the one answer that ends a session. Expected: signed out and the host told.
  it('ends the session on a 401', async () => {
    const { onSessionExpired, state } = await tickWith(new AuthClientError('expired', 401))

    expect(state()).toBe('unauthenticated:none')
    expect(onSessionExpired).toHaveBeenCalledTimes(1)
  })

  // Scenario: another final answer, such as an account that is no longer usable. Expected: signed
  // out, without telling the host the session expired.
  it('signs the user out on another final answer', async () => {
    const { onSessionExpired, state } = await tickWith(new AuthClientError('forbidden', 403))

    expect(state()).toBe('unauthenticated:none')
    expect(onSessionExpired).not.toHaveBeenCalled()
  })

  // Scenario: the first check of a page load meets a 503. Expected: nothing is known about the
  // session yet, so the provider reports `unauthenticated`, as for any other failure.
  it('reports unauthenticated when the first check meets a 503', async () => {
    const client = createMockClient()
    client.getMe.mockRejectedValueOnce(new AuthClientError('unavailable', 503))
    const view = render(
      <AuthProvider client={client} revalidateInterval={0}>
        <Probe />
      </AuthProvider>
    )
    await act(async () => {
      await Promise.resolve()
    })

    expect(view.getByTestId('state').textContent).toBe('unauthenticated:none')
  })
})
