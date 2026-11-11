/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * What `AuthProvider` does with a session check that is still on its way when it unmounts: the result
 * is dropped, so the host's `onSessionExpired` is never called after the host has gone.
 */

import { act, render } from '@testing-library/react'

import { AuthClientError } from '../../shared'
import { AuthProvider } from '../AuthProvider'

import { createMockClient, MOCK_USER } from './_testHelpers'

/** Mounts a signed-in provider and starts a revalidation that answers only when told to. */
async function withRevalidationInFlight() {
  const client = createMockClient()
  client.getMe.mockResolvedValueOnce(MOCK_USER)
  const onSessionExpired = jest.fn()
  const view = render(
    <AuthProvider client={client} onSessionExpired={onSessionExpired} revalidateInterval={1000}>
      <div />
    </AuthProvider>
  )
  await act(async () => {
    await Promise.resolve()
  })
  let expire: () => void = () => undefined
  client.getMe.mockImplementationOnce(
    () =>
      new Promise(
        (_resolve, reject) => (expire = () => reject(new AuthClientError('expired', 401)))
      )
  )
  await act(async () => {
    jest.advanceTimersByTime(1000)
    await Promise.resolve()
  })
  const answer = async (): Promise<void> => {
    await act(async () => {
      expire()
      await Promise.resolve()
      await Promise.resolve()
    })
  }
  return { view, onSessionExpired, answer }
}

describe('AuthProvider with a revalidation in flight', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  it('calls onSessionExpired when the session expires while it is mounted', async () => {
    const { onSessionExpired, answer } = await withRevalidationInFlight()

    await answer()

    expect(onSessionExpired).toHaveBeenCalledTimes(1)
  })

  it('does not call onSessionExpired for an answer that arrives after it unmounted', async () => {
    const { view, onSessionExpired, answer } = await withRevalidationInFlight()

    view.unmount()
    await answer()

    expect(onSessionExpired).not.toHaveBeenCalled()
  })
})
