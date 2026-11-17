/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * What a cross-tab broadcast does when the revalidation it starts first could not be confirmed. The
 * revalidation rejects for a failure the server did not decide, and the broadcast is not a caller that
 * can read it: the reload that follows must run.
 */

import { act } from '@testing-library/react'

import { AuthClientError } from '../../shared'

import { FakeChannel, mount, settle, signedIn } from './_workspaceTestKit'

describe('a workspace broadcast whose revalidation could not be confirmed', () => {
  beforeEach(() => {
    Object.assign(globalThis, { BroadcastChannel: FakeChannel })
  })

  // Scenario: another tab broadcasts while the session check cannot be confirmed. Expected: the list
  // reloads once, as it does when the check is answered. Why: the broadcast cannot read the rejection,
  // so a reload chained after a bare `then` would never run.
  it.each([
    ['a 503', new AuthClientError('unavailable', 503)],
    ['a network failure', new TypeError('Failed to fetch')]
  ])('reloads after %s', async (_label, failure) => {
    const client = signedIn()
    const { result } = mount(client)
    await settle()
    const loads = client.listWorkspaces.mock.calls.length
    client.getMe.mockRejectedValueOnce(failure)

    act(() => {
      new FakeChannel('nest-auth:workspaces').postMessage({ type: 'workspaces-changed' })
    })
    await settle()
    await settle()
    await settle()

    expect(client.listWorkspaces.mock.calls.length).toBe(loads + 1)
    expect(result.current.memberships.length).toBeGreaterThan(0)
  })
})
