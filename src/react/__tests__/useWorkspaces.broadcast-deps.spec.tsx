/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * The handler of a cross-tab broadcast asks the session check it was given by the latest render. The
 * auth provider hands a new check when its client changes, and a handler that kept the first one would
 * revalidate through a client that is no longer the session's.
 */

import { act, renderHook } from '@testing-library/react'

import type { AuthStatus } from '../context'
import { useBroadcastReload } from '../workspaceState'

describe('useBroadcastReload and the session check of the latest render', () => {
  // Scenario: the check is replaced by a rerender, then a broadcast arrives. Expected: the new check
  // runs once and the first never runs. Why: the callback is memoised on the check, so an array that
  // omits it keeps asking the one it was created with.
  it('asks the check it was last given', async () => {
    const first = jest.fn<Promise<void>, []>().mockResolvedValue(undefined)
    const second = jest.fn<Promise<void>, []>().mockResolvedValue(undefined)
    const reload = jest.fn<Promise<void>, []>().mockResolvedValue(undefined)
    const statusRef = { current: 'authenticated' as AuthStatus }
    const identityRef = { current: 'account-1' as string | null }
    const { result, rerender } = renderHook(
      ({ check }) => useBroadcastReload(check, statusRef, identityRef, reload),
      { initialProps: { check: first } }
    )

    rerender({ check: second })
    await act(async () => {
      result.current()
      await Promise.resolve()
    })

    expect(second).toHaveBeenCalledTimes(1)
    expect(first).not.toHaveBeenCalled()
  })
})
