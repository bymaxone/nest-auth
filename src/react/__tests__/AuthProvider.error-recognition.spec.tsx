/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * `AuthProvider` — which rejections are recognized as a client error, and with which status.
 *
 * The provider acts on a status only when the rejection is an object named `AuthClientError`
 * whose `status` is an integer HTTP status (100 to 599). Anything else is not a server answer, so
 * it decides nothing: a logout stays unconfirmed and the session is not reported expired. Every
 * cell of that rule has its own case here, for both decisions that read it: the logout and the
 * expiry check on a revalidation. Kept apart from `AuthProvider.spec.tsx` because that file is over
 * the size limit.
 */

import { act, renderHook } from '@testing-library/react'
import { useContext, type ReactNode } from 'react'

import { AuthProvider } from '../AuthProvider'
import { AuthContext, type AuthContextValue } from '../context'

import { createMockClient, MOCK_USER, type MockAuthClient } from './_testHelpers'

/** A rejection that is named like the client error and carries `status` as given. */
function named(status: unknown): Error {
  return Object.assign(new Error('boom'), { name: 'AuthClientError', status })
}

/** Mounts an authenticated provider around `client`. */
async function mountAuthenticated(client: MockAuthClient, onSessionExpired?: () => void) {
  client.getMe.mockResolvedValueOnce(MOCK_USER)
  const rendered = renderHook<AuthContextValue | null, unknown>(() => useContext(AuthContext), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <AuthProvider client={client} {...(onSessionExpired ? { onSessionExpired } : {})}>
        {children}
      </AuthProvider>
    )
  })
  await act(async () => {
    await Promise.resolve()
  })
  expect(rendered.result.current?.status).toBe('authenticated')
  return rendered.result
}

/** The context status after `client.logout()` rejected with `failure`. */
async function statusAfterLogoutFailing(failure: unknown): Promise<string | undefined> {
  const client = createMockClient()
  client.logout.mockRejectedValue(failure)
  const result = await mountAuthenticated(client)
  await act(async () => {
    await expect(result.current?.logout()).rejects.toBe(failure)
  })
  return result.current?.status
}

/** How many times `onSessionExpired` fired after a refresh that rejected with `failure`. */
async function expiryCallsAfterRefreshFailing(failure: unknown): Promise<number> {
  const onSessionExpired = jest.fn()
  const client = createMockClient()
  const result = await mountAuthenticated(client, onSessionExpired)
  client.getMe.mockRejectedValueOnce(failure)
  await act(async () => {
    await result.current?.refresh()
  })
  return onSessionExpired.mock.calls.length
}

describe('AuthProvider — recognizing a client error by name and integer HTTP status', () => {
  // The statuses that are final answers clear the context; the throttle and the server errors do
  // not. Valid statuses at both ends of the range are included, because the bounds are part of the
  // rule.
  it.each([
    [100, 'unauthenticated'],
    [302, 'unauthenticated'],
    [400, 'unauthenticated'],
    [499, 'unauthenticated'],
    [429, 'authenticated'],
    [500, 'authenticated'],
    [599, 'authenticated']
  ])('decides a logout rejected with the valid status %i', async (status, expected) => {
    expect(await statusAfterLogoutFailing(named(status))).toBe(expected)
  })

  // A status that is not an integer HTTP status is not a server answer, whatever its value would
  // compare as: the logout stays unconfirmed.
  it.each([
    ['below the range', 99],
    ['zero', 0],
    ['negative', -1],
    ['above the range', 600],
    ['a fraction', 401.5],
    ['not a number', Number.NaN],
    ['infinite', Number.POSITIVE_INFINITY],
    ['a numeric string', '401'],
    ['null', null],
    ['absent', undefined],
    ['an object', {}]
  ])('keeps the state for a logout rejected with a status that is %s', async (_label, status) => {
    expect(await statusAfterLogoutFailing(named(status))).toBe('authenticated')
  })

  // The name and the shape decide whether it is a client error at all.
  it.each([
    ['an error with another name', Object.assign(new Error('boom'), { status: 401 })],
    ['a string', '401'],
    ['null', null],
    ['undefined', undefined]
  ])('keeps the state for a logout rejected with %s', async (_label, failure) => {
    expect(await statusAfterLogoutFailing(failure)).toBe('authenticated')
  })

  // An object that is not an Error instance (another realm's error, a serialized one) but is named
  // and carries a valid status is recognized the same way.
  it('recognizes a named plain object that is not an Error instance', async () => {
    expect(await statusAfterLogoutFailing({ name: 'AuthClientError', status: 401 })).toBe(
      'unauthenticated'
    )
  })

  // The expiry check reads the same rule: only a valid 401 reports the session expired.
  it('reports the session expired for a valid 401', async () => {
    expect(await expiryCallsAfterRefreshFailing(named(401))).toBe(1)
  })

  it.each([
    ['a valid 403', named(403)],
    ['a valid 500', named(500)],
    ['a string 401', named('401')],
    ['a fractional 401', named(401.5)],
    ['an absent status', named(undefined)],
    ['another name with 401', Object.assign(new Error('boom'), { status: 401 })],
    ['a string', '401']
  ])('does not report the session expired for %s', async (_label, failure) => {
    expect(await expiryCallsAfterRefreshFailing(failure)).toBe(0)
  })
})
