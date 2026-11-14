/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * `revalidateInterval` reaches `setInterval`, which gives a delay it cannot honor (`NaN`,
 * `Infinity`, above 2147483647) a 1 ms period: a revalidation request every millisecond. Such a
 * value is read as the default, and `0` still disables the loop.
 */

import { act, render } from '@testing-library/react'

import { AuthProvider } from '../AuthProvider'

import { createMockClient, MOCK_USER } from './_testHelpers'

const DEFAULT_MS = 300_000

/** Mounts a signed-in provider, lets time run for a while and counts the revalidations. */
async function revalidationsOver(revalidateInterval: number, elapsedMs: number) {
  const client = createMockClient()
  client.getMe.mockResolvedValue(MOCK_USER)
  render(
    <AuthProvider client={client} revalidateInterval={revalidateInterval}>
      <div />
    </AuthProvider>
  )
  await act(async () => {
    await Promise.resolve()
  })
  const afterMount = client.getMe.mock.calls.length
  await act(async () => {
    jest.advanceTimersByTime(elapsedMs)
    await Promise.resolve()
  })
  return client.getMe.mock.calls.length - afterMount
}

describe('AuthProvider revalidateInterval ceiling', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })
  afterEach(() => {
    jest.useRealTimers()
  })

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['one above the ceiling', 2_147_483_648],
    ['negative', -5]
  ])('reads %s as the default period, not a 1 ms loop', async (_label, value) => {
    expect(await revalidationsOver(value, 60_000)).toBe(0)
    expect(await revalidationsOver(value, DEFAULT_MS)).toBe(1)
  })

  it('still honors a period inside the range', async () => {
    expect(await revalidationsOver(1000, 3000)).toBe(3)
  })

  it('still honors the ceiling itself as given', async () => {
    expect(await revalidationsOver(2_147_483_647, DEFAULT_MS)).toBe(0)
  })

  it('still disables the loop for 0', async () => {
    expect(await revalidationsOver(0, DEFAULT_MS * 2)).toBe(0)
  })
})
