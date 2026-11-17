/**
 * @jest-environment @stryker-mutator/jest-runner/jest-env/jsdom
 */

/**
 * `revalidateInterval` is a tuning value for a background poll, and a positive value below the floor
 * is a loop that costs a request every few milliseconds per open tab (`5` meant as seconds is a 5 ms
 * loop). A positive value below the floor is read as the floor; `0` disables the loop; a value that
 * is not a number in range reads as the default.
 */

import { act, render } from '@testing-library/react'

import { AuthProvider } from '../AuthProvider'

import { createMockClient, MOCK_USER } from './_testHelpers'

const FLOOR_MS = 5_000
const DEFAULT_MS = 300_000

/** Mounts a signed-in provider, lets time run and counts the revalidations after mount. */
async function revalidationsOver(revalidateInterval: number, elapsedMs: number): Promise<number> {
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

describe('AuthProvider revalidateInterval floor', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })
  afterEach(() => {
    jest.useRealTimers()
  })

  // Scenario: a positive value far below the floor. Expected: no revalidation until the floor has
  // passed, then one per floor period. Why: a 1 ms loop is a request every millisecond per tab.
  it.each([1, 1.5, 5, 999, 4_999])('reads %s ms as the floor', async (value) => {
    expect(await revalidationsOver(value, FLOOR_MS - 1)).toBe(0)
    expect(await revalidationsOver(value, FLOOR_MS)).toBe(1)
    expect(await revalidationsOver(value, FLOOR_MS * 3)).toBe(3)
  })

  // Scenario: the floor itself and the first value above it. Expected: each is honoured as given.
  it('honours the floor as given', async () => {
    expect(await revalidationsOver(FLOOR_MS, FLOOR_MS - 1)).toBe(0)
    expect(await revalidationsOver(FLOOR_MS, FLOOR_MS * 2)).toBe(2)
  })

  it('honours a value just above the floor as given', async () => {
    expect(await revalidationsOver(FLOOR_MS + 1, FLOOR_MS)).toBe(0)
    expect(await revalidationsOver(FLOOR_MS + 1, FLOOR_MS + 1)).toBe(1)
  })

  it('honours a period well inside the range as given', async () => {
    expect(await revalidationsOver(10_000, 30_000)).toBe(3)
  })

  // Scenario: zero. Expected: the loop is disabled, not clamped up to the floor.
  it('disables the loop for 0', async () => {
    expect(await revalidationsOver(0, DEFAULT_MS * 2)).toBe(0)
  })

  // Scenario: values that are not a number in range. Expected: the default period, not the floor.
  it.each([
    ['NaN', Number.NaN],
    ['negative', -1],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['one above the ceiling', 2_147_483_648]
  ])('reads %s as the default period', async (_label, value) => {
    expect(await revalidationsOver(value, DEFAULT_MS - 1)).toBe(0)
    expect(await revalidationsOver(value, DEFAULT_MS)).toBe(1)
  })

  it('accepts the ceiling as given', async () => {
    expect(await revalidationsOver(2_147_483_647, DEFAULT_MS)).toBe(0)
  })
})
