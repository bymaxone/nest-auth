/**
 * @fileoverview The deadline a provider plugin's network calls get during an OAuth callback: the
 * bounds of the value a plugin may ask for, and the rejection when it passes.
 *
 * @layer Test
 */

import {
  OAUTH_PLUGIN_DEFAULT_TIMEOUT_MS,
  OAUTH_PLUGIN_MAX_TIMEOUT_MS,
  pluginDeadlineMs,
  withDeadline
} from './plugin-deadline'

describe('pluginDeadlineMs', () => {
  // Scenario: the two ends of the accepted range, one past each, and the default. Expected: a whole
  // number from 1 to the maximum is taken as given, so 1 is a deadline of one millisecond and not the
  // default, and one past either end falls back to the default.
  it.each([
    [1, 1],
    [2, 2],
    [OAUTH_PLUGIN_MAX_TIMEOUT_MS, OAUTH_PLUGIN_MAX_TIMEOUT_MS],
    [0, OAUTH_PLUGIN_DEFAULT_TIMEOUT_MS],
    [OAUTH_PLUGIN_MAX_TIMEOUT_MS + 1, OAUTH_PLUGIN_DEFAULT_TIMEOUT_MS],
    [undefined, OAUTH_PLUGIN_DEFAULT_TIMEOUT_MS]
  ])('reads a timeoutMs of %p as %p', (timeoutMs, expected) => {
    expect(pluginDeadlineMs({ timeoutMs })).toBe(expected)
  })
})

describe('withDeadline', () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  // Scenario: work that never settles. Expected: a rejection naming the time that passed, at that
  // time and not before.
  it('rejects with the elapsed budget when the work never settles', async () => {
    const attempt = withDeadline(() => new Promise<never>(() => undefined), 5)
    const outcome = expect(attempt).rejects.toThrow('the plugin did not answer within 5 ms')

    await jest.advanceTimersByTimeAsync(5)

    await outcome
  })

  // Scenario: work that settles in time. Expected: its value, and no timer left behind.
  it('resolves with the work and leaves no timer running', async () => {
    await expect(withDeadline(() => Promise.resolve('done'), 5000)).resolves.toBe('done')

    expect(jest.getTimerCount()).toBe(0)
  })

  // Scenario: work that rejects in time. Expected: its rejection, and no timer left behind.
  it('passes the work rejection through and leaves no timer running', async () => {
    await expect(withDeadline(() => Promise.reject(new Error('boom')), 5000)).rejects.toThrow(
      'boom'
    )

    expect(jest.getTimerCount()).toBe(0)
  })
})
