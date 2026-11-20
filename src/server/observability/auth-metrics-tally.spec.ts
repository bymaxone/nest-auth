/**
 * @fileoverview The tally keeps one count per closed outcome per plane, and hands out copies.
 *
 * @layer Test
 */

import {
  AUTH_PLANES,
  AuthMetricsTally,
  LOGIN_OUTCOMES,
  MFA_OUTCOMES,
  REFRESH_OUTCOMES
} from './auth-metrics-tally'

describe('AuthMetricsTally', () => {
  // Scenario: a fresh tally. Expected: every plane and outcome of every closed set is present at zero, so a
  // scrape publishes a sample for each from the first request.
  it('starts every closed set at zero on both planes', () => {
    const snapshot = new AuthMetricsTally().snapshot()

    for (const plane of AUTH_PLANES) {
      expect(Object.keys(snapshot.logins[plane])).toEqual([...LOGIN_OUTCOMES])
      expect(Object.keys(snapshot.refreshes[plane])).toEqual([...REFRESH_OUTCOMES])
      expect(Object.keys(snapshot.mfa[plane])).toEqual([...MFA_OUTCOMES])
      expect(Object.values(snapshot.logins[plane]).every((count) => count === 0)).toBe(true)
    }
    expect(snapshot.lockouts).toBe(0)
  })

  // Scenario: one event of each kind on one plane. Expected: exactly that count moves, on that plane only.
  it('counts each event against its own plane and outcome', () => {
    const tally = new AuthMetricsTally()

    tally.login('platform', 'locked')
    tally.login('platform', 'locked')
    tally.refresh('dashboard', 'reuse_detected')
    tally.mfa('dashboard', 'invalid')
    tally.lockout()
    const snapshot = tally.snapshot()

    expect(snapshot.logins.platform.locked).toBe(2)
    expect(snapshot.logins.dashboard.locked).toBe(0)
    expect(snapshot.refreshes.dashboard.reuse_detected).toBe(1)
    expect(snapshot.refreshes.platform.reuse_detected).toBe(0)
    expect(snapshot.mfa.dashboard.invalid).toBe(1)
    expect(snapshot.lockouts).toBe(1)
  })

  // Scenario: a snapshot is mutated after it is read. Expected: the tally does not change. Why: the
  // publisher must not be able to alter what the flows counted.
  it('hands out a copy of the counts', () => {
    const tally = new AuthMetricsTally()
    const first = tally.snapshot()

    ;(first.logins.dashboard as Record<string, number>)['success'] = 99
    tally.login('dashboard', 'success')

    expect(tally.snapshot().logins.dashboard.success).toBe(1)
  })
})
