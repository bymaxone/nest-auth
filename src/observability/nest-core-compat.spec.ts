/**
 * @fileoverview The subpath meets the published `@bymax-one/nest-core` 1.6.15 contracts without importing it:
 * the metadata keys the module discovers by, and the shapes of the contributor and the indicator, are
 * compared with the package's own declarations; the collectors register on a real registry and scrape with
 * closed labels.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { Registry } from 'prom-client'

import { AuthHealthProbe, AuthMetricsTally } from '@bymax-one/nest-auth'
import { AuthRedisHealthIndicator, HEALTH_INDICATOR_METADATA } from './auth-health'
import { AuthMetrics, METRICS_CONTRIBUTOR_METADATA } from './auth-metrics'

/** The published declarations of one subpath of the contract package. */
function declarations(subpath: 'health' | 'metrics'): string {
  return readFileSync(
    join(__dirname, '../../node_modules/@bymax-one/nest-core/dist', subpath, 'index.d.ts'),
    'utf8'
  )
}

describe('observability against @bymax-one/nest-core', () => {
  // Scenario: the module discovers providers by a metadata key, and calls a contributor and an indicator by a
  // shape. Expected: the keys written out here and the members the classes carry are those the published
  // declarations name, so a host that lists the two classes is discovered and called.
  it('matches the keys and the shapes the published declarations name', () => {
    const metrics = declarations('metrics')
    const health = declarations('health')

    expect(metrics).toContain(
      `BYMAX_METRICS_CONTRIBUTOR_METADATA = "${METRICS_CONTRIBUTOR_METADATA}"`
    )
    expect(metrics).toContain('registerMetrics(registry: MetricsRegistry): void;')
    expect(health).toContain(`BYMAX_HEALTH_INDICATOR_METADATA = "${HEALTH_INDICATOR_METADATA}"`)
    expect(health).toContain('readonly name: string;')
    expect(health).toContain('check(signal?: AbortSignal): Promise<HealthIndicatorResult>;')
    expect(health).toContain("status: 'up' | 'down';")
    expect(Reflect.getMetadata(METRICS_CONTRIBUTOR_METADATA, AuthMetrics)).toBe(true)
    expect(Reflect.getMetadata(HEALTH_INDICATOR_METADATA, AuthRedisHealthIndicator)).toBe(true)
    expect(typeof AuthMetrics.prototype.registerMetrics).toBe('function')
  })

  // Scenario: the contributor registers on a registry and the registry is scraped. Expected: every collector
  // is present with its help text, with a sample for each plane and outcome before any event.
  it('registers every collector with its help text and a zero sample per label set', async () => {
    const registry = new Registry()
    const contributor = new AuthMetrics(new AuthMetricsTally())

    contributor.registerMetrics(registry)
    const text = await registry.metrics()

    for (const name of [
      'bymax_auth_logins_total',
      'bymax_auth_refresh_total',
      'bymax_auth_mfa_verifications_total',
      'bymax_auth_bruteforce_lockouts_total'
    ]) {
      expect(text).toContain(`# HELP ${name} `)
      expect(text).toContain(`# TYPE ${name} counter`)
    }
    expect(text).toContain('bymax_auth_logins_total{plane="dashboard",outcome="success"} 0')
    expect(text).toContain('bymax_auth_refresh_total{plane="platform",outcome="reuse_detected"} 0')
    expect(text).toContain(
      'bymax_auth_mfa_verifications_total{plane="dashboard",outcome="locked"} 0'
    )
    expect(text).toContain('bymax_auth_bruteforce_lockouts_total 0')
  })

  // Scenario: events happen between scrapes. Expected: the scrape shows them, and a second scrape with no
  // new events shows the same numbers (a counter that is read, not added to again).
  it('shows what the flows counted and the same numbers when nothing happened since', async () => {
    const tally = new AuthMetricsTally()
    const registry = new Registry()
    new AuthMetrics(tally).registerMetrics(registry)
    tally.login('dashboard', 'success')
    tally.login('dashboard', 'success')
    tally.refresh('platform', 'reuse_detected')
    tally.mfa('dashboard', 'invalid')
    tally.lockout()

    const first = await registry.metrics()
    const second = await registry.metrics()

    for (const text of [first, second]) {
      expect(text).toContain('bymax_auth_logins_total{plane="dashboard",outcome="success"} 2')
      expect(text).toContain(
        'bymax_auth_refresh_total{plane="platform",outcome="reuse_detected"} 1'
      )
      expect(text).toContain(
        'bymax_auth_mfa_verifications_total{plane="dashboard",outcome="invalid"} 1'
      )
      expect(text).toContain('bymax_auth_bruteforce_lockouts_total 1')
    }
  })

  // Scenario: every label value on the scrape. Expected: each is drawn from the closed sets, and the sample
  // count is fixed, so no label can grow with traffic.
  it('publishes only labels drawn from the closed sets, in a fixed number of samples', async () => {
    const registry = new Registry()
    const tally = new AuthMetricsTally()
    new AuthMetrics(tally).registerMetrics(registry)
    for (let i = 0; i < 25; i += 1) tally.login('dashboard', 'invalid_credentials')

    const samples = (await registry.metrics())
      .split('\n')
      .filter((line) => /^bymax_auth_/.test(line))
    const planes = new Set(samples.map((line) => /plane="([^"]*)"/.exec(line)?.[1]).filter(Boolean))
    const outcomes = new Set(
      samples.map((line) => /outcome="([^"]*)"/.exec(line)?.[1]).filter(Boolean)
    )

    expect(samples).toHaveLength(2 * (5 + 4 + 3) + 1)
    expect([...planes].sort()).toEqual(['dashboard', 'platform'])
    expect([...outcomes].sort()).toEqual(
      [
        'blocked',
        'expired',
        'invalid',
        'invalid_credentials',
        'locked',
        'mfa_required',
        'reuse_detected',
        'rotated',
        'success'
      ].sort()
    )
  })

  // Scenario: the indicator over a probe that answers, answers wrongly, and rejects. Expected: up, down, and
  // the rejection left to the aggregator, which turns it into a down entry; the name is `auth-redis`, and no
  // detail is reported.
  it('reports up, down and lets a rejection through, without detail', async () => {
    const answers: Array<Promise<string>> = [
      Promise.resolve('PONG'),
      Promise.resolve('LOADING'),
      Promise.reject(new Error('ECONNREFUSED 10.0.0.1:6379'))
    ]
    const indicator = new AuthRedisHealthIndicator(
      new AuthHealthProbe({ ping: () => answers.shift() ?? Promise.resolve('') })
    )

    expect(indicator.name).toBe('auth-redis')
    await expect(indicator.check()).resolves.toStrictEqual({ status: 'up' })
    await expect(indicator.check()).resolves.toStrictEqual({ status: 'down' })
    // The rejection is the probe's own: the address the client's error named is not carried to the aggregator.
    await expect(indicator.check()).rejects.toThrow(/^The authentication store failed the PING\.$/)
  })

  // Scenario: the aggregator aborts the signal it gave the check while the store has not answered. Expected:
  // the check rejects at once, which the aggregator reports as down, instead of waiting for the store.
  it('ends the check when the aggregator’s signal aborts', async () => {
    const indicator = new AuthRedisHealthIndicator(
      new AuthHealthProbe({ ping: () => new Promise<string>(() => undefined) })
    )
    const controller = new AbortController()

    const check = indicator.check(controller.signal)
    controller.abort()

    await expect(check).rejects.toThrow('did not answer in time')
  })
})
