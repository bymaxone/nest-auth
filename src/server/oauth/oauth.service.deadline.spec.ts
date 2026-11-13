/**
 * OAuthService — the deadline on a provider plugin's code exchange and profile fetch.
 *
 * Both calls are the plugin's own network I/O. One that never settles would hold the callback
 * request open, with its state already consumed, so the library bounds them together and answers
 * `OAUTH_FAILED` when the time is up. Kept apart from `oauth.service.spec.ts`, which is frozen on
 * the file-length baseline.
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { OAUTH_PLUGINS } from './oauth.constants'
import { OAuthService } from './oauth.service'
import {
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthRedisService } from '../redis/auth-redis.service'
import { SessionService } from '../services/session.service'
import { TokenManagerService } from '../services/token-manager.service'

const STORED_STATE = JSON.stringify({
  provider: 'google',
  tenantId: 'tenant-1',
  codeVerifier: 'verifier-xyz'
})

const PROFILE = {
  provider: 'google',
  providerId: 'g-123',
  email: 'user@example.com',
  emailVerified: true,
  name: 'Test User'
}

/** A promise that never settles, as a provider that accepts the connection and goes silent. */
const never = (): Promise<never> => new Promise(() => undefined)

interface FakePlugin {
  name: string
  timeoutMs?: unknown
  authorizeUrl: jest.Mock
  exchangeCode: jest.Mock
  fetchProfile: jest.Mock
}

function plugin(timeoutMs?: unknown): FakePlugin {
  return {
    name: 'google',
    ...(timeoutMs === undefined ? {} : { timeoutMs }),
    authorizeUrl: jest.fn(),
    exchangeCode: jest.fn(),
    fetchProfile: jest.fn()
  }
}

const mockRedis = { set: jest.fn(), getdel: jest.fn() }

async function serviceWith(target: FakePlugin): Promise<OAuthService> {
  const module = await Test.createTestingModule({
    providers: [
      OAuthService,
      { provide: OAUTH_PLUGINS, useValue: [target] },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} },
      { provide: BYMAX_AUTH_HOOKS, useValue: {} },
      { provide: AuthRedisService, useValue: mockRedis },
      { provide: TokenManagerService, useValue: {} },
      { provide: SessionService, useValue: {} },
      {
        provide: BYMAX_AUTH_OPTIONS,
        useValue: { sessions: { enabled: false }, secureCookies: true, blockedStatuses: [] }
      }
    ]
  }).compile()
  return module.get(OAuthService)
}

/** Runs the callback and reports whether it had settled after each of the given elapsed times. */
async function settledAt(
  service: OAuthService,
  checkpoints: readonly number[]
): Promise<{ at: number; settled: boolean; code?: string }[]> {
  let outcome: { code?: string } | undefined
  void service.handleCallback('google', 'code', 'state', 'state', '1.2.3.4', 'UA', {}).then(
    () => {
      outcome = {}
    },
    (error: { getResponse: () => { error: { code: string } } }) => {
      outcome = { code: error.getResponse().error.code }
    }
  )
  const results: { at: number; settled: boolean; code?: string }[] = []
  let elapsed = 0
  for (const at of checkpoints) {
    await jest.advanceTimersByTimeAsync(at - elapsed)
    elapsed = at
    results.push({ at, settled: outcome !== undefined, ...(outcome ?? {}) })
  }
  return results
}

describe('OAuthService — the plugin deadline', () => {
  let error: jest.SpyInstance

  beforeEach(() => {
    jest.resetAllMocks()
    error = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    mockRedis.getdel.mockResolvedValue(STORED_STATE)
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
    jest.restoreAllMocks()
  })

  // Scenario: a token endpoint that never answers. Expected: still waiting at 9.9 s, OAUTH_FAILED at
  // 10 s, and the profile is never asked for.
  it('answers OAUTH_FAILED at 10 s when the code exchange never settles', async () => {
    const target = plugin()
    target.exchangeCode.mockImplementation(never)

    const results = await settledAt(await serviceWith(target), [9900, 10_000])

    expect(results).toEqual([
      { at: 9900, settled: false },
      { at: 10_000, settled: true, code: AUTH_ERROR_CODES.OAUTH_FAILED }
    ])
    expect(target.fetchProfile).not.toHaveBeenCalled()
  })

  // Scenario: the exchange answers and the profile endpoint goes silent. Expected: the same deadline,
  // measured over both calls together.
  it('answers OAUTH_FAILED at 10 s when the profile fetch never settles', async () => {
    const target = plugin()
    target.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
    target.fetchProfile.mockImplementation(never)

    const results = await settledAt(await serviceWith(target), [9900, 10_000])

    expect(results.map((r) => r.settled)).toEqual([false, true])
    expect(results[1]?.code).toBe(AUTH_ERROR_CODES.OAUTH_FAILED)
  })

  // Scenario: the two calls each take most of the time. Expected: the deadline is for the pair, so a
  // slow exchange followed by a slow fetch is cut off at 10 s in total and not at 20 s.
  it('measures the deadline over the exchange and the fetch together', async () => {
    const target = plugin()
    target.exchangeCode.mockImplementation(
      () =>
        new Promise((resolve) =>
          setTimeout(() => resolve({ access_token: 'at', token_type: 'Bearer' }), 6000)
        )
    )
    target.fetchProfile.mockImplementation(never)

    const results = await settledAt(await serviceWith(target), [9900, 10_000])

    expect(results.map((r) => r.settled)).toEqual([false, true])
  })

  // Scenario: a plugin that sets its own deadline. Expected: honoured, and not before it.
  it('honours the plugin timeoutMs', async () => {
    const target = plugin(2000)
    target.exchangeCode.mockImplementation(never)

    const results = await settledAt(await serviceWith(target), [1900, 2000])

    expect(results.map((r) => r.settled)).toEqual([false, true])
    expect(results[1]?.code).toBe(AUTH_ERROR_CODES.OAUTH_FAILED)
  })

  // Scenario: a timeout the plugin set to something unusable, as configuration arrives. Expected:
  // the 10 s default, never no deadline and never an immediate one.
  it.each([[0], [-1], [Number.NaN], [Infinity], [1.5], ['5000'], [null], [120_001]])(
    'falls back to the 10 s default for a timeoutMs of %p',
    async (timeoutMs) => {
      const target = plugin(timeoutMs)
      target.exchangeCode.mockImplementation(never)

      const results = await settledAt(await serviceWith(target), [9900, 10_000])

      expect(results.map((r) => r.settled)).toEqual([false, true])
    }
  )

  // Scenario: the longest deadline a plugin may ask for. Expected: accepted as given.
  it('accepts a timeoutMs up to 120000', async () => {
    const target = plugin(120_000)
    target.exchangeCode.mockImplementation(never)

    const results = await settledAt(await serviceWith(target), [119_900, 120_000])

    expect(results.map((r) => r.settled)).toEqual([false, true])
  })

  // Scenario: a plugin that answers in time. Expected: the profile is used and no timer is left.
  it('leaves no timer behind when the plugin answers in time', async () => {
    const target = plugin()
    target.exchangeCode.mockResolvedValue({ access_token: 'at', token_type: 'Bearer' })
    target.fetchProfile.mockResolvedValue(PROFILE)
    const service = await serviceWith(target)

    // The flow continues past the profile into the account lookup, which this spec does not
    // provide; reaching it is the proof that the plugin calls completed.
    await service
      .handleCallback('google', 'code', 'state', 'state', '1.2.3.4', 'UA', {})
      .catch(() => undefined)

    expect(target.fetchProfile).toHaveBeenCalledWith('at')
    expect(jest.getTimerCount()).toBe(0)
  })

  // Scenario: a timeout. Expected: the log line carries the shape of the failure only, nothing the
  // plugin wrote, like every other failure on this path.
  it('logs only the shape of a timeout', async () => {
    const target = plugin(1000)
    target.exchangeCode.mockImplementation(never)

    await settledAt(await serviceWith(target), [1000])

    expect(error).toHaveBeenCalledTimes(1)
    expect(String(error.mock.calls[0]?.[0])).toContain("OAuth plugin 'google' failed")
  })
})
