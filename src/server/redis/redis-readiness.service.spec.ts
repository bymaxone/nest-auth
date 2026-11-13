/**
 * @fileoverview Tests for the startup Redis check: the PING that keeps trying inside its budget and
 * fails the boot at the end of it, and the warning for a client with no command timeout.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import Redis from 'ioredis'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import { RedisReadinessService } from './redis-readiness.service'

/** The service over a client, built through the injector as the module builds it. */
async function check(client: object): Promise<RedisReadinessService> {
  const module = await Test.createTestingModule({
    providers: [RedisReadinessService, { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: client }]
  }).compile()
  return module.get(RedisReadinessService)
}

/** A client the check accepts without a warning: a `ping`, a status and a command timeout. */
function client(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    status: 'ready',
    options: { commandTimeout: 500 },
    once: jest.fn(),
    off: jest.fn(),
    ping: jest.fn().mockResolvedValue('PONG'),
    ...overrides
  }
}

/**
 * Runs the check under fake timers and reports how long it took to settle.
 *
 * @param target - The client.
 * @param afterStart - Runs once the check has begun, to drive the client from the test.
 * @param stepMs - How far each timer advance moves the clock.
 * @returns The outcome and the milliseconds elapsed when it settled.
 */
async function settle(
  target: object,
  afterStart?: () => void,
  stepMs = 50
): Promise<{ outcome: 'resolved' | Error; at: number }> {
  const service = await check(target)
  const start = Date.now()
  let outcome: 'resolved' | Error | undefined
  let at = -1
  void service.onApplicationBootstrap().then(
    () => {
      outcome = 'resolved'
      at = Date.now() - start
    },
    (error: unknown) => {
      outcome = error as Error
      at = Date.now() - start
    }
  )
  await Promise.resolve()
  afterStart?.()
  for (let elapsed = 0; outcome === undefined && elapsed <= 8000; elapsed += stepMs) {
    await jest.advanceTimersByTimeAsync(stepMs)
  }
  if (outcome === undefined) throw new Error('the check never settled')
  return { outcome, at }
}

describe('RedisReadinessService', () => {
  let warn: jest.SpyInstance

  beforeEach(() => {
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
    jest.useFakeTimers()
  })

  afterEach(() => {
    jest.useRealTimers()
    jest.restoreAllMocks()
  })

  // Scenario: a Redis that answers. Expected: boot continues after one PING.
  it('lets boot continue when Redis answers PING', async () => {
    const redis = client()

    const { outcome, at } = await settle(redis)

    expect(outcome).toBe('resolved')
    expect(at).toBeLessThan(250)
    expect(redis['ping']).toHaveBeenCalledTimes(1)
  })

  // Scenario: a Redis still starting during a rolling deploy, which refuses until one second in.
  // Expected: the check keeps trying and boot continues, instead of failing on the first refusal.
  it('keeps trying and passes when Redis comes up after one second', async () => {
    const start = Date.now()
    const redis = client({
      ping: jest.fn(() =>
        Date.now() - start < 1000
          ? Promise.reject(new Error('connect ECONNREFUSED 10.1.2.3:6379'))
          : Promise.resolve('PONG')
      )
    })

    const { outcome, at } = await settle(redis)

    expect(outcome).toBe('resolved')
    expect(at).toBeGreaterThanOrEqual(1000)
    expect(at).toBeLessThan(1500)
  })

  // Scenario: a client built with `lazyConnect` and the offline queue off, which rejects the very
  // command that starts its connection. Expected: the retry passes once the connection is up. This
  // is the combination the README recommends, so a healthy Redis must not fail boot on it.
  it('passes for a lazy client whose first command is rejected', async () => {
    const ping = jest
      .fn()
      .mockRejectedValueOnce(
        new Error("Stream isn't writeable and enableOfflineQueue options is false")
      )
      .mockResolvedValue('PONG')

    const { outcome } = await settle(client({ status: 'wait', ping }))

    expect(outcome).toBe('resolved')
    expect(ping).toHaveBeenCalledTimes(2)
  })

  // Scenario: a Redis that never answers on a port nothing serves. Expected: not refused early, then
  // refused at the end of the five seconds, with a message that names the address from the client's
  // own host and port and nothing the error said or the options held.
  it('refuses a dead port at the end of the budget, naming only host and port', async () => {
    const redis = client({
      options: {
        commandTimeout: 500,
        host: 'redis.internal',
        port: 6380,
        password: 's3cret-pass',
        username: 'svc-user'
      },
      ping: jest
        .fn()
        .mockRejectedValue(new Error('NOAUTH s3cret-pass at redis://svc-user:s3cret-pass@10.9.9.9'))
    })

    const { outcome, at } = await settle(redis)

    expect(at).toBeGreaterThanOrEqual(4750)
    expect(at).toBeLessThan(5500)
    expect(outcome).toBeInstanceOf(Error)
    const message = (outcome as Error).message
    expect(message).toBe(
      '[BymaxAuthModule] Redis at redis.internal:6380 did not answer PING within 5000 ms at startup. ' +
        'Check the address, the credentials and the network.'
    )
    expect(message).not.toMatch(/s3cret|svc-user|10\.9\.9\.9|redis:\/\//)
    // Retried every 250 ms for the whole budget, not given up on at the first refusal.
    expect((redis['ping'] as jest.Mock).mock.calls.length).toBeGreaterThanOrEqual(15)
  })

  // Scenario: a client with neither host nor port to name, such as a cluster. Expected: the message
  // omits the address and keeps the rest.
  it('omits the address when the client carries none', async () => {
    const redis = client({ ping: jest.fn().mockRejectedValue(new Error('down')) })

    const { outcome } = await settle(redis)

    expect((outcome as Error).message).toMatch(
      /^\[BymaxAuthModule\] Redis did not answer PING within 5000 ms/
    )
  })

  // Scenario: a client that does not dial a host and port, or whose host is not a plain name.
  // Expected: no address in the message. ioredis fills `localhost:6379` into every client's options,
  // so naming it for a socket or sentinel client would report an address it never tried, and a host
  // carrying userinfo or a path would repeat a credential.
  it.each([
    ['a unix-socket client', { host: 'localhost', port: 6379, path: '/var/run/redis.sock' }],
    [
      'a sentinel client',
      { host: 'localhost', port: 6379, sentinels: [{ host: 's', port: 26379 }] }
    ],
    ['a host with userinfo', { host: 'svc:s3cret@redis.internal', port: 6379 }],
    ['a host that is a URL', { host: 'redis://redis.internal', port: 6379 }],
    ['a host with whitespace', { host: 'redis internal', port: 6379 }],
    ['a port that is not a number', { host: 'redis.internal', port: '6379' }]
  ])('omits the address for %s', async (_why, options) => {
    const redis = client({
      options: { commandTimeout: 500, ...options },
      ping: jest.fn().mockRejectedValue(new Error('down'))
    })

    const { outcome } = await settle(redis)

    expect((outcome as Error).message).toMatch(
      /^\[BymaxAuthModule\] Redis did not answer PING within 5000 ms/
    )
  })

  // Scenario: an IPv6 literal host. Expected: named, since it is a plain host with colons.
  it('names an IPv6 host', async () => {
    const redis = client({
      options: { commandTimeout: 500, host: '::1', port: 6379 },
      ping: jest.fn().mockRejectedValue(new Error('down'))
    })

    const { outcome } = await settle(redis)

    expect((outcome as Error).message).toContain('Redis at ::1:6379 did not answer PING')
  })

  // Scenario: a client that has already ended, which no retry can bring back. Expected: refused at
  // once, without sending a command.
  it('refuses a client that has ended without sending a command', async () => {
    const redis = client({ status: 'end' })

    const { outcome, at } = await settle(redis)

    expect(outcome).toBeInstanceOf(Error)
    expect(at).toBeLessThan(250)
    expect(redis['ping']).not.toHaveBeenCalled()
  })

  // Scenario: a client that is connecting and then gives up while boot waits. Expected: refused at
  // once, not at the end of the budget.
  it('refuses at once a client that gives up while boot waits for it', async () => {
    let end: () => void = () => undefined
    const redis = client({
      status: 'connecting',
      once: jest.fn((event: string, listener: () => void) => {
        if (event === 'end') end = listener
      })
    })
    const { outcome, at } = await settle(redis, () => {
      redis['status'] = 'end'
      end()
    })

    expect(outcome).toBeInstanceOf(Error)
    expect(at).toBeLessThan(400)
    expect(redis['ping']).not.toHaveBeenCalled()
  })

  // Scenario: a connecting client that becomes ready. Expected: the PING waits for it, then goes.
  it('waits for a connecting client to become ready before it pings', async () => {
    let ready: () => void = () => undefined
    const redis = client({
      status: 'connecting',
      once: jest.fn((event: string, listener: () => void) => {
        if (event === 'ready') ready = listener
      })
    })
    const { outcome } = await settle(redis, () => {
      expect(redis['ping']).not.toHaveBeenCalled()
      ready()
    })

    expect(outcome).toBe('resolved')
    expect(redis['ping']).toHaveBeenCalledTimes(1)
  })

  // Scenario: a client that never becomes ready. Expected: refused at the end of the budget, with no
  // timer or listener left behind.
  it('refuses a client that never becomes ready, leaving nothing running', async () => {
    const redis = client({ status: 'connecting' })

    const { outcome, at } = await settle(redis)

    expect(outcome).toBeInstanceOf(Error)
    expect(at).toBeGreaterThanOrEqual(4750)
    expect(jest.getTimerCount()).toBe(0)
    expect(redis['ping']).not.toHaveBeenCalled()
    expect((redis['off'] as jest.Mock).mock.calls.map((call) => call[0])).toEqual(
      expect.arrayContaining(['ready', 'end'])
    )
  })

  // Scenario: a client that is not an ioredis client at all. Expected: a boot error naming the
  // token, not a TypeError from a missing method.
  it('fails boot, naming the token, for a client that cannot PING', async () => {
    const service = await check({})

    await expect(service.onApplicationBootstrap()).rejects.toThrow(
      '[BymaxAuthModule] BYMAX_AUTH_REDIS_CLIENT must be an ioredis client'
    )
  })

  // Scenario: no command timeout, in the shapes ioredis carries it. Expected: one warning that
  // names the option, and boot continues.
  it.each([
    ['a client with no options', undefined],
    ['a client with options and no commandTimeout', { host: 'redis' }],
    ['a cluster whose node options carry none', { redisOptions: {} }]
  ])('warns once for %s', async (_why, options) => {
    const { outcome } = await settle(client({ options }))

    expect(outcome).toBe('resolved')
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toContain('commandTimeout')
  })

  // Scenario: a command timeout on the client, or on a cluster's node options. Expected: no warning.
  it.each([
    ['a client', { commandTimeout: 500 }],
    ['a cluster', { redisOptions: { commandTimeout: 500 } }]
  ])('does not warn when %s has a command timeout', async (_why, options) => {
    await settle(client({ options }))

    expect(warn).not.toHaveBeenCalled()
  })

  // Scenario: a command timeout that is not a number, as an environment variable arrives. Expected:
  // warned, since ioredis arms its timer only for a number and the commands stay unbounded.
  it.each([['500'], [null], [undefined]])(
    'warns when commandTimeout is %p',
    async (commandTimeout) => {
      await settle(client({ options: { commandTimeout } }))

      expect(warn).toHaveBeenCalledTimes(1)
    }
  )

  // Scenario: a REAL ioredis client pointed at a port nothing listens on, which gives up at once.
  // Expected: boot fails fast with the address and nothing else. The fakes above invent the
  // client's shape; this is the shape ioredis really has.
  it('fails boot for a real client that cannot connect, naming only the address', async () => {
    jest.useRealTimers()
    const real = new Redis({
      host: '127.0.0.1',
      port: 1,
      password: 'real-secret',
      retryStrategy: () => null,
      maxRetriesPerRequest: 1,
      commandTimeout: 500
    })
    real.on('error', () => undefined)
    try {
      const attempt = (await check(real)).onApplicationBootstrap()

      await expect(attempt).rejects.toThrow(
        '[BymaxAuthModule] Redis at 127.0.0.1:1 did not answer PING'
      )
      await expect(attempt).rejects.not.toThrow(/real-secret/)
    } finally {
      real.disconnect()
    }
  })
})
