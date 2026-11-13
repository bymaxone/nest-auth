/**
 * @fileoverview Tests for the startup Redis check: the PING that fails boot on a Redis that cannot
 * be reached, and the warning for a client with no command timeout.
 *
 * @layer Test
 */

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import Redis from 'ioredis'

import { BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import { RedisReadinessService } from './redis-readiness.service'

/** A client as far as the check reads it: a `ping` and the options it was built with. */
interface FakeClient {
  ping: jest.Mock
  options?: Record<string, unknown>
}

/** The service over a client, built through the injector as the module builds it. */
async function check(client: object): Promise<RedisReadinessService> {
  const module = await Test.createTestingModule({
    providers: [RedisReadinessService, { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: client }]
  }).compile()
  return module.get(RedisReadinessService)
}

describe('RedisReadinessService', () => {
  let warn: jest.SpyInstance

  beforeEach(() => {
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // Scenario: a Redis that answers. Expected: boot continues.
  it('lets boot continue when Redis answers PING', async () => {
    const client = { ping: jest.fn().mockResolvedValue('PONG'), options: { commandTimeout: 1000 } }

    await expect((await check(client)).onApplicationBootstrap()).resolves.toBeUndefined()
    expect(client.ping).toHaveBeenCalledTimes(1)
  })

  // Scenario: a Redis that refuses the command (a wrong password, a dead connection). Expected: boot
  // fails with a message that names the cause and carries nothing the error said, since an ioredis
  // error can quote the host and port.
  it('fails boot when Redis rejects PING, without echoing the error', async () => {
    const client = {
      ping: jest.fn().mockRejectedValue(new Error('connect ECONNREFUSED 10.1.2.3:6379')),
      options: { commandTimeout: 1000 }
    }

    const attempt = (await check(client)).onApplicationBootstrap()

    await expect(attempt).rejects.toThrow('[BymaxAuthModule] Redis did not answer PING')
    await expect(attempt).rejects.not.toThrow(/10\.1\.2\.3|ECONNREFUSED/)
  })

  // Scenario: a Redis that never answers. Expected: boot fails at the deadline and does not hang,
  // and the timer is not left running.
  it('fails boot at the deadline when Redis never answers', async () => {
    jest.useFakeTimers()
    try {
      const client = { ping: jest.fn(() => new Promise(() => undefined)), options: {} }
      const attempt = (await check(client)).onApplicationBootstrap()
      const assertion = expect(attempt).rejects.toThrow(/did not answer PING within 5000 ms/)

      await jest.advanceTimersByTimeAsync(5000)

      await assertion
      expect(jest.getTimerCount()).toBe(0)
    } finally {
      jest.useRealTimers()
    }
  })

  // Scenario: a client that is not an ioredis client at all. Expected: a boot error naming the
  // token, not a TypeError from a missing method.
  it('fails boot, naming the token, for a client that cannot PING', async () => {
    const service = await check({})

    await expect(service.onApplicationBootstrap()).rejects.toThrow(
      '[BymaxAuthModule] BYMAX_AUTH_REDIS_CLIENT must be an ioredis client'
    )
  })

  // Scenario: no command timeout, in the three shapes ioredis carries it. Expected: one warning
  // that names the option, and boot continues.
  it.each([
    ['a client with no options', undefined],
    ['a client with options and no commandTimeout', { host: 'redis' }],
    ['a cluster whose node options carry none', { redisOptions: {} }]
  ])('warns once for %s', async (_why, options) => {
    const client = { ping: jest.fn().mockResolvedValue('PONG'), options }
    const service = await check(client)

    await service.onApplicationBootstrap()

    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]?.[0]).toContain('commandTimeout')
  })

  // Scenario: a command timeout on the client, or on a cluster's node options. Expected: no warning.
  it.each([
    ['a client', { commandTimeout: 500 }],
    ['a cluster', { redisOptions: { commandTimeout: 500 } }]
  ])('does not warn when %s has a command timeout', async (_why, options) => {
    const client = { ping: jest.fn().mockResolvedValue('PONG'), options }

    await (await check(client)).onApplicationBootstrap()

    expect(warn).not.toHaveBeenCalled()
  })

  // Scenario: a command timeout that is not a number, as an environment variable arrives. Expected:
  // warned, since ioredis arms its timer only for a number and the commands stay unbounded.
  it.each([['500'], [null], [undefined]])(
    'warns when commandTimeout is %p',
    async (commandTimeout) => {
      const client = { ping: jest.fn().mockResolvedValue('PONG'), options: { commandTimeout } }

      await (await check(client)).onApplicationBootstrap()

      expect(warn).toHaveBeenCalledTimes(1)
    }
  )

  // Scenario: a client still connecting when boot reaches the probe, as one with the offline queue
  // off is. Expected: the PING waits for `ready` and does not fail on a connection a moment behind.
  it('waits for a connecting client to become ready before it pings', async () => {
    let ready: () => void = () => undefined
    const client = {
      status: 'connecting',
      options: { commandTimeout: 500 },
      once: jest.fn((event: string, listener: () => void) => {
        if (event === 'ready') ready = listener
      }),
      off: jest.fn(),
      ping: jest.fn().mockResolvedValue('PONG')
    }
    const attempt = (await check(client)).onApplicationBootstrap()
    await Promise.resolve()

    expect(client.ping).not.toHaveBeenCalled()
    ready()

    await expect(attempt).resolves.toBeUndefined()
    expect(client.once).toHaveBeenCalledWith('ready', expect.any(Function))
    expect(client.ping).toHaveBeenCalledTimes(1)
  })

  // Scenario: a client that has not started (`lazyConnect`) or is ready. Expected: PING at once,
  // the first command being what starts a lazy client.
  it.each([['wait'], ['ready']])('pings a %s client without waiting', async (status) => {
    const client = {
      status,
      options: { commandTimeout: 500 },
      once: jest.fn(),
      ping: jest.fn().mockResolvedValue('PONG')
    }

    await expect((await check(client)).onApplicationBootstrap()).resolves.toBeUndefined()
    expect(client.once).not.toHaveBeenCalled()
  })

  // Scenario: a client that gives up connecting while boot waits, or is already closed. Expected:
  // boot fails at once with the generic message, not at the deadline.
  it.each([
    ['gives up while boot waits', 'connecting'],
    ['is already closed', 'end']
  ])('fails boot at once for a client that %s', async (_why, status) => {
    let end: () => void = () => undefined
    const client = {
      status,
      options: { commandTimeout: 500 },
      once: jest.fn((event: string, listener: () => void) => {
        if (event === 'end') end = listener
      }),
      off: jest.fn(),
      ping: jest.fn()
    }
    const attempt = (await check(client)).onApplicationBootstrap()
    const assertion = expect(attempt).rejects.toThrow('[BymaxAuthModule] Redis did not answer PING')
    await Promise.resolve()
    end()

    await assertion
    expect(client.ping).not.toHaveBeenCalled()
  })

  // Scenario: a client that never becomes ready. Expected: boot fails at the deadline.
  it('fails boot at the deadline for a client that never becomes ready', async () => {
    jest.useFakeTimers()
    try {
      const client = {
        status: 'connecting',
        options: {},
        once: jest.fn(),
        off: jest.fn(),
        ping: jest.fn()
      }
      const attempt = (await check(client)).onApplicationBootstrap()
      const assertion = expect(attempt).rejects.toThrow(/did not answer PING within 5000 ms/)

      await jest.advanceTimersByTimeAsync(5000)

      await assertion
      expect(client.ping).not.toHaveBeenCalled()
    } finally {
      jest.useRealTimers()
    }
  })

  // Scenario: a REAL ioredis client pointed at a port nothing listens on, which gives up at once.
  // Expected: boot fails with the generic message and not the address ioredis would have quoted.
  // The fakes above invent the client's shape; this is the shape ioredis really has.
  it('fails boot for a real client that cannot connect, without the address', async () => {
    const client = new Redis({
      host: '127.0.0.1',
      port: 1,
      retryStrategy: () => null,
      maxRetriesPerRequest: 1,
      commandTimeout: 500
    })
    client.on('error', () => undefined)
    try {
      const attempt = (await check(client)).onApplicationBootstrap()

      await expect(attempt).rejects.toThrow('[BymaxAuthModule] Redis did not answer PING')
      await expect(attempt).rejects.not.toThrow(/127\.0\.0\.1|:1\b/)
    } finally {
      client.disconnect()
    }
  })
})
