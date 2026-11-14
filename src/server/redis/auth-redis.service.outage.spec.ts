/**
 * @fileoverview Every Redis call of `AuthRedisService` answers an outage with the typed 503.
 *
 * Each case rejects one raw client command the way a real ioredis client does when the store does
 * not answer, calls the public method that issues it, and asserts the library's `503
 * auth.service_unavailable` with the client's error on `cause`. A reply error that is a mistake
 * stays the error it is.
 */

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from './auth-redis.service'

const COMMANDS = [
  'get',
  'set',
  'del',
  'incr',
  'expire',
  'ttl',
  'sadd',
  'srem',
  'smembers',
  'sismember',
  'exists',
  'eval'
] as const

describe('AuthRedisService under a Redis outage', () => {
  const client = Object.fromEntries(COMMANDS.map((name) => [name, jest.fn()]))
  let service: AuthRedisService

  beforeEach(async () => {
    jest.resetAllMocks()
    const module = await Test.createTestingModule({
      providers: [
        AuthRedisService,
        { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: client },
        { provide: BYMAX_AUTH_OPTIONS, useValue: { redisNamespace: 'auth', hmacKey: 'k' } }
      ]
    }).compile()
    service = module.get(AuthRedisService)
  })

  /** The public call that issues each raw command. */
  const CALLS: ReadonlyArray<[string, () => Promise<unknown>]> = [
    ['get', () => service.get('k')],
    ['set', () => service.set('k', 'v', 60)],
    ['set', () => service.setnx('k', 60)],
    ['del', () => service.del('k')],
    ['incr', () => service.incr('k')],
    ['expire', () => service.expire('k', 60)],
    ['ttl', () => service.ttl('k')],
    ['sadd', () => service.sadd('s', 'm')],
    ['srem', () => service.srem('s', 'm')],
    ['smembers', () => service.smembers('s')],
    ['sismember', () => service.sismember('s', 'm')],
    ['eval', () => service.eval('return 1', [], [])]
  ]

  // Scenario: the store does not answer in time. Expected: the typed 503, the client's error as
  // its cause, and no store text in the body.
  it.each(CALLS)('maps a timeout of %s to the typed 503', async (command, call) => {
    const timeout = new Error('Command timed out')
    client[command]?.mockRejectedValue(timeout)

    const rejection = (await call().catch((error: unknown) => error)) as AuthException

    expect(rejection).toBeInstanceOf(AuthException)
    expect(rejection.getStatus()).toBe(503)
    expect(rejection.cause).toBe(timeout)
    expect(JSON.stringify(rejection.getResponse())).not.toContain('timed out')
  })

  // Scenario: the client refuses the command because its connection is gone. Expected: the same.
  it('maps a closed connection to the typed 503', async () => {
    client['get']?.mockRejectedValue(new Error('Connection is closed.'))

    await expect(service.get('k')).rejects.toMatchObject({ status: 503 })
  })

  // Scenario: Redis replies with a script error, which is a bug and not an outage. Expected: the
  // same error object, so it is not answered as "try again".
  it('leaves a reply error that is a mistake as it is', async () => {
    const mistake = Object.assign(new Error('NOSCRIPT No matching script. Please use EVAL.'), {
      name: 'ReplyError'
    })
    client['eval']?.mockRejectedValue(mistake)

    await expect(service.eval('return 1', [], [])).rejects.toBe(mistake)
  })

  // Scenario: the store answers. Expected: the value, so the wrapper changes nothing when Redis is
  // up.
  it('returns the stored value when the store answers', async () => {
    client['get']?.mockResolvedValue('value')

    await expect(service.get('k')).resolves.toBe('value')
  })
})
