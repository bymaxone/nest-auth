/**
 * @fileoverview What the scripts are given when the client has a `keyPrefix`.
 *
 * A declared key is left to ioredis, which prefixes it. A name passed as an argument is not
 * touched by ioredis, so the service has to put the prefix there itself.
 *
 * @layer Test
 */

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'

import { AuthRedisService } from './auth-redis.service'

/** One recorded `eval`: the declared keys and the arguments. */
interface Call {
  keys: string[]
  argv: string[]
}

/** A service over a client with `options`, recording every script call. */
async function recording(
  options: object | undefined
): Promise<{ service: AuthRedisService; calls: Call[] }> {
  const calls: Call[] = []
  const client = {
    options,
    eval: jest.fn(async (_script: string, count: number, ...rest: string[]) => {
      calls.push({ keys: rest.slice(0, count), argv: rest.slice(count) })
      // The family revocation answers the members it removed; the other scripts here a count.
      return rest[0]?.startsWith('ns:fam:') ? [] : 0
    }),
    smembers: jest.fn().mockResolvedValue(['h1']),
    get: jest.fn().mockResolvedValue(JSON.stringify({ userId: 'u1', tenantId: 't1' }))
  }
  const module = await Test.createTestingModule({
    providers: [
      AuthRedisService,
      { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: client },
      {
        provide: BYMAX_AUTH_OPTIONS,
        useValue: { redisNamespace: 'ns', hmacKey: 'k'.repeat(32) }
      }
    ]
  }).compile()
  return { service: module.get(AuthRedisService), calls }
}

const ROTATION = {
  kind: 'dashboard' as const,
  tenantId: 't1',
  oldHash: 'old',
  newHash: 'new',
  newSessionJson: '{}',
  familyId: 'f1',
  userId: 'u1',
  refreshTtl: 60,
  graceTtl: 30
}

describe('AuthRedisService over a client with keyPrefix', () => {
  // Rotation hands the live-session prefix over as an argument, for the successor probe.
  it('gives the rotation script the live prefix as the server stores it', async () => {
    const { service, calls } = await recording({ keyPrefix: 'host:' })

    await service.rotateRefreshSession(ROTATION)

    expect(calls[0]?.argv[6]).toBe('host:ns:rt')
    expect(calls[0]?.keys[0]).toBe('ns:rt:old')
  })

  // The family revocation builds the record names and prunes the owner's index from arguments.
  it('gives the family revocation the stored namespace and index key', async () => {
    const { service, calls } = await recording({ keyPrefix: 'host:' })

    await service.revokeFamily('f1')

    expect(calls[0]?.argv[0]).toBe('host:ns')
    expect(calls[0]?.argv[3]).toMatch(/^host:ns:sess:/)
    expect(calls[0]?.keys[0]).toBe('ns:fam:f1')
  })

  // The three sweeps over a session index take the namespace as their first argument.
  it.each([
    [
      'the grace pruning',
      (service: AuthRedisService) => service.pruneExpiredGraceMembers('sess:x', 'rp:')
    ],
    [
      'the dead-member pruning',
      (service: AuthRedisService) => service.pruneDeadMembers('sess:x', ['rt:h'])
    ],
    [
      'the revocation of all sessions',
      (service: AuthRedisService) => service.invalidateUserSessions('u1', 't1', 'dashboard')
    ]
  ])('gives %s the stored namespace', async (_name, run) => {
    const { service, calls } = await recording({ keyPrefix: 'host:' })

    await run(service)

    expect(calls[0]?.argv[0]).toBe('host:ns')
    expect(calls[0]?.keys[0]?.startsWith('ns:')).toBe(true)
  })

  // A client with no prefix, and a stand-in with no options at all, give the namespace alone.
  it.each([
    ['an empty prefix', { keyPrefix: '' }],
    ['no prefix', {}],
    ['no options', undefined]
  ])('gives the namespace alone with %s', async (_name, options) => {
    const { service, calls } = await recording(options)

    await service.pruneDeadMembers('sess:x', ['rt:h'])

    expect(calls[0]?.argv[0]).toBe('ns')
  })

  // ioredis prepends bytes as bytes, so no string argument would name the same keys.
  it('refuses a client whose keyPrefix is not a string', async () => {
    await expect(recording({ keyPrefix: Buffer.from('host:') })).rejects.toThrow(
      '[BymaxAuthModule] The keyPrefix of BYMAX_AUTH_REDIS_CLIENT must be a string.'
    )
  })
})
