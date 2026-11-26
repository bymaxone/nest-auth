/**
 * @fileoverview Every reader of an integer reply, over a reply that spells no integer.
 *
 * @layer Test
 */

import type { ExecutionContext } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Redis } from 'ioredis'

import { AuthRedisService } from './auth-redis.service'
import { publishInvitation } from './publish-invitation.script'
import { releaseIndex } from './release-index.script'
import { withdrawInvitation } from './withdraw-invitation.script'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { BruteForceService } from '../services/brute-force.service'
import { SessionService } from '../services/session.service'
import { WorkspaceInvitationStore } from '../services/workspace-invitation.store'

const OPTIONS: ResolvedOptions = Object.assign(Object.create(null), {
  redisNamespace: 'spec',
  hmacKey: 'integer-reply-callers-spec-key',
  rateLimit: { enabled: true, clientIpSource: 'peer' },
  bruteForce: { maxAttempts: 5, windowSeconds: 60 }
})

/** The service over a client on which every integer command and script answers `reply`. */
function answering(reply: unknown): AuthRedisService {
  const client: Redis = Object.create(null)
  const answer = (): Promise<unknown> => Promise.resolve(reply)
  for (const command of ['del', 'incr', 'ttl', 'sadd', 'srem', 'sismember', 'exists', 'eval']) {
    Object.assign(client, { [command]: answer })
  }
  Object.assign(client, { smembers: (): Promise<string[]> => Promise.resolve([]) })
  return new AuthRedisService(client, OPTIONS)
}

/** A grace recovery whose family lookup answers `reply`. */
function recoveringFrom(reply: unknown): Promise<unknown> {
  const service = answering(reply)
  jest.spyOn(service, 'eval').mockResolvedValue(`GRACE:${JSON.stringify({ familyId: 'f1' })}`)
  return service.rotateRefreshSession({
    kind: 'dashboard',
    tenantId: 't1',
    userId: 'u1',
    familyId: 'f1',
    oldHash: 'old',
    newHash: 'new',
    newSessionJson: '{}',
    refreshTtl: 60,
    graceTtl: 10
  })
}

function sessions(redis: AuthRedisService): SessionService {
  const none: never = null as never
  return new SessionService(OPTIONS, none, null, redis)
}

const publication = {
  indexKey: 'i',
  tokenHash: 'h',
  record: '{}',
  ttl: 60,
  superseded: null
}

const callers: [string, (s: AuthRedisService) => Promise<unknown>][] = [
  ['del', (s) => s.del('k')],
  ['incr', (s) => s.incr('k')],
  ['ttl', (s) => s.ttl('k')],
  ['sadd', (s) => s.sadd('k', 'm')],
  ['srem', (s) => s.srem('k', 'm')],
  ['sismember', (s) => s.sismember('k', 'm')],
  [
    'writeRecoveredSession',
    (s) =>
      s.writeRecoveredSession({
        kind: 'dashboard',
        tenantId: 't1',
        userId: 'u1',
        familyId: 'f1',
        newHash: 'new',
        newSessionJson: '{}',
        refreshTtl: 60
      })
  ],
  ['revokeFamily', (s) => s.revokeFamily('f1')],
  ['pruneExpiredGraceMembers', (s) => s.pruneExpiredGraceMembers('set', 'rp:')],
  ['pruneDeadMembers', (s) => s.pruneDeadMembers('set', ['rt:a'])],
  ['incrWithFixedTtl', (s) => s.incrWithFixedTtl('k', 60)],
  ['bumpUserTokenEpoch', (s) => s.bumpUserTokenEpoch('u1', 't1', 'dashboard')],
  ['publishInvitation', (s) => publishInvitation(s, publication)],
  ['withdrawInvitation', (s) => withdrawInvitation(s, 'i', 'h', null)],
  ['releaseIndex', (s) => releaseIndex(s, 'i', 'h')],
  [
    'WorkspaceInvitationStore.publish',
    (s) =>
      new WorkspaceInvitationStore(s, OPTIONS).publish(
        { tenantId: 't1', workspaceId: 'w1' },
        'a@example.com',
        'winv:a',
        Object.create(null),
        60,
        0,
        null
      )
  ],
  [
    'SessionService.revokeSession',
    (s) => sessions(s).revokeSession({ userId: 'u1', tenantId: 't1', sessionHash: 'a'.repeat(64) })
  ],
  ['BruteForceService.recordFailure', (s) => new BruteForceService(s, OPTIONS).recordFailure('id')],
  [
    'BruteForceService.getRemainingLockoutSeconds',
    (s) => new BruteForceService(s, OPTIONS).getRemainingLockoutSeconds('id')
  ]
]

const refused = { response: { error: { code: AUTH_ERROR_CODES.INTERNAL } } }

describe('a reply that spells no integer', () => {
  // Scenario: each reader of an integer reply gets `OK`. Expected: `auth.internal`. Why: read as
  // `0`, a counter says nothing was counted and a limit never fires.
  it.each(callers)('is refused by %s', async (_caller, call) => {
    await expect(call(answering('OK'))).rejects.toMatchObject(refused)
  })

  // Scenario: the family lookup of a grace recovery answers `OK`. Expected: `auth.internal`.
  it('is refused by a grace recovery asking for its family', async () => {
    await expect(recoveringFrom('OK')).rejects.toMatchObject(refused)
  })

  // Scenario: the rate limiter's counter answers no integer. Expected: the request is refused.
  it.each([[null], [''], ['OK'], [undefined]])(
    'keeps the rate limiter closed on %p',
    async (reply) => {
      const reflector = Object.assign(new Reflector(), { get: () => ({ limit: 3, ttl: 60_000 }) })
      const guard = new AuthRateLimitGuard(reflector, OPTIONS, answering(reply))
      const context: ExecutionContext = Object.assign(Object.create(null), {
        getHandler: () => function login(): void {},
        getClass: () => class AuthController {},
        switchToHttp: () => ({
          getRequest: () => ({ socket: { remoteAddress: '198.51.100.9' } }),
          getResponse: () => ({ setHeader: jest.fn() })
        })
      })

      await expect(guard.canActivate(context)).rejects.toMatchObject(refused)
    }
  )
})
