/**
 * @fileoverview What `AuthRedisService.writeNewSession` hands the store: the three records of the
 * session first, then the records written with it, each under the namespace.
 */

import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS, BYMAX_AUTH_REDIS_CLIENT } from '../bymax-auth.constants'
import { AuthRedisService } from './auth-redis.service'
import { CREATE_SESSION_LUA } from './create-session-script'

const FAMILY = '4d6e1c2a-8b3f-4a5e-9c7d-0e1f2a3b4c5d'
const BASE = {
  kind: 'dashboard' as const,
  tenantId: 'tenant-1',
  tokenHash: 'h1',
  sessionJson: '{"userId":"u1"}',
  familyId: FAMILY,
  userId: 'u1',
  refreshTtl: 604800
}

describe('AuthRedisService.writeNewSession', () => {
  const client = { eval: jest.fn().mockResolvedValue(1) }
  let service: AuthRedisService

  beforeEach(async () => {
    client.eval.mockClear()
    const module = await Test.createTestingModule({
      providers: [
        AuthRedisService,
        { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: client },
        { provide: BYMAX_AUTH_OPTIONS, useValue: { redisNamespace: 'auth', hmacKey: 'k' } }
      ]
    }).compile()
    service = module.get(AuthRedisService)
  })

  // Scenario: a session with two extra records. Expected: one EVAL of the creation script whose
  // keys are the three session keys then the extras, namespaced, and whose arguments are the five
  // fixed ones then each extra's value and lifetime. Why: the script pairs them by position.
  it('passes the extras after the three session keys and the five fixed arguments', async () => {
    await service.writeNewSession({
      ...BASE,
      extras: [
        { key: 'ra:mark', value: '1', ttl: 300 },
        { key: 'sd:h1', value: '{"device":"x"}', ttl: 604800 }
      ]
    })

    const call = client.eval.mock.calls[0] as unknown[]
    expect(client.eval).toHaveBeenCalledTimes(1)
    expect(call[0]).toBe(CREATE_SESSION_LUA)
    expect(call[1]).toBe(5)
    expect((call.slice(2, 7) as string[]).filter((k) => k.startsWith('auth:'))).toHaveLength(5)
    expect(call.slice(5, 7)).toEqual(['auth:ra:mark', 'auth:sd:h1'])
    expect(call.slice(7)).toEqual([
      '{"userId":"u1"}',
      '604800',
      FAMILY,
      'rt',
      'h1',
      '1',
      '300',
      '{"device":"x"}',
      '604800'
    ])
  })

  it('passes only the session keys and the five fixed arguments when there are no extras', async () => {
    await service.writeNewSession(BASE)

    const call = client.eval.mock.calls[0] as unknown[]
    expect(call[1]).toBe(3)
    expect(call.slice(5)).toEqual(['{"userId":"u1"}', '604800', FAMILY, 'rt', 'h1'])
  })

  // Scenario: an extra that would make the script fail. Expected: refused, and nothing is sent.
  it('refuses a bad extra before anything is sent', async () => {
    await expect(
      service.writeNewSession({ ...BASE, extras: [{ key: 'ra:mark', value: '1', ttl: 0 }] })
    ).rejects.toThrow(TypeError)

    expect(client.eval).not.toHaveBeenCalled()
  })
})
