/**
 * @fileoverview The two paths where a store outage is absorbed although the request is on a path
 * that answers 503 when the store fails, which a sibling implementation that read the contract
 * literally would get wrong:
 *
 *   - a logout whose session-metadata cleanup cannot reach the store still answers 204: the
 *     revocation writes that decide the logout succeeded;
 *   - a failed login whose lockout state cannot be read afterwards still answers its 401: the two
 *     reads exist only to feed an event hook.
 *
 * The contract states the rule (`serviceUnavailable.absorption`): a call whose result the answer
 * does not depend on is logged and absorbed, one it does depend on never is. The typed 503 is what
 * the library's Redis wrapper raises for an outage, so the failures here are that exception.
 */

import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { BYMAX_AUTH_HOOKS } from '../../src/server/bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../../src/server/errors/auth-error-codes'
import { AuthException } from '../../src/server/errors/auth-exception'
import { AuthRedisService } from '../../src/server/redis/auth-redis.service'
import { bootstrapTestApp } from './setup'

const UNAVAILABLE = (): AuthException => new AuthException(AUTH_ERROR_CODES.SERVICE_UNAVAILABLE)
const PASSWORD = 'Absorbed123!-xyz'

describe('an outage that is absorbed on a path that otherwise answers 503 (E2E)', () => {
  let app: INestApplication

  beforeEach(async () => {
    // The lockout reads that follow a failed login exist only to feed `onLockout`, so they run only
    // when the host defines it.
    const boot = await bootstrapTestApp(
      { tokenDelivery: 'bearer', sessions: { enabled: true } },
      {
        mutateBuilder: (builder) =>
          builder
            .overrideProvider(BYMAX_AUTH_HOOKS)
            .useValue({ onLockout: jest.fn() }) as typeof builder
      }
    )
    app = boot.app
  })

  afterEach(async () => {
    jest.restoreAllMocks()
    await app.close()
  })

  async function register(): Promise<{ accessToken: string; refreshToken: string }> {
    const res = await request(app.getHttpServer())
      .post('/register')
      .send({ email: 'absorbed@example.com', password: PASSWORD, name: 'Absorbed', tenantId: 't1' })
    expect(res.status).toBe(201)
    return res.body as { accessToken: string; refreshToken: string }
  }

  // Scenario: the session-metadata cleanup of a logout (the Lua script that removes the session
  // from its index) cannot reach the store, while the revocation writes succeed. Expected: the
  // logout answers 204, exactly as a healthy one does.
  it('answers a logout 204 when only its session-metadata cleanup fails', async () => {
    const tokens = await register()
    const redis = app.get(AuthRedisService)
    const evaluate = redis.eval.bind(redis)
    let cleanupFailed = 0
    jest.spyOn(redis, 'eval').mockImplementation((script, keys, args) => {
      if (script.includes('SISMEMBER')) {
        cleanupFailed += 1
        return Promise.reject(UNAVAILABLE())
      }
      return evaluate(script, keys, args)
    })

    const res = await request(app.getHttpServer())
      .post('/logout')
      .set('Authorization', `Bearer ${tokens.accessToken}`)
      .send({ refreshToken: tokens.refreshToken })

    expect(cleanupFailed).toBe(1)
    expect(res.status).toBe(204)
  })

  // Scenario: a wrong password, then the store fails the lockout reads that only feed the
  // onLockout hook. Expected: the caller still gets the 401 a healthy store gives, never a 503.
  it('answers a failed login 401 when only the lockout reads after it fail', async () => {
    await register()
    const redis = app.get(AuthRedisService)
    const read = redis.get.bind(redis)
    let lockoutReads = 0
    jest.spyOn(redis, 'get').mockImplementation((key) => {
      if (key.startsWith('lf:')) {
        lockoutReads += 1
        // The first read is the pre-check, which is security state and fails closed; every later
        // read feeds the hook.
        if (lockoutReads > 1) return Promise.reject(UNAVAILABLE())
      }
      return read(key)
    })

    const res = await request(app.getHttpServer())
      .post('/login')
      .send({ email: 'absorbed@example.com', password: 'not-the-password', tenantId: 't1' })

    expect(lockoutReads).toBeGreaterThan(1)
    expect(res.status).toBe(401)
    expect((res.body as { error: { code: string } }).error.code).toBe(
      AUTH_ERROR_CODES.INVALID_CREDENTIALS
    )
  })

  // Scenario: the same pre-check failing. Expected: 503, because the counter is security state and
  // the answer depends on it. This is the other half of the rule, so the two cannot be read as
  // "every Redis failure is absorbed".
  it('answers a login 503 when the lockout pre-check itself fails', async () => {
    await register()
    const redis = app.get(AuthRedisService)
    const read = redis.get.bind(redis)
    jest
      .spyOn(redis, 'get')
      .mockImplementation((key) =>
        key.startsWith('lf:') ? Promise.reject(UNAVAILABLE()) : read(key)
      )

    const res = await request(app.getHttpServer())
      .post('/login')
      .send({ email: 'absorbed@example.com', password: PASSWORD, tenantId: 't1' })

    expect(res.status).toBe(503)
  })
})
