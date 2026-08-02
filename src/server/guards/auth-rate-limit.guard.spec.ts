/**
 * @fileoverview Tests for AuthRateLimitGuard — the per-IP limit the library enforces itself,
 * rather than recommending to the host and hoping it wires a throttler.
 */

import { Test } from '@nestjs/testing'
import { Reflector } from '@nestjs/core'
import type { ExecutionContext } from '@nestjs/common'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { hmacSha256 } from '../crypto/secure-token'
import { AUTH_RATE_LIMIT_KEY } from '../decorators/auth-rate-limit.decorator'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { AuthRateLimitGuard } from './auth-rate-limit.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const HMAC_KEY = 'a'.repeat(64)
const LIMIT = { limit: 3, ttl: 60_000 }

const mockRedis = { incrWithFixedTtl: jest.fn() }
const setHeader = jest.fn()

/** Options with the limiter enabled unless a test says otherwise. */
function optionsWith(
  enabled: boolean,
  clientIpSource: 'peer' | 'trusted-proxy' = 'peer'
): Record<string, unknown> {
  return { rateLimit: { enabled, clientIpSource }, hmacKey: HMAC_KEY }
}

/**
 * A context for `AuthController.login`.
 *
 * Both address channels are separately controllable, because the whole point of the setting is
 * that they can disagree — a forwarded header says one thing, the socket says another.
 */
function contextFor(ip: unknown = '203.0.113.4', peer: unknown = '198.51.100.9'): ExecutionContext {
  const handler = function login(): void {}
  class AuthController {}
  return {
    getHandler: () => handler,
    getClass: () => AuthController,
    switchToHttp: () => ({
      getRequest: () => ({ ip, socket: { remoteAddress: peer } }),
      getResponse: () => ({ setHeader })
    })
  } as unknown as ExecutionContext
}

/** Build the guard with a reflector that reports `limit` for every handler. */
async function guardWith(
  limit: unknown,
  enabled = true,
  clientIpSource: 'peer' | 'trusted-proxy' = 'peer'
): Promise<AuthRateLimitGuard> {
  const module = await Test.createTestingModule({
    providers: [
      AuthRateLimitGuard,
      { provide: Reflector, useValue: { get: () => limit } },
      { provide: BYMAX_AUTH_OPTIONS, useValue: optionsWith(enabled, clientIpSource) },
      { provide: AuthRedisService, useValue: mockRedis }
    ]
  }).compile()
  return module.get(AuthRateLimitGuard)
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('AuthRateLimitGuard', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  // Under the limit the request passes and the counter advances — that is the whole
  // mechanism, and it must not consult anything else.
  it('admits a request inside the window and counts it', async () => {
    mockRedis.incrWithFixedTtl.mockResolvedValue(1)
    const guard = await guardWith(LIMIT)

    await expect(guard.canActivate(contextFor())).resolves.toBe(true)
    expect(mockRedis.incrWithFixedTtl).toHaveBeenCalledTimes(1)
  })

  // The boundary: the limit is the number of requests allowed, so the Nth still passes and
  // only the N+1th is refused. An off-by-one here either leaks a request or eats one.
  it('admits exactly `limit` requests and refuses the next', async () => {
    const guard = await guardWith(LIMIT)

    mockRedis.incrWithFixedTtl.mockResolvedValue(3)
    await expect(guard.canActivate(contextFor())).resolves.toBe(true)

    mockRedis.incrWithFixedTtl.mockResolvedValue(4)
    await expect(guard.canActivate(contextFor())).rejects.toBeInstanceOf(AuthException)
  })

  // The refusal is the library's own envelope with a 429, not whatever a third-party
  // throttler would produce — a client must not have to parse two shapes depending on which
  // backend answered.
  it('refuses with the auth envelope, a 429, and Retry-After', async () => {
    mockRedis.incrWithFixedTtl.mockResolvedValue(99)
    const guard = await guardWith(LIMIT)

    let thrown: unknown
    try {
      await guard.canActivate(contextFor())
    } catch (error) {
      thrown = error
    }

    expect(thrown).toBeInstanceOf(AuthException)
    expect((thrown as AuthException).getStatus()).toBe(429)
    expect((thrown as AuthException).getResponse()).toMatchObject({
      error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOO_MANY_REQUESTS })
    })
    // The window length, not the remaining time — the remaining time would tell a caller
    // exactly when the window opened.
    expect(setHeader).toHaveBeenCalledWith('Retry-After', 60)
  })

  // The counter is scoped per route and keyed by the HMAC of the IP: a burst of logins must
  // not exhaust the budget for password resets, and the keyspace must not hold a raw address.
  it('keys the counter per route, by the HMAC of the IP', async () => {
    mockRedis.incrWithFixedTtl.mockResolvedValue(1)
    const guard = await guardWith(LIMIT)

    await guard.canActivate(contextFor('198.51.100.9'))

    const [key, windowSeconds] = mockRedis.incrWithFixedTtl.mock.calls[0] as [string, number]
    expect(key).toBe(`rl:AuthController.login:${hmacSha256('198.51.100.9', HMAC_KEY)}`)
    expect(key).not.toContain('198.51.100.9')
    expect(windowSeconds).toBe(60)
  })

  // A request with no resolvable IP still gets counted rather than waved through, all such
  // callers sharing one bucket. Skipping them would be a trivial bypass.
  it('counts a request whose IP cannot be resolved', async () => {
    mockRedis.incrWithFixedTtl.mockResolvedValue(1)
    const guard = await guardWith(LIMIT)

    // `null`, not `undefined`: a default parameter would swallow `undefined` and the test
    // would silently exercise the happy path instead. Both channels, because "cannot be
    // resolved" now means neither the forwarded address nor the socket yielded one.
    await guard.canActivate(contextFor(null, null))

    const [key] = mockRedis.incrWithFixedTtl.mock.calls[0] as [string]
    expect(key).toBe(`rl:AuthController.login:${hmacSha256('unknown', HMAC_KEY)}`)
  })

  // A sub-second window would round to a zero TTL, which Redis rejects — the key would then
  // never expire and the caller would be blocked permanently.
  it('clamps a sub-second window to one second', async () => {
    mockRedis.incrWithFixedTtl.mockResolvedValue(1)
    const guard = await guardWith({ limit: 1, ttl: 10 })

    await guard.canActivate(contextFor())

    expect(mockRedis.incrWithFixedTtl).toHaveBeenCalledWith(expect.any(String), 1)
  })

  // A route that declares no limit is not limited here. The decorator is the declaration, so
  // an undeclared route must not silently inherit some other route's budget.
  it('does not count a route that declares no limit', async () => {
    const guard = await guardWith(undefined)

    await expect(guard.canActivate(contextFor())).resolves.toBe(true)
    expect(mockRedis.incrWithFixedTtl).not.toHaveBeenCalled()
  })

  // The opt-out is for a deployment already enforcing the same limits at its edge; when it is
  // off, no counter is touched at all.
  it('is inert when rateLimit.enabled is false', async () => {
    const guard = await guardWith(LIMIT, false)

    await expect(guard.canActivate(contextFor())).resolves.toBe(true)
    expect(mockRedis.incrWithFixedTtl).not.toHaveBeenCalled()
  })

  // ---------------------------------------------------------------------------
  // Which address the limit is keyed on
  // ---------------------------------------------------------------------------

  describe('client IP source', () => {
    /** The HMAC'd address the guard actually counted against. */
    function keyedAddress(): string {
      const [key] = mockRedis.incrWithFixedTtl.mock.calls[0] as [string]
      return key
    }

    // Scenario: a forwarded header disagreeing with the socket, under the default. Expected:
    // the SOCKET address is counted. Why: this is the finding the setting exists for. Behind a
    // `trust proxy` that admits more hops than the deployment really has, `req.ip` is whatever
    // the caller wrote in `X-Forwarded-For` — and a limiter whose key the caller chooses is not
    // a limit. Over-counting is the safer direction, and it is recoverable by opting in.
    it('should key on the socket address by default, not the forwarded one', async () => {
      mockRedis.incrWithFixedTtl.mockResolvedValue(1)
      const guard = await guardWith(LIMIT)

      await guard.canActivate(contextFor('1.2.3.4', '198.51.100.9'))

      expect(keyedAddress()).toBe(`rl:AuthController.login:${hmacSha256('198.51.100.9', HMAC_KEY)}`)
      expect(keyedAddress()).not.toContain(hmacSha256('1.2.3.4', HMAC_KEY))
    })

    // Scenario: the same disagreement with the setting opted in. Expected: `req.ip` is counted.
    // Why: a deployment that has configured `trust proxy` for its real hop count wants the
    // client address, not its own load balancer's — which would put every user in one bucket.
    it('should key on req.ip when trusted-proxy is opted into', async () => {
      mockRedis.incrWithFixedTtl.mockResolvedValue(1)
      const guard = await guardWith(LIMIT, true, 'trusted-proxy')

      await guard.canActivate(contextFor('1.2.3.4', '198.51.100.9'))

      expect(keyedAddress()).toBe(`rl:AuthController.login:${hmacSha256('1.2.3.4', HMAC_KEY)}`)
    })

    // Scenario: no readable address on either channel, in either mode. Expected: one shared
    // bucket, not a per-request one. Why: an unreadable address must not read as "unlimited" —
    // that would make the limit skippable by whatever makes the address unreadable.
    it.each([
      ['peer', null, null],
      ['peer', '1.2.3.4', ''],
      ['trusted-proxy', null, '198.51.100.9'],
      ['trusted-proxy', '', '198.51.100.9']
    ])('should fall back to a shared bucket in %s mode', async (mode, ip, peer) => {
      mockRedis.incrWithFixedTtl.mockResolvedValue(1)
      const guard = await guardWith(LIMIT, true, mode as 'peer' | 'trusted-proxy')

      await guard.canActivate(contextFor(ip, peer))

      expect(keyedAddress()).toBe(`rl:AuthController.login:${hmacSha256('unknown', HMAC_KEY)}`)
    })

    // Scenario: a request with no socket at all, as a non-HTTP transport might present.
    it('should tolerate a request with no socket', async () => {
      mockRedis.incrWithFixedTtl.mockResolvedValue(1)
      const guard = await guardWith(LIMIT)
      const handler = function login(): void {}
      class AuthController {}
      const context = {
        getHandler: () => handler,
        getClass: () => AuthController,
        switchToHttp: () => ({
          getRequest: () => ({ ip: '1.2.3.4' }),
          getResponse: () => ({ setHeader })
        })
      } as unknown as ExecutionContext

      await expect(guard.canActivate(context)).resolves.toBe(true)
      expect(keyedAddress()).toBe(`rl:AuthController.login:${hmacSha256('unknown', HMAC_KEY)}`)
    })
  })
})
