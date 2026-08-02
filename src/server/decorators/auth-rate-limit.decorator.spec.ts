import { AUTH_RATE_LIMIT_KEY, AuthRateLimit } from './auth-rate-limit.decorator'

describe('AuthRateLimit decorator', () => {
  // The window reaches the guard as method metadata, so the decorator's whole job is to
  // stamp exactly what it was given under exactly the agreed key.
  it('should stamp the window on the decorated method', () => {
    class TestController {
      @(AuthRateLimit({ default: { limit: 5, ttl: 60_000 } }) as MethodDecorator)
      login() {}
    }

    const metadata: unknown = Reflect.getMetadata(
      AUTH_RATE_LIMIT_KEY,
      TestController.prototype.login
    )
    expect(metadata).toEqual({ limit: 5, ttl: 60_000 })
  })

  // The key is namespaced and pinned to its literal, not just to itself: the guard reads it
  // through this same constant, so a mutated value would round-trip perfectly — while a
  // consumer inspecting the metadata by name, or a second library stamping an unnamespaced
  // key, would silently disagree with the library.
  it('should expose a namespaced metadata key', () => {
    expect(AUTH_RATE_LIMIT_KEY).toBe('bymax:auth:rate-limit')

    class TestController {
      @(AuthRateLimit({ default: { limit: 1, ttl: 1_000 } }) as MethodDecorator)
      refresh() {}
    }

    // Read back by the literal a consumer would write, never through the constant.
    const byLiteral: unknown = Reflect.getMetadata(
      'bymax:auth:rate-limit',
      TestController.prototype.refresh
    )
    expect(byLiteral).toEqual({ limit: 1, ttl: 1_000 })
  })
})
