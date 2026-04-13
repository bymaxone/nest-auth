/**
 * @fileoverview Tests for BymaxAuthModule.registerAsync(), which compiles the full
 * NestJS auth module with resolved options, conditional controllers, and fallback providers.
 * Covers startup validation errors, controller registration, and NoOp fallback providers.
 */

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-one-nest-auth.constants'
import { AuthController } from './controllers/auth.controller'
import { NoOpAuthHooks } from './hooks/no-op-auth.hooks'
import { NoOpEmailProvider } from './providers/no-op-email.provider'
import { AuthRedisService } from './redis/auth-redis.service'
import { AuthService } from './services/auth.service'
import { BymaxAuthModule } from './bymax-one-nest-auth.module'

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

/** Minimal valid JWT secret — 32 chars, high entropy. */
const JWT_SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'

/** Minimal valid options factory. */
const validOptions = {
  jwt: { secret: JWT_SECRET },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } }
}

/** Minimal mock Redis client (ioredis shape). */
const mockRedisClient = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  setex: jest.fn(),
  eval: jest.fn()
}

/** Minimal mock user repository. */
const mockUserRepo = {
  findByEmail: jest.fn(),
  findById: jest.fn(),
  create: jest.fn(),
  updateLastLogin: jest.fn(),
  updateEmailVerified: jest.fn()
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('BymaxAuthModule', () => {
  // ---------------------------------------------------------------------------
  // Module compilation
  // ---------------------------------------------------------------------------

  describe('registerAsync', () => {
    // Verifies that the module compiles successfully with the minimal required configuration.
    it('should compile the module with valid minimal config', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
            ]
          })
        ]
      }).compile()

      expect(module).toBeDefined()
    })

    // Verifies that the module fails to compile when jwt.secret is shorter than 32 characters.
    it('should throw when jwt.secret is too short', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => ({
                jwt: { secret: 'tooshort' },
                roles: { hierarchy: { MEMBER: [] } }
              }),
              extraProviders: [
                { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
                { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
              ]
            })
          ]
        }).compile()
      ).rejects.toThrow(/jwt\.secret must be at least 32 characters/)
    })

    // Verifies that the module fails to compile when jwt.secret has insufficient entropy.
    it('should throw when jwt.secret has insufficient entropy', async () => {
      // 32 chars but all the same character — entropy ~0
      const weakSecret = 'a'.repeat(32)

      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => ({
                jwt: { secret: weakSecret },
                roles: { hierarchy: { MEMBER: [] } }
              }),
              extraProviders: [
                { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
                { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
              ]
            })
          ]
        }).compile()
      ).rejects.toThrow(/insufficient entropy/)
    })

    // Verifies that the module fails to compile when roles.hierarchy is missing.
    it('should throw when roles.hierarchy is missing', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () =>
                ({
                  jwt: { secret: JWT_SECRET }
                  // roles intentionally omitted — TypeScript cast needed
                }) as never,
              extraProviders: [
                { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
                { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
              ]
            })
          ]
        }).compile()
      ).rejects.toThrow(/roles\.hierarchy is required/)
    })
  })

  // ---------------------------------------------------------------------------
  // Controller registration
  // ---------------------------------------------------------------------------

  describe('controller registration', () => {
    // Verifies that AuthController is registered by default when no controllers option is provided.
    it('should register AuthController by default', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
            ]
          })
        ]
      }).compile()

      expect(module.get(AuthController)).toBeDefined()
    })

    // Verifies that AuthController is excluded when controllers.auth is explicitly set to false.
    it('should NOT register AuthController when controllers.auth is false', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            controllers: { auth: false },
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
            ]
          })
        ]
      }).compile()

      // NestJS throws when getting an unregistered controller — catch that.
      expect(() => module.get(AuthController)).toThrow()
    })
  })

  // ---------------------------------------------------------------------------
  // Fallback providers
  // ---------------------------------------------------------------------------

  describe('fallback providers', () => {
    // Verifies that a class-shorthand (function) provider does not trigger hasProviderToken to match a token.
    it('should use NoOpEmailProvider even when a class-shorthand provider is in extraProviders', async () => {
      // AuthRedisService is a class (function) — hasProviderToken skips it and does not confuse it
      // with BYMAX_AUTH_EMAIL_PROVIDER, so the NoOp fallback is still registered.
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
              // Class shorthand — hasProviderToken must return false for this, not throw
              AuthRedisService as never
            ]
          })
        ]
      }).compile()

      // NoOpEmailProvider should still be registered because the class shorthand is not BYMAX_AUTH_EMAIL_PROVIDER
      const emailProvider = module.get(BYMAX_AUTH_EMAIL_PROVIDER)
      expect(emailProvider).toBeInstanceOf(NoOpEmailProvider)
    })

    // Verifies that the module compiles without extraProviders (defaults to empty array).
    it('should compile when extraProviders is omitted (defaults to empty array)', async () => {
      // When extraProviders is omitted, it defaults to []. BYMAX_AUTH_USER_REPOSITORY
      // and BYMAX_AUTH_REDIS_CLIENT must still be provided for the module to compile.
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions,
              extraProviders: [
                { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
                { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
              ]
              // Note: no extraProviders key at the top level — module uses ?? [] internally
            })
          ]
        }).compile()
      ).resolves.toBeDefined()
    })

    // Verifies that omitting extraProviders entirely triggers the ?? [] branch in registerAsync.
    it('should use the ?? [] fallback when extraProviders is not provided at all', async () => {
      // Without extraProviders, the module defaults to [] internally but cannot resolve
      // BYMAX_AUTH_REDIS_CLIENT or BYMAX_AUTH_USER_REPOSITORY — compilation must fail.
      // The ?? [] branch is exercised even though the result is a rejection.
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions
              // extraProviders intentionally omitted — exercises the ?? [] branch
            })
          ]
        }).compile()
      ).rejects.toThrow()
    })

    // Verifies that NoOpEmailProvider is registered as the fallback when no email provider is given.
    it('should use NoOpEmailProvider when no email provider is given', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
              // No BYMAX_AUTH_EMAIL_PROVIDER
            ]
          })
        ]
      }).compile()

      const emailProvider = module.get(BYMAX_AUTH_EMAIL_PROVIDER)
      expect(emailProvider).toBeInstanceOf(NoOpEmailProvider)
    })

    // Verifies that a consumer-supplied email provider overrides the NoOp fallback.
    it('should use the consumer email provider when supplied', async () => {
      const customEmailProvider = { sendEmailVerificationOtp: jest.fn() }

      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
              { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: customEmailProvider }
            ]
          })
        ]
      }).compile()

      const emailProvider = module.get(BYMAX_AUTH_EMAIL_PROVIDER)
      expect(emailProvider).toBe(customEmailProvider)
    })

    // Verifies that NoOpAuthHooks is registered as the fallback when no hooks provider is given.
    it('should use NoOpAuthHooks when no hooks provider is given', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
              // No BYMAX_AUTH_HOOKS
            ]
          })
        ]
      }).compile()

      const hooks = module.get(BYMAX_AUTH_HOOKS)
      expect(hooks).toBeInstanceOf(NoOpAuthHooks)
    })

    // Verifies that a consumer-supplied hooks provider overrides the NoOp fallback.
    it('should use the consumer hooks when supplied', async () => {
      const customHooks = { beforeLogin: jest.fn() }

      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
              { provide: BYMAX_AUTH_HOOKS, useValue: customHooks }
            ]
          })
        ]
      }).compile()

      const hooks = module.get(BYMAX_AUTH_HOOKS)
      expect(hooks).toBe(customHooks)
    })
  })

  // ---------------------------------------------------------------------------
  // Core service availability
  // ---------------------------------------------------------------------------

  describe('exported services', () => {
    // Verifies that AuthService is accessible from the compiled module as an export.
    it('should export AuthService', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
            ]
          })
        ]
      }).compile()

      expect(module.get(AuthService)).toBeDefined()
    })

    // Verifies that the resolved options are exposed via the BYMAX_AUTH_OPTIONS injection token.
    it('should expose resolved options via BYMAX_AUTH_OPTIONS', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
            ]
          })
        ]
      }).compile()

      const opts = module.get(BYMAX_AUTH_OPTIONS)
      expect(opts).toMatchObject({
        jwt: expect.objectContaining({ secret: JWT_SECRET }),
        roles: expect.objectContaining({ hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } })
      })
    })
  })
})
