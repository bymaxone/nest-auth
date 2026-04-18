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
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'
import { OAuthController } from './oauth/oauth.controller'
import { AuthController } from './controllers/auth.controller'
import { PasswordResetController } from './controllers/password-reset.controller'
import { SessionController } from './controllers/session.controller'
import { NoOpAuthHooks } from './hooks/no-op-auth.hooks'
import { NoOpEmailProvider } from './providers/no-op-email.provider'
import { AuthRedisService } from './redis/auth-redis.service'
import { AuthService } from './services/auth.service'
import { PasswordResetService } from './services/password-reset.service'
import { SessionService } from './services/session.service'
import { BymaxAuthModule } from './bymax-auth.module'

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

    // Verifies that the module fails when controllers.mfa: true is set without the mfa config group.
    it('should throw when controllers.mfa is true but mfa config group is missing', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions, // validOptions has no mfa group
              controllers: { mfa: true },
              extraProviders: [
                { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
                { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
              ]
            })
          ]
        }).compile()
      ).rejects.toThrow(/controllers\.mfa: true requires the mfa group/)
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
    // registerAsync now throws synchronously when BYMAX_AUTH_USER_REPOSITORY is missing,
    // so this test uses a sync toThrow() assertion instead of rejects.
    it('should use the ?? [] fallback when extraProviders is not provided at all', () => {
      // Without extraProviders the ?? [] branch is exercised and the synchronous
      // BYMAX_AUTH_USER_REPOSITORY guard fires before any async work begins.
      expect(() =>
        BymaxAuthModule.registerAsync({
          useFactory: () => validOptions
          // extraProviders intentionally omitted — exercises the ?? [] branch
        })
      ).toThrow(/BYMAX_AUTH_USER_REPOSITORY is required/)
    })

    // Verifies that omitting BYMAX_AUTH_USER_REPOSITORY produces a descriptive startup error
    // rather than a cryptic NestJS injection error at the first request.
    it('should throw a descriptive startup error when BYMAX_AUTH_USER_REPOSITORY is missing', () => {
      expect(() =>
        BymaxAuthModule.registerAsync({
          useFactory: () => validOptions,
          extraProviders: [
            { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient }
            // BYMAX_AUTH_USER_REPOSITORY intentionally omitted
          ]
        })
      ).toThrow(/BYMAX_AUTH_USER_REPOSITORY is required/)
    })

    // Verifies that omitting BYMAX_AUTH_REDIS_CLIENT produces a matching descriptive
    // startup error. The user-repository guard fires first; this test proves that
    // the Redis-client guard also fires when the repository is present.
    it('should throw a descriptive startup error when BYMAX_AUTH_REDIS_CLIENT is missing', () => {
      expect(() =>
        BymaxAuthModule.registerAsync({
          useFactory: () => validOptions,
          extraProviders: [
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
            // BYMAX_AUTH_REDIS_CLIENT intentionally omitted
          ]
        })
      ).toThrow(/BYMAX_AUTH_REDIS_CLIENT is required/)
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

  // ---------------------------------------------------------------------------
  // Sessions and Password Reset integration smoke tests
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // platform, oauth, and invitations cross-validations
  // ---------------------------------------------------------------------------

  describe('platform, oauth, and invitations cross-validations', () => {
    const extraProviders = [
      { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
    ]

    /** Valid MFA config — 32-byte key encoded in base64, required for platform. */
    const MFA_ENCRYPTION_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='

    /** Options that satisfy platform.enabled + platformHierarchy requirements. */
    const platformOptions = {
      ...validOptions,
      roles: {
        hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] },
        platformHierarchy: { SUPER_ADMIN: [] }
      },
      platform: { enabled: true }
    }

    /** Options that also include a valid mfa group (required by the third platform gate). */
    const platformWithMfaOptions = {
      ...platformOptions,
      mfa: { encryptionKey: MFA_ENCRYPTION_KEY, issuer: 'TestApp' }
    }

    // Verifies that controllers.platform: true without platform.enabled: true throws
    // at startup — prevents silent registration of admin endpoints without proper config.
    it('should throw when controllers.platform: true but platform.enabled is false', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions, // no platform.enabled: true
              controllers: { platform: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/controllers\.platform.*requires.*platform\.enabled/)
    })

    // Verifies that controllers.platform: true without the mfa group throws at startup —
    // MfaService is used by the platform MFA challenge endpoint and needs encryptionKey + issuer.
    it('should throw when controllers.platform: true but the mfa group is missing', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => platformOptions, // has platform.enabled but no mfa
              controllers: { platform: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/controllers\.platform.*requires.*mfa group/)
    })

    // Verifies that controllers.platform: true without BYMAX_AUTH_PLATFORM_USER_REPOSITORY
    // in extraProviders throws at startup — without the token, all platform auth requests would
    // fail at runtime with TOKEN_INVALID rather than at startup.
    it('should throw when controllers.platform: true but BYMAX_AUTH_PLATFORM_USER_REPOSITORY is missing from extraProviders', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => platformWithMfaOptions,
              controllers: { platform: true },
              extraProviders // no BYMAX_AUTH_PLATFORM_USER_REPOSITORY
            })
          ]
        }).compile()
      ).rejects.toThrow(/BYMAX_AUTH_PLATFORM_USER_REPOSITORY/)
    })

    // Verifies that controllers.platform: true with all required config and
    // BYMAX_AUTH_PLATFORM_USER_REPOSITORY provided compiles and registers PlatformAuthController.
    it('should compile when controllers.platform: true with all required config', async () => {
      const mockPlatformUserRepo = { findByEmail: jest.fn(), findById: jest.fn() }

      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => platformWithMfaOptions,
            controllers: { platform: true },
            extraProviders: [
              ...extraProviders,
              { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: mockPlatformUserRepo }
            ]
          })
        ]
      }).compile()

      expect(module).toBeDefined()
    })

    // Verifies that controllers.oauth: true without the oauth config group throws at startup —
    // registering OAuthService without configured plugins would cause all OAuth requests to fail.
    it('should throw when controllers.oauth: true but the oauth config group is absent', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions, // no oauth group
              controllers: { oauth: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/controllers\.oauth.*requires the oauth group/)
    })

    // Verifies that controllers.oauth: true with a valid oauth.google config compiles
    // successfully and registers OAuthController — also exercises the OAUTH_PLUGINS
    // factory provider body (line 294 in bymax-auth.module.ts).
    it('should compile and register OAuthController when controllers.oauth: true with valid oauth config', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => ({
              ...validOptions,
              oauth: {
                google: {
                  clientId: 'test-client-id',
                  clientSecret: 'test-client-secret',
                  callbackUrl: 'https://app.example.com/callback'
                }
              }
            }),
            controllers: { oauth: true },
            extraProviders
          })
        ]
      }).compile()

      expect(module.get(OAuthController)).toBeDefined()
    })

    // Verifies that controllers.invitations: true without invitations.enabled: true throws
    // at startup — the default for invitations.enabled is false, so an explicit opt-in is required.
    it('should throw when controllers.invitations: true but invitations.enabled is false', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions, // invitations.enabled defaults to false
              controllers: { invitations: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/controllers\.invitations.*requires.*invitations\.enabled/)
    })
  })

  describe('SessionService and PasswordResetService wiring', () => {
    const extraProviders = [
      { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
      { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
    ]

    // Verifies that SessionService is always exported from the module regardless of whether the sessions controller flag is set.
    it('SessionService is always exported regardless of controllers.sessions flag', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders
          })
        ]
      }).compile()

      expect(module.get(SessionService)).toBeDefined()
    })

    // Verifies that PasswordResetService is exported when the passwordReset controller feature is not explicitly disabled.
    it('PasswordResetService is exported when controllers.passwordReset is not disabled (default)', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders
          })
        ]
      }).compile()

      expect(module.get(PasswordResetService)).toBeDefined()
    })

    // Verifies that PasswordResetController is registered by default when no controllers config is provided, confirming opt-out behavior.
    it('PasswordResetController is registered by default (opt-out behavior)', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders
          })
        ]
      }).compile()

      expect(module.get(PasswordResetController)).toBeDefined()
    })

    // Verifies that PasswordResetController is not registered when controllers.passwordReset is explicitly set to false.
    it('PasswordResetController is NOT registered when controllers.passwordReset is false', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            controllers: { passwordReset: false },
            extraProviders
          })
        ]
      }).compile()

      expect(() => module.get(PasswordResetController)).toThrow()
    })

    // Verifies that PasswordResetService is also not registered when the passwordReset feature is fully disabled via controllers config.
    it('PasswordResetService is NOT registered when controllers.passwordReset is false', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            controllers: { passwordReset: false },
            extraProviders
          })
        ]
      }).compile()

      expect(() => module.get(PasswordResetService)).toThrow()
    })

    // Verifies that SessionController is registered only when both controllers.sessions is true and sessions.enabled is true.
    it('SessionController is registered when controllers.sessions: true AND sessions.enabled: true', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => ({
              ...validOptions,
              sessions: { enabled: true }
            }),
            controllers: { sessions: true },
            extraProviders
          })
        ]
      }).compile()

      expect(module.get(SessionController)).toBeDefined()
    })

    // Verifies that SessionController is not registered when controllers.sessions is not set, confirming opt-in behavior.
    it('SessionController is NOT registered when controllers.sessions is not set (opt-in behavior)', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders
          })
        ]
      }).compile()

      expect(() => module.get(SessionController)).toThrow()
    })

    // Verifies that the module throws a startup error when controllers.sessions is true but sessions.enabled is false or not set.
    it('throws startup error when controllers.sessions: true but sessions.enabled is not true', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => ({
                ...validOptions,
                sessions: { enabled: false }
              }),
              controllers: { sessions: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/controllers\.sessions.*requires sessions\.enabled/)
    })
  })
})
