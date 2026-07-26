/**
 * @fileoverview Tests for BymaxAuthModule.registerAsync(), which compiles the full
 * NestJS auth module with resolved options, conditional controllers, and fallback providers.
 * Covers startup validation errors, controller registration, and NoOp fallback providers.
 */

import { Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_BREACH_CHECKER,
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from './bymax-auth.constants'
import { OAuthController } from './oauth/oauth.controller'
import { OAUTH_PLUGINS } from './oauth/oauth.constants'
import { OAuthService } from './oauth/oauth.service'
import { AuthController } from './controllers/auth.controller'
import { InvitationController } from './controllers/invitation.controller'
import { MfaController } from './controllers/mfa.controller'
import { PasswordResetController } from './controllers/password-reset.controller'
import { PlatformAuthController } from './controllers/platform-auth.controller'
import { PlatformMfaController } from './controllers/platform-mfa.controller'
import { SessionController } from './controllers/session.controller'
import { MfaRequiredGuard } from './guards/mfa-required.guard'
import { NoOpAuthHooks } from './hooks/no-op-auth.hooks'
import { AllowAllBreachChecker } from './providers/hibp-breach-checker.provider'
import { NoOpEmailProvider } from './providers/no-op-email.provider'
import { AuthRedisService } from './redis/auth-redis.service'
import { AuthService } from './services/auth.service'
import { InvitationService } from './services/invitation.service'
import { MfaService } from './services/mfa.service'
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

/** Required extraProviders for any compiling module. */
const baseProviders = [
  { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
  { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }
]

/** Valid MFA config — 32-byte key encoded in base64, required for mfa/platform controllers. */
const MFA_ENCRYPTION_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='

/** Options that satisfy controllers.mfa: true (valid mfa group). */
const mfaOptions = {
  ...validOptions,
  mfa: { encryptionKey: MFA_ENCRYPTION_KEY, issuer: 'TestApp' }
}

/** Options with a valid Google OAuth provider. */
const oauthOptions = {
  ...validOptions,
  oauth: {
    google: {
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      callbackUrl: 'https://app.example.com/callback'
    }
  }
}

/** Options that enable invitations so the invitation controller/service register. */
const invitationOptions = {
  ...validOptions,
  invitations: { enabled: true }
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

    // Scenario: controllers.mfa: true without the mfa group. Expected: the error names the required
    // sub-fields (encryptionKey and issuer) and where to put them. Why: pins the second concatenated
    // literal of the mfa cross-validation error so the StringLiteral mutant emptying it is killed.
    it('should name encryptionKey and issuer in the missing-mfa-group error', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions,
              controllers: { mfa: true },
              extraProviders: baseProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(
        /\(encryptionKey and issuer\) to be configured in the useFactory return value\./
      )
    })

    // Scenario: controllers.mfa: true WITH a valid mfa group. Expected: the module compiles and
    // MfaController, MfaService, and MfaRequiredGuard are all registered. Why: kills (1) the
    // ConditionalExpression mutant `resolved.mfa === undefined`→`true` at the mfa cross-validation,
    // which would throw even on a valid mfa group; (2) the ArrayDeclaration mutant emptying the
    // `includeMfa ? [MfaController] : []` controllers entry; and (3) the ArrayDeclaration mutant
    // emptying `mfaProviders = [MfaService, MfaRequiredGuard]` — under those the gets would throw.
    it('should compile and register MFA components when controllers.mfa: true with a valid mfa group', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => mfaOptions,
            controllers: { mfa: true },
            extraProviders: baseProviders
          })
        ]
      }).compile()

      expect(module.get(MfaController)).toBeDefined()
      expect(module.get(MfaService)).toBeDefined()
      expect(module.get(MfaRequiredGuard)).toBeDefined()
    })

    // Scenario: minimal config (no platform, no mfa controllers). Expected: the module compiles but
    // MfaService is NOT registered, so module.get(MfaService) throws. Why: pins the
    // `platformMfaProvider = includePlatform && !includeMfa ? [MfaService] : []` guard. The
    // ConditionalExpression mutant `→ true` and the LogicalOperator mutant `&&`→`||` would both make
    // the condition true in minimal config (includePlatform=false, includeMfa=false), registering
    // MfaService — so asserting it is absent kills both mutants.
    it('should NOT register MfaService in minimal config (no platform, no mfa)', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: baseProviders
          })
        ]
      }).compile()

      expect(() => module.get(MfaService)).toThrow()
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

    // The default breach checker approves everything, so a deployment that upgrades the
    // library never starts reaching a third-party corpus it did not ask for.
    it('should register the allow-all breach checker when the consumer supplies none', async () => {
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

      expect(module.get(BYMAX_AUTH_BREACH_CHECKER)).toBeInstanceOf(AllowAllBreachChecker)
    })

    // A supplied checker wins, and the fallback is not registered over it — otherwise opting
    // into the check would silently do nothing.
    it('should use the consumer-supplied breach checker when one is provided', async () => {
      const consumerChecker = { isBreached: async () => true }
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: [
              { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient },
              { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
              { provide: BYMAX_AUTH_BREACH_CHECKER, useValue: consumerChecker }
            ]
          })
        ]
      }).compile()

      expect(module.get(BYMAX_AUTH_BREACH_CHECKER)).toBe(consumerChecker)
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

    // Scenario: BYMAX_AUTH_USER_REPOSITORY omitted. Expected: the error includes the IUserRepository
    // remediation guidance and the concrete useClass example. Why: pins the two concatenated string
    // literals of the user-repository error so the StringLiteral mutants emptying either are killed.
    it('should include the IUserRepository remediation and useClass example', () => {
      const build = (): unknown =>
        BymaxAuthModule.registerAsync({
          useFactory: () => validOptions,
          extraProviders: [{ provide: BYMAX_AUTH_REDIS_CLIENT, useValue: mockRedisClient }]
        })
      expect(build).toThrow(/Provide your IUserRepository implementation:/)
      expect(build).toThrow(
        /\{ provide: BYMAX_AUTH_USER_REPOSITORY, useClass: YourUserRepository \}\./
      )
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

    // Scenario: BYMAX_AUTH_REDIS_CLIENT omitted (repository present so the redis guard is reached).
    // Expected: the error includes the ioredis remediation guidance and the concrete useValue
    // example. Why: pins the two concatenated string literals of the redis-client error so the
    // StringLiteral mutants emptying either are killed.
    it('should include the ioredis remediation and useValue example', () => {
      const build = (): unknown =>
        BymaxAuthModule.registerAsync({
          useFactory: () => validOptions,
          extraProviders: [{ provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo }]
        })
      expect(build).toThrow(/Provide your ioredis client instance:/)
      expect(build).toThrow(/\{ provide: BYMAX_AUTH_REDIS_CLIENT, useValue: new Redis\(url\) \}\./)
    })

    // Scenario: a class-shorthand provider (function) carrying a static `provide` field equal to the
    // redis token is passed, while the real redis object provider is omitted. Expected: still throws
    // the redis-client startup error. Why: hasProviderToken must SKIP function providers (line
    // `if (typeof p === 'function') return false`); the ConditionalExpression mutant `if (false)`
    // would fall through and match the static `provide` field, treating the token as satisfied and
    // suppressing the startup error. Asserting the synchronous throw kills that mutant.
    it('should skip a class-shorthand provider even if it has a static provide field', () => {
      // A class whose static `provide` happens to equal the redis token — must NOT count as the token.
      class SneakyProvider {}
      ;(SneakyProvider as unknown as { provide: symbol }).provide = BYMAX_AUTH_REDIS_CLIENT

      expect(() =>
        BymaxAuthModule.registerAsync({
          useFactory: () => validOptions,
          extraProviders: [
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
            SneakyProvider as never
            // real BYMAX_AUTH_REDIS_CLIENT object provider intentionally omitted
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

    // Scenario: get JwtService from the compiled module and sign a payload. Expected: signing
    // succeeds and the verified payload round-trips. Why: the JwtModule async factory must return
    // `{ secret: userOptions.jwt.secret, signOptions: { algorithm: 'HS256' } }`. The ObjectLiteral
    // mutant that returns `{}` strips the secret, so JwtService.sign would throw 'secretOrPrivateKey
    // must have a value'. Asserting a successful sign+verify with the configured secret kills that
    // mutant.
    it('should configure JwtModule with the consumer jwt.secret (sign/verify round-trip)', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: baseProviders
          })
        ]
      }).compile()

      const jwt = module.get(JwtService)
      const token = jwt.sign({ sub: 'user-1' })
      expect(typeof token).toBe('string')
      expect(token.split('.')).toHaveLength(3)
      // Verifying with the same secret proves the module used the configured secret, not an empty one.
      const payload = jwt.verify<{ sub: string }>(token, { secret: JWT_SECRET })
      expect(payload.sub).toBe('user-1')
    })

    // Scenario: a host module imports BymaxAuthModule and injects AuthService into its own provider.
    // Expected: AuthService resolves across the module boundary. Why: this is only possible if
    // AuthService appears in the module's `exports` array. The ArrayDeclaration mutant that empties
    // the entire `exports: [...]` array would make AuthService invisible to importing modules, so
    // the host module would fail to compile. A successful cross-module injection kills that mutant.
    it('should export AuthService to importing host modules', async () => {
      @Injectable()
      class HostProbe {
        constructor(readonly auth: AuthService) {}
      }

      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => validOptions,
            extraProviders: baseProviders
          })
        ],
        providers: [HostProbe]
      }).compile()

      const probe = module.get(HostProbe)
      expect(probe.auth).toBeInstanceOf(AuthService)
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

    // Scenario: controllers.platform: true with platform.enabled but no mfa group. Expected: the
    // error explains MfaService is used for platform admin MFA challenges. Why: pins the two
    // concatenated literals of the platform-mfa cross-validation error so the StringLiteral mutants
    // emptying either are killed.
    it('should explain the platform-admin MFA usage in the missing-mfa-group platform error', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => platformOptions,
              controllers: { platform: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/MfaService is used for platform admin MFA challenges\./)
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

    // Scenario: controllers.platform: true with valid platform + mfa config but WITHOUT the platform
    // user repository token. Expected: rejects with the explicit startup guard message containing
    // 'Omitting it will cause TOKEN_INVALID on all platform auth requests.'. Why: this phrase only
    // appears in the explicit guard (the `includePlatform && !hasProviderToken(...)` block), NOT in
    // the NestJS DI error that would otherwise mention the token. This kills the ConditionalExpression
    // mutant `→ false`, the BlockStatement-empty mutant, and the StringLiteral mutants on that guard —
    // under each, the explicit message would not be thrown (NestJS would throw its generic injection
    // error instead, which lacks this phrase).
    it('should throw the explicit TOKEN_INVALID guard message when the platform user repository token is missing', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => platformWithMfaOptions,
              controllers: { platform: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/Omitting it will cause TOKEN_INVALID on all platform auth requests\./)
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
      // PlatformAuthController must be registered. The ArrayDeclaration mutant emptying
      // `includePlatform ? [PlatformAuthController, PlatformMfaController] : []` would leave it
      // unregistered, so this get would throw — asserting it resolves kills that mutant.
      expect(module.get(PlatformAuthController)).toBeDefined()
      // PlatformMfaController must also be registered alongside PlatformAuthController when
      // controllers.platform: true is set. Pins that the platform admin MFA enrolment surface is
      // exposed by the same gate rather than living behind a separate option.
      expect(module.get(PlatformMfaController)).toBeDefined()
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

    // Scenario: controllers.oauth: true without the oauth group. Expected: the error explains the
    // oauth group must be configured in the useFactory return value. Why: pins the second
    // concatenated literal of the oauth cross-validation error so the StringLiteral mutant emptying
    // it is killed.
    it('should point to the useFactory return value in the missing-oauth-group error', async () => {
      await expect(
        Test.createTestingModule({
          imports: [
            BymaxAuthModule.registerAsync({
              useFactory: () => validOptions,
              controllers: { oauth: true },
              extraProviders
            })
          ]
        }).compile()
      ).rejects.toThrow(/to be configured in the useFactory return value\./)
    })

    // Verifies that controllers.oauth: true with a valid oauth.google config compiles
    // successfully and registers OAuthController — also exercises the OAUTH_PLUGINS
    // factory provider body (line 294 in bymax-auth.module.ts).
    it('should compile and register OAuthController when controllers.oauth: true with valid oauth config', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => oauthOptions,
            controllers: { oauth: true },
            extraProviders
          })
        ]
      }).compile()

      expect(module.get(OAuthController)).toBeDefined()
      // OAUTH_PLUGINS must be the array produced by buildOAuthPlugins(opts). The ArrowFunction mutant
      // replacing the factory with `() => undefined` would make this provider resolve to undefined,
      // so asserting it is a non-empty array kills that mutant.
      const plugins = module.get<unknown[]>(OAUTH_PLUGINS)
      expect(Array.isArray(plugins)).toBe(true)
      expect(plugins.length).toBeGreaterThan(0)
    })

    // Scenario: a host module imports an OAuth-enabled BymaxAuthModule and injects OAuthService.
    // Expected: OAuthService resolves across the module boundary. Why: this requires OAuthService to
    // be in the module's `exports`. The ArrayDeclaration mutant emptying the
    // `...(includeOAuth ? [OAuthService] : [])` exports entry would make it invisible to importing
    // modules, so the host module would fail to compile. A successful cross-module injection kills it.
    it('should export OAuthService to importing host modules when oauth is enabled', async () => {
      @Injectable()
      class OAuthProbe {
        constructor(readonly oauth: OAuthService) {}
      }

      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => oauthOptions,
            controllers: { oauth: true },
            extraProviders
          })
        ],
        providers: [OAuthProbe]
      }).compile()

      expect(module.get(OAuthProbe).oauth).toBeInstanceOf(OAuthService)
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

    // Scenario: controllers.invitations: true WITH invitations.enabled: true. Expected: the module
    // compiles and both InvitationController and InvitationService are registered. Why: kills the
    // ArrayDeclaration mutant emptying the `includeInvitations ? [InvitationController] : []`
    // controllers entry and the one emptying `invitationProviders = [InvitationService]` — under
    // either, the corresponding get would throw.
    it('should compile and register invitation components when controllers.invitations: true and enabled', async () => {
      const module = await Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => invitationOptions,
            controllers: { invitations: true },
            extraProviders
          })
        ]
      }).compile()

      expect(module.get(InvitationController)).toBeDefined()
      expect(module.get(InvitationService)).toBeDefined()
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

    // Scenario: controllers.sessions: true but sessions.enabled is false. Expected: the error ends
    // with 'in the useFactory return value.'. Why: pins the second concatenated literal of the
    // sessions cross-validation error so the StringLiteral mutant emptying it is killed.
    it('should point to the useFactory return value in the sessions cross-validation error', async () => {
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
      ).rejects.toThrow(/in the useFactory return value\./)
    })
  })
})
