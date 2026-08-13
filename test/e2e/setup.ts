/**
 * Shared E2E test setup helpers for @bymax-one/nest-auth.
 *
 * Provides in-memory implementations of every external dependency required by
 * the BymaxAuthModule (user repository, platform user repository, email provider,
 * Redis client) plus a `bootstrapTestApp` factory that compiles a NestJS
 * application instance ready to be exercised over HTTP via supertest.
 *
 * The helpers intentionally never touch the real network or any external service —
 * email sends are captured into an in-memory array and Redis operations are routed
 * through ioredis-mock.
 */

import type { INestApplication } from '@nestjs/common'
import type { Provider } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import type { TestingModuleBuilder } from '@nestjs/testing'
import type { NextFunction, Request, Response } from 'express'
import RedisMock from 'ioredis-mock'
import type { Redis } from 'ioredis'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_PLATFORM_USER_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { BymaxAuthModule } from '../../src/server/bymax-auth.module'
import type { AuthErrorCode } from '../../src/server/errors/auth-error-codes'
import { AUTH_ERROR_STATUS } from '../../src/server/errors/auth-error-codes'
import type { BymaxAuthModuleOptions } from '../../src/server/interfaces/auth-module-options.interface'
import type {
  IEmailProvider,
  InviteData,
  SessionInfo
} from '../../src/server/interfaces/email-provider.interface'
import type {
  AuthPlatformUser,
  IPlatformUserRepository,
  UpdatePlatformMfaData
} from '../../src/server/interfaces/platform-user-repository.interface'
import type {
  AuthUser,
  CreateUserData,
  CreateWithOAuthData,
  IUserRepository,
  UpdateMfaData
} from '../../src/server/interfaces/user-repository.interface'
import { createAuthValidationPipe } from '../../src/server/pipes/auth-validation.pipe'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * 32-character JWT secret with high entropy.
 *
 * Satisfies the `resolveOptions()` security gate (length >= 32, Shannon entropy
 * >= 3.5 bits/char). Reused across every E2E suite — no per-test rotation is
 * needed because tokens never leave the in-memory test process.
 */
export const JWT_SECRET = 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B'

/**
 * 32-byte AES-256-GCM encryption key encoded in base64.
 *
 * Required when MFA is configured. The decoded length is exactly 32 bytes,
 * which is the only length accepted by `validateMfaEncryptionKey()`.
 */
export const MFA_ENCRYPTION_KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='

// ---------------------------------------------------------------------------
// In-memory repositories
// ---------------------------------------------------------------------------

/**
 * In-memory mock for {@link IUserRepository}.
 *
 * Stores users in a Map keyed by `id` and maintains a secondary Map of
 * `tenantId|email` to `id` for fast lookup by email. Returned object exposes
 * the underlying maps and a deterministic id counter so that tests can assert
 * persisted state directly.
 */
export interface MockUserRepository extends IUserRepository {
  /** Direct access to the in-memory user map for assertions. */
  readonly users: Map<string, AuthUser>
}

/**
 * Builds a fresh {@link MockUserRepository} backed by `Map`-based storage.
 *
 * Each call returns an independent instance — tests must not share repos across
 * suites unless intentional.
 */
export function createMockUserRepository(): MockUserRepository {
  const users = new Map<string, AuthUser>()
  const emailIndex = new Map<string, string>()
  let nextId = 1

  const emailKey = (email: string, tenantId: string): string => `${tenantId}|${email.toLowerCase()}`

  const repo: MockUserRepository = {
    users,

    async findById(id: string, tenantId?: string): Promise<AuthUser | null> {
      const user = users.get(id) ?? null
      if (!user) return null
      if (tenantId !== undefined && user.tenantId !== tenantId) return null
      return user
    },

    async findByEmail(email: string, tenantId: string): Promise<AuthUser | null> {
      const id = emailIndex.get(emailKey(email, tenantId))
      return id ? (users.get(id) ?? null) : null
    },

    async create(data: CreateUserData): Promise<AuthUser> {
      const id = `user-${nextId++}`
      const user: AuthUser = {
        id,
        email: data.email,
        name: data.name,
        passwordHash: data.passwordHash,
        role: data.role ?? 'MEMBER',
        status: data.status ?? 'active',
        tenantId: data.tenantId,
        emailVerified: data.emailVerified ?? false,
        mfaEnabled: false,
        lastLoginAt: null,
        createdAt: new Date()
      }
      users.set(id, user)
      emailIndex.set(emailKey(data.email, data.tenantId), id)
      return user
    },

    async updatePassword(id: string, passwordHash: string): Promise<void> {
      const user = users.get(id)
      if (user) users.set(id, { ...user, passwordHash })
    },

    async updateMfa(id: string, tenantId: string | undefined, data: UpdateMfaData): Promise<void> {
      const user = users.get(id)
      // Scoped by tenant like `findById`: a write for the wrong tenant matches no row, exactly as a
      // read would, so an id shared across tenants cannot cross the update onto the wrong account.
      if (!user || (tenantId !== undefined && user.tenantId !== tenantId)) return
      // Strip the existing optional fields first, then re-add only when present —
      // exactOptionalPropertyTypes forbids assigning `undefined` to optional fields.
      const { mfaSecret: _s, mfaRecoveryCodes: _r, ...rest } = user
      const next: AuthUser = {
        ...rest,
        mfaEnabled: data.mfaEnabled,
        ...(data.mfaSecret !== null ? { mfaSecret: data.mfaSecret } : {}),
        ...(data.mfaRecoveryCodes !== null ? { mfaRecoveryCodes: data.mfaRecoveryCodes } : {})
      }
      users.set(id, next)
    },

    async updateLastLogin(id: string): Promise<void> {
      const user = users.get(id)
      if (user) users.set(id, { ...user, lastLoginAt: new Date() })
    },

    async updateStatus(id: string, status: string): Promise<void> {
      const user = users.get(id)
      if (user) users.set(id, { ...user, status })
    },

    async updateEmailVerified(id: string, verified: boolean): Promise<void> {
      const user = users.get(id)
      if (user) users.set(id, { ...user, emailVerified: verified })
    },

    async updateEmail(id: string, email: string): Promise<void> {
      const user = users.get(id)
      // The address is proven before this runs, so the account stays verified across the
      // change — a store that cleared the flag here would sign the user out of a state they
      // had just proved.
      if (user) users.set(id, { ...user, email })
    },

    async findByOAuthId(
      provider: string,
      providerId: string,
      tenantId: string
    ): Promise<AuthUser | null> {
      for (const user of users.values()) {
        if (
          user.tenantId === tenantId &&
          user.oauthProvider === provider &&
          user.oauthProviderId === providerId
        ) {
          return user
        }
      }
      return null
    },

    async linkOAuth(userId: string, provider: string, providerId: string): Promise<void> {
      const user = users.get(userId)
      if (user) {
        users.set(userId, {
          ...user,
          oauthProvider: provider,
          oauthProviderId: providerId
        })
      }
    },

    async createWithOAuth(data: CreateWithOAuthData): Promise<AuthUser> {
      const id = `user-${nextId++}`
      const user: AuthUser = {
        id,
        email: data.email,
        name: data.name,
        passwordHash: null,
        role: data.role ?? 'MEMBER',
        status: data.status ?? 'active',
        tenantId: data.tenantId,
        emailVerified: data.emailVerified ?? false,
        mfaEnabled: false,
        oauthProvider: data.oauthProvider,
        oauthProviderId: data.oauthProviderId,
        lastLoginAt: null,
        createdAt: new Date()
      }
      users.set(id, user)
      emailIndex.set(emailKey(data.email, data.tenantId), id)
      return user
    }
  }

  return repo
}

/**
 * In-memory mock for {@link IPlatformUserRepository}.
 */
export interface MockPlatformUserRepository extends IPlatformUserRepository {
  /** Direct access to the in-memory platform user map for assertions. */
  readonly users: Map<string, AuthPlatformUser>
  /**
   * Seeds a platform user into the in-memory store and updates the internal
   * email→id index so `findByEmail` resolves the row. Used by e2e specs that
   * need a pre-existing platform admin without going through a public create
   * endpoint (the lib does not ship one — platform admins are provisioned by
   * the host application out-of-band).
   */
  seed(user: AuthPlatformUser): void
}

/**
 * Builds a fresh {@link MockPlatformUserRepository} backed by `Map` storage.
 */
export function createMockPlatformUserRepository(): MockPlatformUserRepository {
  const users = new Map<string, AuthPlatformUser>()
  const emailIndex = new Map<string, string>()

  const repo: MockPlatformUserRepository = {
    users,

    seed(user: AuthPlatformUser): void {
      users.set(user.id, user)
      emailIndex.set(user.email.toLowerCase(), user.id)
    },

    async findById(id: string): Promise<AuthPlatformUser | null> {
      return users.get(id) ?? null
    },

    async findByEmail(email: string): Promise<AuthPlatformUser | null> {
      const id = emailIndex.get(email.toLowerCase())
      return id ? (users.get(id) ?? null) : null
    },

    async updateLastLogin(id: string): Promise<void> {
      const user = users.get(id)
      if (user) users.set(id, { ...user, lastLoginAt: new Date(), updatedAt: new Date() })
    },

    async updateMfa(id: string, data: UpdatePlatformMfaData): Promise<void> {
      const user = users.get(id)
      if (!user) return
      // Strip the existing optional fields first, then re-add only when present —
      // exactOptionalPropertyTypes forbids assigning `undefined` to optional fields.
      const { mfaSecret: _s, mfaRecoveryCodes: _r, ...rest } = user
      const next: AuthPlatformUser = {
        ...rest,
        mfaEnabled: data.mfaEnabled,
        ...(data.mfaSecret !== null ? { mfaSecret: data.mfaSecret } : {}),
        ...(data.mfaRecoveryCodes !== null ? { mfaRecoveryCodes: data.mfaRecoveryCodes } : {}),
        updatedAt: new Date()
      }
      users.set(id, next)
    },

    async updatePassword(id: string, passwordHash: string): Promise<void> {
      const user = users.get(id)
      if (user) users.set(id, { ...user, passwordHash, updatedAt: new Date() })
    },

    async updateStatus(id: string, status: string): Promise<void> {
      const user = users.get(id)
      if (user) users.set(id, { ...user, status, updatedAt: new Date() })
    }
  }

  return repo
}

// ---------------------------------------------------------------------------
// Email provider mock
// ---------------------------------------------------------------------------

/**
 * Captured email payload — covers every method on {@link IEmailProvider}.
 */
export interface CapturedEmail {
  to: string
  subject: string
  html: string
}

/**
 * In-memory mock for {@link IEmailProvider}.
 *
 * Every send method captures a `CapturedEmail` entry into `sentEmails` so tests
 * can assert delivery without touching a real mailer. The `send` jest.fn() is a
 * single fan-in spy that fires for every method — useful for verifying that
 * any email was sent at all.
 */
export interface MockEmailProvider extends IEmailProvider {
  readonly send: jest.Mock
  readonly sentEmails: CapturedEmail[]
}

/**
 * Builds a fresh {@link MockEmailProvider}.
 */
export function createMockEmailProvider(): MockEmailProvider {
  const sentEmails: CapturedEmail[] = []
  const send = jest.fn((email: CapturedEmail): void => {
    sentEmails.push(email)
  })

  const provider: MockEmailProvider = {
    send,
    sentEmails,

    async sendPasswordResetToken(_tenantId: string, email: string, _token: string): Promise<void> {
      send({ to: email, subject: 'Password reset', html: '<p>token</p>' })
    },

    async sendPasswordResetOtp(_tenantId: string, email: string, _otp: string): Promise<void> {
      send({ to: email, subject: 'Password reset OTP', html: '<p>otp</p>' })
    },

    async sendEmailVerificationOtp(_tenantId: string, email: string, _otp: string): Promise<void> {
      send({ to: email, subject: 'Verify your email', html: '<p>otp</p>' })
    },

    async sendMfaEnabledNotification(_tenantId: string, email: string): Promise<void> {
      send({ to: email, subject: 'MFA enabled', html: '<p>enabled</p>' })
    },

    async sendMfaDisabledNotification(_tenantId: string, email: string): Promise<void> {
      send({ to: email, subject: 'MFA disabled', html: '<p>disabled</p>' })
    },

    async sendNewSessionAlert(
      _tenantId: string,
      email: string,
      _sessionInfo: SessionInfo
    ): Promise<void> {
      send({ to: email, subject: 'New session', html: '<p>session</p>' })
    },

    async sendInvitation(_tenantId: string, email: string, _data: InviteData): Promise<void> {
      send({ to: email, subject: 'Invitation', html: '<p>invite</p>' })
    }
  }

  return provider
}

// ---------------------------------------------------------------------------
// Redis mock
// ---------------------------------------------------------------------------

/**
 * Monotonic port used to isolate each ioredis-mock keyspace.
 *
 * `ioredis-mock` keys its in-memory store by connection, so every bare
 * `new RedisMock()` in a worker shares ONE keyspace. The merged unit+E2E run
 * (`test:cov:all`) spreads E2E files across parallel workers, and which files
 * co-locate in a worker shifts with the file set — so two suites that both mint
 * `user-1` in `tenant-1` (the in-memory repo restarts its id counter per
 * bootstrap) would silently collide on the MFA subject-derived keys: a lockout
 * counter one suite fills rejects the next suite's disable. Handing every
 * instance a distinct port gives each bootstrap its own keyspace — the
 * isolation the repo and email mocks already provide.
 */
let nextMockRedisPort = 6400

/**
 * Builds a fresh ioredis-mock instance, keyspace-isolated from every other, typed
 * as the upstream `Redis` interface.
 *
 * The cast is safe — `ioredis-mock` is a drop-in replacement for `ioredis` and
 * implements every command surface used by the @bymax-one/nest-auth services.
 */
export function createMockRedis(): Redis {
  return new RedisMock({ port: nextMockRedisPort++ }) as unknown as Redis
}

// ---------------------------------------------------------------------------
// Test app bootstrap
// ---------------------------------------------------------------------------

/**
 * Applies the minimal cookie-parser middleware and global ValidationPipe to a
 * NestJS application instance. Called from every E2E bootstrap to ensure
 * consistent request parsing across all test suites.
 */
export function applyTestMiddleware(app: INestApplication): void {
  // Minimal cookie-parser shim. The library expects `req.cookies` to be
  // populated (TokenDeliveryService.readCookie() reads from it directly), but
  // NestJS does not bundle a cookie parser. Adding this here lets cookie-mode
  // E2E tests forward Set-Cookie headers back to the server without dragging in
  // the `cookie-parser` peer dependency for unit-test infrastructure.
  app.use((req: Request, _res: Response, next: NextFunction): void => {
    const header = req.headers['cookie']
    if (typeof header !== 'string' || header.length === 0) {
      ;(req as Request & { cookies: Record<string, string> }).cookies = {}
      next()
      return
    }
    // Null-prototype: the key comes from a `Set-Cookie` header, so a cookie literally named
    // `__proto__` would otherwise write through to `Object.prototype` and poison every plain
    // object in the process. Nothing here is attacker-reachable — this harness parses headers
    // the suite itself produced, and `test/` is not in the package's `files` — but a cookie
    // parser that can be made to write to a prototype is the wrong thing to keep as the
    // reference implementation in an auth library's own test setup.
    const jar: Record<string, string> = Object.create(null) as Record<string, string>
    for (const part of header.split(';')) {
      const eq = part.indexOf('=')
      if (eq < 0) continue
      const name = part.slice(0, eq).trim()
      const value = part.slice(eq + 1).trim()
      if (name.length > 0) {
        // eslint-disable-next-line security/detect-object-injection
        jar[name] = decodeURIComponent(value)
      }
    }
    ;(req as Request & { cookies: Record<string, string> }).cookies = jar
    next()
  })
  // The library's own pipe, not a bare `ValidationPipe`.
  //
  // Global pipes run BEFORE controller-scoped ones, so the plain `ValidationPipe` this used to
  // install shadowed the `@UsePipes(createAuthValidationPipe())` every auth controller declares:
  // a DTO failure answered with the framework's `{ statusCode, message, error }` instead of the
  // library's `{ error: { code: 'auth.validation', details: [{ field, message }] } }`. Measured,
  // not reasoned about — a seven-character `newPassword` came back as
  // `{"message":["newPassword must be longer than or equal to 8 characters"],"error":"Bad
  // Request","statusCode":400}`.
  //
  // Which means no E2E in this repository had ever seen the library's validation envelope: the
  // suite would have stayed green if `createAuthValidationPipe` stopped producing it entirely.
  // The one assertion that touched the path checked `status === 400`, which the framework's shape
  // satisfies just as well as the library's — the same range-assertion blindness that let thirteen
  // wrong statuses survive.
  //
  // `forbidNonWhitelisted: false` preserves what the previous global pipe did (strip unknown
  // properties, do not reject for them); only the error shape changes, and it changes to the one
  // production actually serves.
  app.useGlobalPipes(createAuthValidationPipe({ transform: true, forbidNonWhitelisted: false }))
}

/**
 * Compiled bootstrap result returned by {@link bootstrapTestApp}.
 *
 * Tests can inspect the in-memory repositories, captured emails, and Redis
 * client directly — no need to reach into module internals.
 */
export interface BootstrappedTestApp {
  app: INestApplication
  repo: MockUserRepository
  platformRepo: MockPlatformUserRepository
  email: MockEmailProvider
  redis: Redis
  options: BymaxAuthModuleOptions
}

/** Extra options for {@link bootstrapTestApp} beyond the standard option overrides. */
export interface ExtraBootstrapOptions {
  /** Controller registration overrides passed to `BymaxAuthModule.registerAsync()`. */
  controllers?: BymaxAuthModuleOptions['controllers']
  /** Additional providers merged into `registerAsync.extraProviders`. */
  extraModuleProviders?: Provider[]
  /** Optional callback to mutate the `TestingModuleBuilder` before compile (e.g. for `.overrideProvider()`). */
  mutateBuilder?: (builder: TestingModuleBuilder) => TestingModuleBuilder
}

/**
 * Compiles a NestJS application bootstrapping the full BymaxAuthModule with
 * sensible E2E defaults: bearer + cookie token delivery, MFA enabled, sessions
 * enabled, every controller registered, and email verification disabled so
 * registration immediately yields tokens.
 *
 * @param overrides - Partial overrides applied to the resolved options. Any
 *   field present here replaces the default — top-level groups are spread, not
 *   deep-merged, so callers must include every sub-field they care about within
 *   a group they override.
 */
export async function bootstrapTestApp(
  overrides: Partial<BymaxAuthModuleOptions> = {},
  extra: ExtraBootstrapOptions = {}
): Promise<BootstrappedTestApp> {
  const repo = createMockUserRepository()
  const platformRepo = createMockPlatformUserRepository()
  const email = createMockEmailProvider()
  const redis = createMockRedis()

  const baseOptions: BymaxAuthModuleOptions = {
    jwt: { secret: JWT_SECRET },
    roles: {
      hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] },
      platformHierarchy: { SUPER_ADMIN: [] }
    },
    tokenDelivery: 'bearer',
    emailVerification: { required: false },
    sessions: { enabled: true },
    mfa: { encryptionKey: MFA_ENCRYPTION_KEY, issuer: 'TestApp' },
    // Declared, because the library no longer sniffs NODE_ENV and defaults to production: the
    // scenarios here serve over plain HTTP and configure `http://` OAuth callbacks, both of
    // which production rightly refuses. Saying so is the point — the escape hatch is a
    // statement the host makes, not an inference the library draws.
    environment: 'test',
    secureCookies: false,
    // The per-IP limiter is off for the shared bootstrap: every scenario here drives many
    // requests from one address on purpose, and a 429 would mask what the scenario is
    // actually asserting. `rate-limit.e2e-spec.ts` turns it on and tests it directly.
    rateLimit: { enabled: false }
  }

  const options: BymaxAuthModuleOptions = { ...baseOptions, ...overrides }

  let builder = Test.createTestingModule({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => options,
        controllers: extra.controllers ?? {
          auth: true,
          mfa: true,
          passwordReset: true,
          sessions: true
        },
        extraProviders: [
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: repo },
          { provide: BYMAX_AUTH_PLATFORM_USER_REPOSITORY, useValue: platformRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: email },
          { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: redis },
          ...(extra.extraModuleProviders ?? [])
        ]
      })
    ]
  })
  if (extra.mutateBuilder) {
    builder = extra.mutateBuilder(builder)
  }
  const moduleRef = await builder
    .setLogger({
      log: () => undefined,
      error: () => undefined,
      warn: () => undefined,
      debug: () => undefined,
      verbose: () => undefined
    })
    .compile()

  const app = moduleRef.createNestApplication()
  applyTestMiddleware(app)
  await app.init()

  return { app, repo, platformRepo, email, redis, options }
}

/**
 * Asserts a response carries the library's error envelope for `code`, at the EXACT HTTP status
 * the shared wire contract declares for that code.
 *
 * Replaces the `status >= 400 && status < 500` pattern these suites used to assert. That range
 * is why thirteen wrong statuses survived the e2e suite: 401 where the contract says 404 is
 * still a 4xx, so the check was satisfied by the right answer and the wrong one alike. The same
 * goes for the negated form (`not.toBe(401)`), which accepts everything but one point and reads
 * like a deliberate assertion about a specific status.
 *
 * Pinning the `(code, status)` pair against `AUTH_ERROR_STATUS` — which `conformance.spec.ts`
 * binds to `conformance/wire-contract.json`, which rust-auth asserts against too — is what makes
 * these wire tests rather than smoke tests.
 */
export function expectAuthError(res: { status: number; body: unknown }, code: AuthErrorCode): void {
  const body = res.body as { error?: { code?: string } }
  expect(body.error?.code).toBe(code)
  expect(res.status).toBe(AUTH_ERROR_STATUS[code])
}
