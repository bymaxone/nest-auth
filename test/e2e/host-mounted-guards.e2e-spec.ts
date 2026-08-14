/**
 * @fileoverview Drives the five guards this library exports and never mounts, from a host's own
 * controller.
 *
 * The library's own controllers use `JwtAuthGuard`, `UserStatusGuard`, `TrustedOriginGuard` and
 * `AuthRateLimitGuard`, so every other e2e exercises those on the way somewhere else.
 * `RolesGuard`, `PlatformRolesGuard`, `MfaRequiredGuard`, `OptionalAuthGuard` and
 * `SelfOrAdminGuard` are exported from `src/server/index.ts` for a consumer to apply to their
 * own routes — and nothing here ever applies them, so their only proof was unit tests handing
 * each guard an `ExecutionContext` no middleware would build. That proves the code runs. It does
 * not prove a consumer can mount it, nor that the refusal survives the pipeline it sits in.
 *
 * So the harness plays the consumer: the fixture controller below is declared in the TEST module,
 * not inside `BymaxAuthModule`. That is what makes this a real test of the exported surface —
 * a guard applied with `@UseGuards(...)` is instantiated in the declaring module's injector, so
 * it can only resolve what `BymaxAuthModule` actually **exports**. A guard whose dependencies are
 * internal is one a consumer cannot apply at all, and no test living inside the library would
 * ever notice.
 *
 * One branch is out of reach of the compositions this library supports, and it is stated rather
 * than skipped: `PlatformRolesGuard`'s missing `platformHierarchy`. Reaching it needs a
 * platform-typed `request.user`, which needs `JwtPlatformGuard`, which is only registered when
 * `platform.enabled` — and `resolveOptions` refuses that configuration without a
 * `platformHierarchy`. A consumer's own guard populating `request.user` with a platform payload
 * reaches it, over HTTP, which is what the arm defends; nothing this library mounts does. It is
 * covered by the guard's unit spec.
 *
 * `SelfOrAdminGuard`'s array-valued param was described the same way in the first draft of this
 * suite, and that was **wrong**. Express 5 (path-to-regexp 8) fills a named wildcard's param with
 * an array of segments — measured, `['abc']` for one segment — so the arm is reachable by any
 * consumer who writes `@Get('files/*path')` behind the guard. The fixture now declares such a
 * route and the case below drives it.
 */

import { randomBytes, randomUUID } from 'node:crypto'

import { Controller, Get, UseGuards } from '@nestjs/common'
import type { INestApplication } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import request from 'supertest'

import { PasswordService } from '../../src/server/services/password.service'
import { Roles } from '../../src/server/decorators/roles.decorator'
import { PlatformRoles } from '../../src/server/decorators/platform-roles.decorator'
import { SkipMfa } from '../../src/server/decorators/skip-mfa.decorator'
import { JwtAuthGuard } from '../../src/server/guards/jwt-auth.guard'
import { JwtPlatformGuard } from '../../src/server/guards/jwt-platform.guard'
import { MfaRequiredGuard } from '../../src/server/guards/mfa-required.guard'
import { OptionalAuthGuard } from '../../src/server/guards/optional-auth.guard'
import { PlatformRolesGuard } from '../../src/server/guards/platform-roles.guard'
import { RolesGuard } from '../../src/server/guards/roles.guard'
import { SelfOrAdminGuard } from '../../src/server/guards/self-or-admin.guard'
import type { BootstrappedTestApp } from './setup'
import { bootstrapTestApp, expectAuthError, JWT_SECRET } from './setup'

// ---------------------------------------------------------------------------
// The host's controller
// ---------------------------------------------------------------------------

/** What a route answers when every guard in front of it admitted the caller. */
const ADMITTED = { admitted: true }

/**
 * A consumer's controller, mounting the exported guards the way the guards' own JSDoc shows.
 *
 * Every route is the documented composition, including the ones that are documented as a
 * PRECONDITION rather than a suggestion: `SelfOrAdminGuard` and `RolesGuard` both say
 * `JwtAuthGuard` must run first, and each carries a defensive branch for the case where it did
 * not. Those branches are reachable exactly by mounting the guard alone, which a consumer can do
 * by mistake — so the fixture does it deliberately, on its own route.
 */
@Controller('host')
class HostController {
  /** `@Roles` with no metadata at all: the guard must admit any authenticated caller. */
  @Get('roles/unrestricted')
  @UseGuards(JwtAuthGuard, RolesGuard)
  unrestricted(): typeof ADMITTED {
    return ADMITTED
  }

  /** `@Roles()` with an EMPTY list — a different branch from no decorator at all. */
  @Get('roles/empty')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles()
  emptyRoles(): typeof ADMITTED {
    return ADMITTED
  }

  /** The ordinary case: a role requirement the hierarchy can satisfy. */
  @Get('roles/admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  adminOnly(): typeof ADMITTED {
    return ADMITTED
  }

  /** `RolesGuard` with no authentication in front of it — the misconfiguration branch. */
  @Get('roles/unauthenticated')
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  rolesWithoutAuth(): typeof ADMITTED {
    return ADMITTED
  }

  /** Self-or-admin over a `:userId` param, composed as documented. */
  @Get('self/:userId')
  @UseGuards(JwtAuthGuard, SelfOrAdminGuard)
  self(): typeof ADMITTED {
    return ADMITTED
  }

  /** The same guard reading the `:id` param instead — the second name it accepts. */
  @Get('self-by-id/:id')
  @UseGuards(JwtAuthGuard, SelfOrAdminGuard)
  selfById(): typeof ADMITTED {
    return ADMITTED
  }

  /** `SelfOrAdminGuard` on a route with NEITHER param — it has nothing to compare. */
  @Get('self-no-param')
  @UseGuards(JwtAuthGuard, SelfOrAdminGuard)
  selfNoParam(): typeof ADMITTED {
    return ADMITTED
  }

  /** `SelfOrAdminGuard` with no authentication in front of it. */
  @Get('self-unauthenticated/:userId')
  @UseGuards(SelfOrAdminGuard)
  selfWithoutAuth(): typeof ADMITTED {
    return ADMITTED
  }

  /**
   * The same guard over a NAMED WILDCARD, which is where its array arm lives.
   *
   * Express 5 (path-to-regexp 8) fills `req.params.userId` with an array of path segments for
   * `*userId` — `['abc']` for one segment, `['a','b','c']` for three. So the arm is not the
   * defensive dead code it reads as: a consumer writes this route the moment they want
   * `/files/*path` behind an ownership check.
   */
  @Get('self-wildcard/*userId')
  @UseGuards(JwtAuthGuard, SelfOrAdminGuard)
  selfWildcard(): typeof ADMITTED {
    return ADMITTED
  }

  /** The guard that admits anonymous callers and still validates a token when one is sent. */
  @Get('optional')
  @UseGuards(OptionalAuthGuard)
  optional(): typeof ADMITTED {
    return ADMITTED
  }

  /** MFA enforcement on a host route. */
  @Get('mfa')
  @UseGuards(JwtAuthGuard, MfaRequiredGuard)
  mfa(): typeof ADMITTED {
    return ADMITTED
  }

  /** The opt-out the challenge endpoint itself needs. */
  @Get('mfa-skipped')
  @UseGuards(JwtAuthGuard, MfaRequiredGuard)
  @SkipMfa()
  mfaSkipped(): typeof ADMITTED {
    return ADMITTED
  }

  /** `MfaRequiredGuard` with nothing authenticating the caller — it must pass through. */
  @Get('mfa-unauthenticated')
  @UseGuards(MfaRequiredGuard)
  mfaWithoutAuth(): typeof ADMITTED {
    return ADMITTED
  }

  /** Platform roles, composed after the platform credential guard. */
  @Get('platform/super')
  @UseGuards(JwtPlatformGuard, PlatformRolesGuard)
  @PlatformRoles('SUPER_ADMIN')
  platformSuper(): typeof ADMITTED {
    return ADMITTED
  }

  /** A platform route with no role metadata: any authenticated platform admin proceeds. */
  @Get('platform/any')
  @UseGuards(JwtPlatformGuard, PlatformRolesGuard)
  platformAny(): typeof ADMITTED {
    return ADMITTED
  }

  /** `PlatformRolesGuard` reached with a DASHBOARD token — authentication, not authorization. */
  @Get('platform/dashboard-token')
  @UseGuards(JwtAuthGuard, PlatformRolesGuard)
  @PlatformRoles('SUPER_ADMIN')
  platformWithDashboardToken(): typeof ADMITTED {
    return ADMITTED
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** The password every account in this suite is registered with. */
const PASSWORD = 'Host-Mounted-Guard-Passphrase'

/**
 * Mints a well-formed token this deployment did not sign.
 *
 * Signed at runtime under a key generated per run, rather than pasted in as a literal. Two
 * reasons, and the second is why the literal had to go:
 *
 *  - It is a stronger fixture. A hand-typed string with a stub signature is rejected by the
 *    parser as much as by the verifier, so it cannot tell "signature check works" from "this is
 *    not a JWT" — which is what the case beside it already tests. A properly signed token
 *    reaches the signature comparison and fails there, which is the claim.
 *  - A JWT-shaped literal beside the word `Bearer` is what GitHub's secret scanner matches. The
 *    string carried nothing (`sub: user-1`, a stub signature) but the alert is indistinguishable
 *    at a glance from a real leak, and an alert stream people learn to dismiss is worse than no
 *    alert stream. Nothing that looks like a credential belongs in the tree when the runtime can
 *    mint one.
 */
function foreignToken(): string {
  return new JwtService({}).sign(
    { sub: 'user-1', tenantId: 'tenant-1', type: 'dashboard' },
    { secret: randomBytes(32).toString('hex'), expiresIn: '5m' }
  )
}

/** Registers an account and returns its access token and id. */
async function register(
  app: INestApplication,
  email: string
): Promise<{ accessToken: string; userId: string }> {
  const res = await request(app.getHttpServer())
    .post('/register')
    .send({ email, password: PASSWORD, name: 'Host User', tenantId: 'tenant-1' })

  return {
    accessToken: res.body.accessToken as string,
    userId: (res.body.user as { id: string }).id
  }
}

/**
 * Registers an account, promotes it in the repository, and logs in for a token carrying the
 * new role.
 *
 * `RegisterDto` has no `role` field — `forbidNonWhitelisted` refuses one, deliberately: the
 * role a self-registration gets is the deployment's to decide, never the caller's. So the
 * promotion happens where a real deployment's would, in the user store, and the second login is
 * what stamps the role into a token. Reusing the registration token would test the guard against
 * a claim the account no longer matches.
 */
async function registerAdmin(
  boot: BootstrappedTestApp,
  email: string,
  role = 'ADMIN'
): Promise<{ accessToken: string; userId: string }> {
  const { userId } = await register(boot.app, email)
  const stored = boot.repo.users.get(userId)!

  boot.repo.users.set(userId, { ...stored, role })

  const login = await request(boot.app.getHttpServer())
    .post('/login')
    .send({ email, password: PASSWORD, tenantId: 'tenant-1' })

  return { accessToken: login.body.accessToken as string, userId }
}

describe('host-mounted guards (E2E)', () => {
  let boot: BootstrappedTestApp
  let app: INestApplication
  let jwt: JwtService

  /** A MEMBER account — the role the repository assigns by default. */
  let member: { accessToken: string; userId: string }

  /** An ADMIN account, for the branch where the hierarchy grants access. */
  let admin: { accessToken: string; userId: string }

  beforeAll(async () => {
    boot = await bootstrapTestApp(
      { platform: { enabled: true } },
      {
        controllers: {
          auth: true,
          mfa: true,
          passwordReset: true,
          sessions: true,
          platform: true
        },
        hostControllers: [HostController]
      }
    )
    app = boot.app
    jwt = app.get(JwtService)

    member = await register(app, 'member@example.com')
    admin = await registerAdmin(boot, 'admin@example.com')
  })

  afterAll(async () => {
    await app.close()
  })

  // ---------------------------------------------------------------------------
  // RolesGuard
  // ---------------------------------------------------------------------------

  describe('RolesGuard', () => {
    // Verifies the two ways a route can carry no requirement. They are different branches —
    // `undefined` metadata and an empty array — and a guard that admitted only the first would
    // 403 every `@Roles()` route, which reads as a hierarchy problem rather than a guard one.
    it.each([
      ['no @Roles decorator', '/host/roles/unrestricted'],
      ['@Roles() with an empty list', '/host/roles/empty']
    ])('admits an authenticated caller with %s', async (_why, path) => {
      const res = await request(app.getHttpServer())
        .get(path)
        .set('Authorization', `Bearer ${member.accessToken}`)

      expect(res.status).toBe(200)
      expect(res.body).toEqual(ADMITTED)
    })

    // Verifies the hierarchy is consulted rather than the role compared literally: the fixture
    // deployment declares ADMIN → [MEMBER], so an ADMIN token satisfies `@Roles('ADMIN')` and a
    // MEMBER token does not.
    it('admits a role the hierarchy grants and refuses one it does not', async () => {
      const granted = await request(app.getHttpServer())
        .get('/host/roles/admin')
        .set('Authorization', `Bearer ${admin.accessToken}`)

      expect(granted.status).toBe(200)

      const refused = await request(app.getHttpServer())
        .get('/host/roles/admin')
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(refused, 'auth.insufficient_role')
    })

    // Verifies the defensive branch, which is only reachable through a composition the guard's
    // own JSDoc warns against — `RolesGuard` alone, with nothing to populate `request.user`.
    // It must refuse. A guard that returned `true` for a request carrying no user would turn a
    // consumer's ordering mistake into an open endpoint, and the mistake is invisible: the route
    // looks protected, and every authenticated test of it passes.
    it('refuses when no guard populated the user', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/roles/unauthenticated')
        .set('Authorization', `Bearer ${admin.accessToken}`)

      expectAuthError(res, 'auth.insufficient_role')
    })
  })

  // ---------------------------------------------------------------------------
  // SelfOrAdminGuard
  // ---------------------------------------------------------------------------

  describe('SelfOrAdminGuard', () => {
    // Verifies the identity boundary in both directions, and under both param names the guard
    // accepts. The `:id` route matters on its own: the guard reads `userId` first and falls back
    // to `id`, so a guard that only ever read `userId` would refuse every session route in the
    // documented example while passing a suite that tested only the first name.
    it.each([
      ['/host/self', 'userId'],
      ['/host/self-by-id', 'id']
    ])('admits the owner over %s and refuses another user', async (prefix) => {
      const own = await request(app.getHttpServer())
        .get(`${prefix}/${member.userId}`)
        .set('Authorization', `Bearer ${member.accessToken}`)

      expect(own.status).toBe(200)

      const other = await request(app.getHttpServer())
        .get(`${prefix}/${admin.userId}`)
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(other, 'auth.insufficient_role')
    })

    // Verifies the admin escape hatch: a caller who is not the owner still passes when the
    // hierarchy grants them `admin`. The fixture hierarchy has no `admin` key, so this is the
    // refusal side of the documented convention — the guard checks the literal role `'admin'`,
    // and a deployment using `ADMIN` does NOT satisfy it. That is the trap the JSDoc names, and
    // it is worth an executing test rather than a sentence: an operator reading "or holds the
    // admin role" would expect the ADMIN token below to pass.
    it('does not treat ADMIN as the literal admin role the guard checks', async () => {
      const res = await request(app.getHttpServer())
        .get(`/host/self/${member.userId}`)
        .set('Authorization', `Bearer ${admin.accessToken}`)

      expectAuthError(res, 'auth.insufficient_role')
    })

    // Verifies the hash-shaped param rule over real HTTP: 64 hex characters are treated as a
    // session hash and must be strictly lowercase, so an uppercase one is refused as a malformed
    // token rather than compared and answered "not yours".
    it('refuses an uppercase 64-hex param as a malformed hash', async () => {
      const res = await request(app.getHttpServer())
        .get(`/host/self/${'A'.repeat(64)}`)
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(res, 'auth.token_invalid')
    })

    // Verifies a lowercase 64-hex param is NOT refused by the format rule — it goes on to the
    // ownership comparison and fails there. Without this pair the uppercase case above would
    // also pass against a guard that refused every 64-character param.
    it('lets a lowercase 64-hex param through the format rule to the ownership check', async () => {
      const res = await request(app.getHttpServer())
        .get(`/host/self/${'a'.repeat(64)}`)
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(res, 'auth.insufficient_role')
    })

    // Verifies the route with no param at all — the guard has nothing to compare and must refuse
    // rather than admit.
    it('refuses a route carrying neither :userId nor :id', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/self-no-param')
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(res, 'auth.insufficient_role')
    })

    // Verifies the array arm, over a real wildcard route. Express 5 hands `req.params.userId` an
    // ARRAY of path segments for `*userId` — `['abc']` even for a single one — and the guard
    // refuses rather than picking an element, because an identity check against one segment of a
    // path the caller chose is not the check it claims to be. A consumer reaches this the moment
    // they put an ownership guard on `/files/*path`.
    //
    // Both shapes are driven: one segment and three. The single-segment case is the one that
    // matters, because it is the shape that LOOKS like a plain param and is not.
    it.each([
      ['a single segment', 'abc'],
      ['several segments', 'abc/def/ghi']
    ])('refuses a wildcard param carrying %s', async (_why, path) => {
      const res = await request(app.getHttpServer())
        .get(`/host/self-wildcard/${path}`)
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(res, 'auth.insufficient_role')
    })

    // The positive half of the convention above, and the guard's last reachable branch: on a
    // deployment whose hierarchy really does carry the literal `admin`, a non-owner passes.
    // Its own application, because the hierarchy is what varies — a second route on the shared
    // one could not express it.
    it('admits a non-owner whose hierarchy grants the literal admin role', async () => {
      const boot = await bootstrapTestApp(
        { roles: { hierarchy: { admin: ['MEMBER'], MEMBER: [] } } },
        { hostControllers: [HostController] }
      )

      try {
        const owner = await register(boot.app, 'owned@example.com')
        const elevated = await registerAdmin(boot, 'literal-admin@example.com', 'admin')

        const res = await request(boot.app.getHttpServer())
          .get(`/host/self/${owner.userId}`)
          .set('Authorization', `Bearer ${elevated.accessToken}`)

        expect(res.status).toBe(200)
      } finally {
        await boot.app.close()
      }
    })

    // Verifies the defensive branch: mounted without `JwtAuthGuard`, it refuses with
    // `auth.token_invalid` — authentication, not authorization, which is the honest code for
    // "nothing proved who this is".
    it('refuses when no guard populated the user', async () => {
      const res = await request(app.getHttpServer())
        .get(`/host/self-unauthenticated/${member.userId}`)
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(res, 'auth.token_invalid')
    })
  })

  // ---------------------------------------------------------------------------
  // OptionalAuthGuard
  // ---------------------------------------------------------------------------

  describe('OptionalAuthGuard', () => {
    // Verifies the whole behaviour matrix in one place, because the value of this guard is the
    // matrix: anonymous is admitted, a valid token is admitted, and an unusable one is refused
    // exactly as `JwtAuthGuard` refuses it. A guard that admitted the third would be an
    // authentication bypass wearing the word "optional".
    it('admits an anonymous caller', async () => {
      const res = await request(app.getHttpServer()).get('/host/optional')

      expect(res.status).toBe(200)
      expect(res.body).toEqual(ADMITTED)
    })

    it('admits a caller carrying a valid token', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/optional')
        .set('Authorization', `Bearer ${member.accessToken}`)

      expect(res.status).toBe(200)
    })

    it.each([
      ['a syntactically invalid token', (): string => 'not-a-jwt'],
      ['a well-formed token this deployment did not sign', foreignToken]
    ])('refuses %s exactly as JwtAuthGuard does', async (_why, token) => {
      const res = await request(app.getHttpServer())
        .get('/host/optional')
        .set('Authorization', `Bearer ${token()}`)

      expectAuthError(res, 'auth.token_invalid')
    })
  })

  // ---------------------------------------------------------------------------
  // MfaRequiredGuard
  // ---------------------------------------------------------------------------

  describe('MfaRequiredGuard', () => {
    /**
     * Mints a dashboard access token with the given claims, signed by the deployment's own key.
     *
     * The guard's remaining branches are decided by claims a login cannot produce on demand —
     * `mfaEnabled: true` without `mfaVerified`, and a payload missing `mfaEnabled` altogether.
     * Signing them here keeps the request a real one: it arrives over HTTP, through
     * `JwtAuthGuard`, which verifies the signature before this guard reads anything. What is
     * synthesised is the claim set, not the pipeline.
     */
    function tokenWith(claims: Record<string, unknown>): string {
      return jwt.sign(
        {
          sub: member.userId,
          tenantId: 'tenant-1',
          role: 'MEMBER',
          type: 'dashboard',
          status: 'active',
          // A real `jti`, because `JwtAuthGuard` requires a UUID v4 and builds the revocation key
          // from it. Every claim this token carries is one the guard in front insists on; the
          // synthesis is confined to `mfaEnabled` / `mfaVerified`, which is the pair under test.
          jti: randomUUID(),
          epoch: 0,
          ...claims
        },
        { secret: JWT_SECRET, expiresIn: '5m' }
      )
    }

    // Verifies an account without MFA is untouched by the guard.
    it('admits a caller whose account has MFA disabled', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/mfa')
        .set('Authorization', `Bearer ${member.accessToken}`)

      expect(res.status).toBe(200)
    })

    // Verifies the enforcement itself: MFA enabled on the account, but this token was not issued
    // after a challenge.
    it('refuses a token that has not completed the challenge', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/mfa')
        .set('Authorization', `Bearer ${tokenWith({ mfaEnabled: true, mfaVerified: false })}`)

      expectAuthError(res, 'auth.mfa_required')
    })

    // The other side of the same pair — without it, the refusal above is also satisfied by a
    // guard that refuses every MFA-enabled account forever.
    it('admits a token that did complete the challenge', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/mfa')
        .set('Authorization', `Bearer ${tokenWith({ mfaEnabled: true, mfaVerified: true })}`)

      expect(res.status).toBe(200)
    })

    // Verifies the runtime type guard. A token with no `mfaEnabled` claim is refused rather than
    // waved through — the branch exists because a custom guard populating `request.user` with a
    // different payload shape would otherwise silently disable MFA enforcement.
    it('refuses a token whose payload carries no mfaEnabled claim', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/mfa')
        .set('Authorization', `Bearer ${tokenWith({ mfaEnabled: undefined })}`)

      expectAuthError(res, 'auth.token_invalid')
    })

    // Verifies `@SkipMfa()` opts the route out — the decorator the challenge endpoint itself
    // depends on.
    it('admits an unverified caller on a @SkipMfa route', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/mfa-skipped')
        .set('Authorization', `Bearer ${tokenWith({ mfaEnabled: true, mfaVerified: false })}`)

      expect(res.status).toBe(200)
    })

    // Verifies the pass-through branch: with nothing authenticating the caller there is no user
    // to enforce MFA against, and `JwtAuthGuard` is what owns that refusal. This guard admitting
    // the request is correct — and only safe because it is never the only guard on a route.
    it('passes an unauthenticated request through', async () => {
      const res = await request(app.getHttpServer()).get('/host/mfa-unauthenticated')

      expect(res.status).toBe(200)
    })
  })

  // ---------------------------------------------------------------------------
  // PlatformRolesGuard
  // ---------------------------------------------------------------------------

  describe('PlatformRolesGuard', () => {
    /** Seeds a platform admin with the given role and returns its access token. */
    async function platformLogin(email: string, role: string): Promise<string> {
      const password = 'Platform-Host-Guard-Passphrase'
      const passwordHash = await app.get(PasswordService).hash(password)

      boot.platformRepo.seed({
        id: `platform-${role.toLowerCase()}`,
        email: email.toLowerCase(),
        name: 'Platform Host Tester',
        passwordHash,
        role,
        status: 'active',
        mfaEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: null
      })

      const res = await request(app.getHttpServer())
        .post('/platform/login')
        .send({ email, password })

      return res.body.accessToken as string
    }

    // Verifies the hierarchy decides, on a host route, with a real platform credential:
    // SUPER_ADMIN satisfies `@PlatformRoles('SUPER_ADMIN')` and SUPPORT does not. The platform
    // hierarchy is a separate map from the dashboard one, and a guard reading the wrong map
    // would pass every test that used only one of them.
    it('admits a platform role the hierarchy grants and refuses one it does not', async () => {
      const granted = await request(app.getHttpServer())
        .get('/host/platform/super')
        .set('Authorization', `Bearer ${await platformLogin('super@platform.test', 'SUPER_ADMIN')}`)

      expect(granted.status).toBe(200)

      const refused = await request(app.getHttpServer())
        .get('/host/platform/super')
        .set('Authorization', `Bearer ${await platformLogin('support@platform.test', 'SUPPORT')}`)

      expectAuthError(refused, 'auth.insufficient_role')
    })

    // Verifies a platform route with no role metadata admits any authenticated platform admin —
    // including the SUPPORT account the route above refuses, which is what shows the metadata
    // and not the account is what decided.
    it('admits any platform admin on a route with no role metadata', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/platform/any')
        .set('Authorization', `Bearer ${await platformLogin('support@platform.test', 'SUPPORT')}`)

      expect(res.status).toBe(200)
    })

    // Verifies a dashboard token cannot reach a platform authorization decision. The guard
    // answers `auth.token_invalid` rather than `auth.insufficient_role`: the caller is not a
    // platform admin with the wrong role, they are not a platform admin at all.
    it('refuses a dashboard token with the authentication code, not the role one', async () => {
      const res = await request(app.getHttpServer())
        .get('/host/platform/dashboard-token')
        .set('Authorization', `Bearer ${member.accessToken}`)

      expectAuthError(res, 'auth.token_invalid')
    })

    // Verifies the credential guard in front refuses an unauthenticated caller before the role
    // guard is reached at all — the composition the JSDoc prescribes.
    it('is not reached at all without a platform credential', async () => {
      const res = await request(app.getHttpServer()).get('/host/platform/super')

      expectAuthError(res, 'auth.token_invalid')
    })
  })
})
