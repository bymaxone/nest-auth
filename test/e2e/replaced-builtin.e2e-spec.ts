import { Controller, Get, UseGuards } from '@nestjs/common'
import request from 'supertest'

import { IS_PUBLIC_KEY } from '../../src/server/decorators/public.decorator'
import { Roles } from '../../src/server/decorators/roles.decorator'
import { JwtAuthGuard } from '../../src/server/guards/jwt-auth.guard'
import { JwtPlatformGuard } from '../../src/server/guards/jwt-platform.guard'
import { RolesGuard } from '../../src/server/guards/roles.guard'
import { bootstrapTestApp, expectAuthError } from './setup'
import type { BootstrappedTestApp } from './setup'

/** A consumer's route that only an ADMIN may reach, composed the way the guards document. */
@Controller('host')
class HostController {
  @Get('roles/admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  adminOnly(): { admitted: boolean } {
    return { admitted: true }
  }

  /** A route behind the dashboard JWT guard and nothing else. */
  @Get('open/dashboard')
  @UseGuards(JwtAuthGuard)
  dashboardOnly(): { admitted: boolean } {
    return { admitted: true }
  }

  /** A route behind the platform JWT guard and nothing else. */
  @Get('open/platform')
  @UseGuards(JwtPlatformGuard)
  platformOnly(): { admitted: boolean } {
    return { admitted: true }
  }
}

/**
 * Runs `body` with `holder[key]` replaced by a function that calls the original and then answers what `bend` says, as a built-in
 * replaced by a flaw that wants a role check to pass or a revoked token to be found would.
 */
async function withReplaced<T>(
  holder: object,
  key: string,
  bend: (original: (...args: unknown[]) => unknown, self: unknown, args: unknown[]) => unknown,
  body: () => Promise<T>
): Promise<T> {
  const held = Object.getOwnPropertyDescriptor(holder, key) as PropertyDescriptor
  const original = held.value as (...args: unknown[]) => unknown
  Object.defineProperty(holder, key, {
    ...held,
    value: function (this: unknown, ...args: unknown[]): unknown {
      return bend(original, this, args)
    }
  })
  try {
    return await body()
  } finally {
    Object.defineProperty(holder, key, held)
  }
}

describe('a built-in replaced after the module started (E2E)', () => {
  let boot: BootstrappedTestApp
  let access: string

  beforeAll(async () => {
    boot = await bootstrapTestApp({}, { hostControllers: [HostController] })
    const registered = await request(boot.app.getHttpServer()).post('/register').send({
      email: 'member@example.com',
      password: 'SuperSecret123!',
      name: 'Member User',
      tenantId: 't1'
    })
    access = registered.body.accessToken as string
  })

  afterAll(async () => {
    await boot.app.close()
  })

  const adminRoute = (): Promise<{ status: number; body: unknown }> =>
    request(boot.app.getHttpServer())
      .get('/host/roles/admin')
      .set('Authorization', `Bearer ${access}`)

  // Scenario: a member calls a route that only an ADMIN may reach. First with nothing replaced, then with `Array.prototype.some`
  // replaced by a function that answers true whenever the list holds ADMIN, which is what a role check is made with. Expected:
  // the first is refused as lacking the role (403) and the second as the library's own refusal (500 `auth.internal`), never
  // admitted. Why: a replaced `some` that answers true is a privilege escalation, and the guard that runs at the entry of every
  // verification compares the built-ins the decisions are made with.
  it('refuses the role-guarded route, and does not admit a member, while some is replaced', async () => {
    expect((await adminRoute()).status).toBe(403)

    const replaced = await withReplaced(
      Array.prototype,
      'some',
      (original, self, args) =>
        original.apply(self, args) === true || (self as unknown[]).includes('ADMIN'),
      adminRoute
    )

    expectAuthError(replaced, 'auth.internal')
    expect((await adminRoute()).status).toBe(403)
  })

  // Scenario: the same route with `Array.prototype.includes` replaced to answer true. Expected: refused as the library's own
  // refusal. Why: the same family, through the other method a role or permission check is written with.
  it('refuses the role-guarded route while includes is replaced', async () => {
    const replaced = await withReplaced(
      Array.prototype,
      'includes',
      (original, self, args) => original.apply(self, args) === true || args[0] === 'ADMIN',
      adminRoute
    )

    expectAuthError(replaced, 'auth.internal')
  })

  // Scenario: a token that was logged out, then used while `Map.prototype.get` is replaced by a function that answers nothing.
  // Expected: first refused as revoked (401), then, with the built-in replaced, the library's own refusal (500), never admitted.
  // Why: a lookup that finds nothing is a revoked token that is accepted, and the guard refuses before the lookup is made.
  it('does not admit a revoked token while Map.prototype.get is replaced', async () => {
    const login = await request(boot.app.getHttpServer())
      .post('/login')
      .send({ email: 'member@example.com', password: 'SuperSecret123!', tenantId: 't1' })
    const token = login.body.accessToken as string
    const refreshToken = login.body.refreshToken as string
    await request(boot.app.getHttpServer())
      .post('/logout')
      .set('Authorization', `Bearer ${token}`)
      .send({ refreshToken })
    const me = (): Promise<{ status: number; body: unknown }> =>
      request(boot.app.getHttpServer()).get('/me').set('Authorization', `Bearer ${token}`)

    expectAuthError(await me(), 'auth.token_invalid')
    const replaced = await withReplaced(Map.prototype, 'get', () => undefined, me)

    expectAuthError(replaced, 'auth.internal')
  })

  // Scenario: a login while `Object.assign` is replaced. Expected: the library's own refusal, no tokens. Why: the sign path
  // builds its options with `Object.assign`, and a replaced one could drop the options that keep a token valid.
  it('refuses a login, and signs no token, while Object.assign is replaced', async () => {
    const replaced = await withReplaced(
      Object,
      'assign',
      (original, self, args) => original.apply(self, args),
      () =>
        request(boot.app.getHttpServer())
          .post('/login')
          .send({ email: 'member@example.com', password: 'SuperSecret123!', tenantId: 't1' })
    )

    expectAuthError(replaced, 'auth.internal')
    expect((replaced.body as Record<string, unknown>)['accessToken']).toBeUndefined()
  })

  // Scenario: a member calls the admin route on an application that resolves the tenant of the host, and the resolver (which the
  // JWT guard waits for, after its own checks) replaces `Array.prototype.some` with one that answers true for ADMIN and then
  // answers the member's tenant. Expected: 500 `auth.internal`, never 200. Why: the replacement is made after the JWT guard's last
  // check and before the roles guard decides, so only a check at the decision of the roles guard refuses it.
  it('refuses the role-guarded route when a built-in is replaced while the JWT guard waits for the tenant', async () => {
    let restore = (): void => undefined
    let armed = false
    const app = await bootstrapTestApp(
      {
        enforceTenantBinding: true,
        tenantIdResolver: async (): Promise<string> => {
          await Promise.resolve()
          if (!armed) return 't1'
          const held = Object.getOwnPropertyDescriptor(
            Array.prototype,
            'some'
          ) as PropertyDescriptor
          const original = held.value as (...args: unknown[]) => unknown
          Object.defineProperty(Array.prototype, 'some', {
            ...held,
            value: function (this: unknown[], ...args: unknown[]): unknown {
              return original.apply(this, args) === true || this.includes('ADMIN')
            }
          })
          restore = (): void => void Object.defineProperty(Array.prototype, 'some', held)
          return 't1'
        }
      },
      { hostControllers: [HostController] }
    )
    try {
      const registered = await request(app.app.getHttpServer()).post('/register').send({
        email: 'tenant@example.com',
        password: 'SuperSecret123!',
        name: 'Tenant User'
      })
      const token = registered.body.accessToken as string
      armed = true
      const res = await request(app.app.getHttpServer())
        .get('/host/roles/admin')
        .set('Authorization', `Bearer ${token}`)

      expectAuthError(res, 'auth.internal')
    } finally {
      restore()
      await app.app.close()
    }
  })

  // Scenario: `Reflect.getMetadata`, which Nest's reflector reads for `@Public()`, replaced by a function that answers true for it,
  // then a request with no credential to a route behind only the JWT guard of each plane. Expected: 500 `auth.internal`, never the route's own
  // answer. Why: a replaced reader makes every route public, and the JWT guard reads it before it looks for a token.
  it.each(['/host/open/dashboard', '/host/open/platform'] as const)(
    'refuses %s with no credential while Reflect.getMetadata is replaced',
    async (route) => {
      const app = await bootstrapTestApp(
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
      const held = Object.getOwnPropertyDescriptor(Reflect, 'getMetadata') as PropertyDescriptor
      const original = held.value as (...args: unknown[]) => unknown
      let res: { status: number; body: unknown }
      try {
        Object.defineProperty(Reflect, 'getMetadata', {
          ...held,
          value: (key: unknown, ...rest: unknown[]): unknown =>
            key === IS_PUBLIC_KEY ? true : original(key, ...rest)
        })
        res = await request(app.app.getHttpServer()).get(route)
      } finally {
        Object.defineProperty(Reflect, 'getMetadata', held)
        await app.app.close()
      }

      expectAuthError(res, 'auth.internal')
    }
  )
})
