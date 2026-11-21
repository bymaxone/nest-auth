/**
 * What the library does with the values a host's records serve for the fields of a contract, through real HTTP: an
 * entity that serves its fields through its prototype is a user like any other, and a field that decides an admission
 * and is served as a function is refused, never read as absent.
 *
 * @layer Test
 */
import type { INestApplication } from '@nestjs/common'
import request from 'supertest'

import { AUTH_ERROR_CODES } from '../../src/server/errors/auth-error-codes'
import type { AuthUser } from '../../src/server/interfaces/user-repository.interface'
import { PasswordService } from '../../src/server/services/password.service'
import { bootstrapTestApp, type BootstrappedTestApp } from './setup'

const EMAIL = 'hydrated@example.com'
const PASSWORD = 'SuperSecret123!'
const NEXT_PASSWORD = 'AnotherSecret456!'

/** The fields of a user an entity of an ORM serves through its prototype, over a bag of values of its own. */
const SERVED = [
  'id',
  'email',
  'name',
  'passwordHash',
  'role',
  'status',
  'tenantId',
  'emailVerified',
  'mfaEnabled',
  'lastLoginAt',
  'createdAt'
] as const

/** An entity shaped like a Sequelize or Mongoose one: the values sit in `dataValues`, the accessors on the prototype. */
class HydratedUser {
  constructor(readonly dataValues: AuthUser) {}
}
for (const field of SERVED)
  Object.defineProperty(HydratedUser.prototype, field, {
    get(this: HydratedUser): unknown {
      return this.dataValues[field]
    }
  })

/** Makes the repository answer with hydrated entities. */
function hydrate(booted: BootstrappedTestApp): void {
  const byEmail = booted.repo.findByEmail.bind(booted.repo)
  const byId = booted.repo.findById.bind(booted.repo)
  booted.repo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
    const user = await byEmail(...args)
    return user === null ? user : (new HydratedUser(user) as Partial<AuthUser> as AuthUser)
  }
  booted.repo.findById = async (...args: Parameters<typeof byId>) => {
    const user = await byId(...args)
    return user === null ? user : (new HydratedUser(user) as Partial<AuthUser> as AuthUser)
  }
}

describe('values a host serves for the fields of a contract (E2E)', () => {
  let app: INestApplication
  let booted: BootstrappedTestApp

  beforeEach(async () => {
    booted = await bootstrapTestApp({ tokenDelivery: 'bearer' })
    app = booted.app
  })

  afterEach(async () => {
    await app.close()
  })

  // Scenario: a user whose entity serves its fields through the prototype, logging in, reading its own profile,
  // refreshing and changing its password. Expected: every step works and the profile carries the role, the tenant and
  // the status. Why: the copy is spread into the token payload, so a field the copy keeps out of a spread would leave
  // the token without a role, a tenant or a status and every later route would answer 401.
  it('serves a user whose entity keeps its fields on the prototype through login, me, refresh and a password change', async () => {
    const http = request(app.getHttpServer())
    await http
      .post('/register')
      .send({ email: EMAIL, password: PASSWORD, name: 'Hydrated User', tenantId: 't1' })
      .expect(201)
    hydrate(booted)

    const login = await http
      .post('/login')
      .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })
    const tokens = login.body as { accessToken: string; refreshToken: string }
    const me = await http.get('/me').set('Authorization', `Bearer ${tokens.accessToken}`)
    const refreshed = await http.post('/refresh').send({ refreshToken: tokens.refreshToken })
    const changed = await http
      .post('/password/change')
      .set('Authorization', `Bearer ${tokens.accessToken}`)
      .send({ currentPassword: PASSWORD, newPassword: NEXT_PASSWORD })
    const old = await http.post('/login').send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })
    const next = await http
      .post('/login')
      .send({ email: EMAIL, password: NEXT_PASSWORD, tenantId: 't1' })

    expect(login.status).toBe(200)
    expect(me.status).toBe(200)
    expect(me.body).toEqual(expect.objectContaining({ email: EMAIL, tenantId: 't1' }))
    expect(me.body).not.toHaveProperty('passwordHash')
    expect(refreshed.status).toBe(200)
    expect([200, 204]).toContain(changed.status)
    expect(old.status).toBe(401)
    expect(next.status).toBe(200)
  })

  // Scenario: the second factor of a user served as a function, and as a getter answering one. Expected: the login ends
  // in the internal error and issues no token. Why: a field that is dropped reads as absent and `mfaEnabled` absent is
  // a user without a second factor, so the login would hand out tokens where the challenge is due.
  it.each(['function', 'getter'] as const)(
    'refuses a login whose mfaEnabled is served as a %s, and issues no token',
    async (shape) => {
      const http = request(app.getHttpServer())
      await http
        .post('/register')
        .send({ email: EMAIL, password: PASSWORD, name: 'Hydrated User', tenantId: 't1' })
        .expect(201)
      const byEmail = booted.repo.findByEmail.bind(booted.repo)
      booted.repo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
        const user = await byEmail(...args)
        if (user === null) return user
        const served = { ...user }
        if (shape === 'function') Object.assign(served, { mfaEnabled: () => true })
        else
          Object.defineProperty(served, 'mfaEnabled', { get: () => () => true, enumerable: true })
        return served
      }

      const login = await http
        .post('/login')
        .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })

      expect(login.status).toBe(500)
      expect(login.body).not.toHaveProperty('accessToken')
      expect(JSON.stringify(login.body)).toContain(AUTH_ERROR_CODES.INTERNAL)
    }
  )

  // Scenario: the second factor of a platform admin served as a function. Expected: the platform login ends in the
  // internal error and issues no token. Why: the same as for a user, on the plane that holds the keys of the others.
  it('refuses a platform login whose mfaEnabled is served as a function, and issues no token', async () => {
    await app.close()
    booted = await bootstrapTestApp(
      { platform: { enabled: true } },
      { controllers: { auth: true, platform: true } }
    )
    app = booted.app
    const passwordHash = await booted.app.get(PasswordService).hash(PASSWORD)
    booted.platformRepo.seed({
      id: 'p1',
      email: 'admin@example.com',
      name: 'Admin',
      passwordHash,
      role: 'SUPER_ADMIN',
      status: 'active',
      mfaEnabled: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLoginAt: null
    })
    const byEmail = booted.platformRepo.findByEmail.bind(booted.platformRepo)
    booted.platformRepo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
      const admin = await byEmail(...args)
      return admin === null ? admin : { ...admin, mfaEnabled: (() => true) as never }
    }

    const login = await request(app.getHttpServer())
      .post('/platform/login')
      .send({ email: 'admin@example.com', password: PASSWORD })

    expect(login.status).toBe(500)
    expect(login.body).not.toHaveProperty('accessToken')
  })

  // Scenario: an account whose e-mail is not verified, served with a Boolean wrapper where `emailVerified` is promised,
  // and an account that serves no `mfaEnabled` at all. Expected: the login of both ends in the internal error and issues
  // no token, while the unwrapped unverified account is turned away as unverified. Why: `new Boolean(false)` is truthy,
  // so `!user.emailVerified` would be false and the account would pass; an absent `mfaEnabled` reads as a second factor
  // that is off.
  it.each(['a Boolean wrapper in emailVerified', 'no mfaEnabled'] as const)(
    'refuses a login of an account served with %s, and issues no token',
    async (shape) => {
      await app.close()
      booted = await bootstrapTestApp({
        tokenDelivery: 'bearer',
        emailVerification: { required: true }
      })
      app = booted.app
      const http = request(app.getHttpServer())
      await http
        .post('/register')
        .send({ email: EMAIL, password: PASSWORD, name: 'Hydrated User', tenantId: 't1' })
        .expect(201)
      const control = await http
        .post('/login')
        .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })
      const byEmail = booted.repo.findByEmail.bind(booted.repo)
      booted.repo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
        const user = await byEmail(...args)
        if (user === null) return user
        if (shape === 'no mfaEnabled') {
          const { mfaEnabled: _omitted, ...rest } = user
          return rest as AuthUser
        }
        return { ...user, emailVerified: new Boolean(false) as never }
      }

      const login = await http
        .post('/login')
        .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })

      expect(control.status).toBe(403)
      expect(login.status).toBe(500)
      expect(login.body).not.toHaveProperty('accessToken')
      expect(JSON.stringify(login.body)).toContain(AUTH_ERROR_CODES.INTERNAL)
    }
  )

  // Scenario: an account whose id is a number and whose `createdAt` is the date of a date library, fields that only
  // inform. Expected: the login still issues tokens. Why: a numeric id is how many databases key rows and a date library's
  // date is common in a host's record; refusing them would turn a working app into a 500 on every login.
  it('still logs in an account whose id is a number and whose createdAt is a date library value', async () => {
    const http = request(app.getHttpServer())
    await http
      .post('/register')
      .send({ email: EMAIL, password: PASSWORD, name: 'Hydrated User', tenantId: 't1' })
      .expect(201)
    class DayjsLike {
      format(): string {
        return 'formatted'
      }
    }
    const byEmail = booted.repo.findByEmail.bind(booted.repo)
    booted.repo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
      const user = await byEmail(...args)
      return user === null
        ? user
        : { ...user, id: 42 as never, createdAt: new DayjsLike() as never }
    }

    const login = await http
      .post('/login')
      .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })

    expect(login.status).toBe(200)
    expect(login.body).toHaveProperty('accessToken')
  })

  // Scenario: an account whose id is an object that prints as its hex (the id type of a document database), and one
  // whose id is a Map. Expected: the first logs in and the second is refused with no token. Why: the first names one
  // row, and the second prints as `{}` in a claim for every account that has one, so it could stand for any of them.
  it.each([
    ['an object that prints as its id', 200],
    ['a Map', 500]
  ] as const)('answers a login whose id is %s with %i', async (kind, status) => {
    const http = request(app.getHttpServer())
    await http
      .post('/register')
      .send({ email: EMAIL, password: PASSWORD, name: 'Hydrated User', tenantId: 't1' })
      .expect(201)
    class HexId {
      toString(): string {
        return '64b0000000000000000000a1'
      }
    }
    const id = kind === 'a Map' ? new Map() : new HexId()
    const byEmail = booted.repo.findByEmail.bind(booted.repo)
    booted.repo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
      const user = await byEmail(...args)
      return user === null ? user : { ...user, id: id as never }
    }

    const login = await http
      .post('/login')
      .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })

    expect(login.status).toBe(status)
    expect(login.body.accessToken !== undefined).toBe(status === 200)
  })

  // Scenario: an account whose id is a number, and one whose id is an object that prints as its hex, through login, me,
  // refresh and a password change, with a repository that finds a row by the id the library gives it, as a driver does.
  // Expected: every step works and the token's subject is the id as a string. Why: a claim, a key and a comparison all
  // take a string, so the library keeps the id as the text it prints as, and the verifier of every later request
  // finds the same string in the token that the repository is asked for.
  class HexId {
    toString(): string {
      return '64b0000000000000000000a1'
    }
  }

  it.each([
    ['a number', (): unknown => 42],
    ['an object that prints as its hex', (): unknown => new HexId()]
  ] as const)(
    'serves an account whose id is %s through login, me, refresh and a password change',
    async (_kind, make) => {
      const http = request(app.getHttpServer())
      await http
        .post('/register')
        .send({ email: EMAIL, password: PASSWORD, name: 'Hydrated User', tenantId: 't1' })
        .expect(201)
      const byEmail = booted.repo.findByEmail.bind(booted.repo)
      const byId = booted.repo.findById.bind(booted.repo)
      const stored = [...booted.repo.users.values()][0]
      const asked: unknown[] = []
      booted.repo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
        const user = await byEmail(...args)
        return user === null ? user : { ...user, id: make() as never }
      }
      booted.repo.findById = async (ref: Parameters<typeof byId>[0]) => {
        asked.push(ref.id)
        const user = await byId({ ...ref, id: stored?.id ?? ref.id })
        return user === null ? user : { ...user, id: make() as never }
      }

      const login = await http
        .post('/login')
        .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })
      const tokens = login.body as { accessToken: string; refreshToken: string }
      const me = await http.get('/me').set('Authorization', `Bearer ${tokens.accessToken}`)
      const refreshed = await http.post('/refresh').send({ refreshToken: tokens.refreshToken })
      const changed = await http
        .post('/password/change')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .send({ currentPassword: PASSWORD, newPassword: NEXT_PASSWORD })
      const claims = JSON.parse(
        Buffer.from(tokens.accessToken.split('.')[1] ?? '', 'base64url').toString()
      ) as { sub: unknown }

      expect(login.status).toBe(200)
      expect(typeof claims.sub).toBe('string')
      expect(me.status).toBe(200)
      expect(refreshed.status).toBe(200)
      expect([200, 204]).toContain(changed.status)
      expect(asked.every((id) => typeof id === 'string')).toBe(true)
    }
  )

  // Scenario: the tenant of an account served as an instance of a class of the host (an id type of a driver) while the
  // request names it as a string. Expected: the login ends in the library's internal error and issues no token. Why: a
  // tenant is read as a string and nothing else, because it is written into the claims of a token, where two objects
  // that serialize to `{}` would be one tenant, so the copy refuses it before any comparison can.
  it('refuses a login whose tenantId is an object where the request names a string', async () => {
    const http = request(app.getHttpServer())
    await http
      .post('/register')
      .send({ email: EMAIL, password: PASSWORD, name: 'Hydrated User', tenantId: 't1' })
      .expect(201)
    class TenantIdLike {
      toString(): string {
        return 't1'
      }
    }
    const byEmail = booted.repo.findByEmail.bind(booted.repo)
    booted.repo.findByEmail = async (...args: Parameters<typeof byEmail>) => {
      const user = await byEmail(...args)
      return user === null ? user : { ...user, tenantId: new TenantIdLike() as never }
    }

    const login = await http
      .post('/login')
      .send({ email: EMAIL, password: PASSWORD, tenantId: 't1' })

    expect(login.status).toBe(500)
    expect(login.body).not.toHaveProperty('accessToken')
  })
})
