/**
 * @fileoverview Executes the server half of the README Quick Start (sections 2 to 5) as written.
 * @layer test
 *
 * `check:published` compiles the README's snippets, and `readme-contract.e2e-spec.ts` reads its
 * imports and names, but neither can see a wrong option shape, a provider that is never bound or
 * a guard that cannot read its credential: a Quick Start can compile and still fail for the
 * reader. The blocks below are taken from the README text at test time, never copied, compiled
 * and run inside a real Nest application, so a change to a block is a change to what runs here.
 *
 * What stands in for what the README leaves to the reader, and nothing else does:
 * - `./prisma.service`, the reader's database client: an in-memory object that answers exactly the
 *   Prisma calls the repository block makes;
 * - `resend`, the mail transport: a client that records what it was asked to send;
 * - `ConfigModule`, `ConfigService`, `DatabaseModule`, `RedisModule` and `RedisService`, which the
 *   module block uses without importing. The README names them as the reader's own, and a check
 *   below fails if it stops saying so. `ConfigModule` is a plain, non-global module, exactly as
 *   the README imports it;
 * - `cookie-parser`, which the `main.ts` block mounts: a minimal parser that fills `req.cookies`;
 * - the Redis client behind `RedisService` is `ioredis-mock`. No suite in this repository starts a
 *   real Redis (no container runtime and no Redis service in CI), so a real one would be a new
 *   piece of infrastructure rather than a choice between two existing ones.
 *
 * NOT executed, by design:
 * - the fragment inside Section 3 (`describeChannelStatus` inside a method) and the one-line
 *   `extraProviders` entry that follows the email provider: they are not programs. The email
 *   provider block is compiled and the module block binds its class;
 * - Section 6 (React) and Section 7 (Next.js): they are not part of this file.
 */
import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { compileFunction } from 'node:vm'

import * as nestCommon from '@nestjs/common'
import { Injectable, Module } from '@nestjs/common'
import type { INestApplication, Type } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import RedisMock from 'ioredis-mock'
import request from 'supertest'
import { ModuleKind, ScriptTarget, transpileModule } from 'typescript'

import * as nestAuth from '../../src/server/index'

const README = readFileSync(join(__dirname, '../../README.md'), 'utf8')

const QUICK_START_START = '## 🚀 Quick Start'
const QUICK_START_END = '## ⚙️ Configuration'

/** The top-level `typescript` fences of the Quick Start, in the order the README shows them. */
function quickStartBlocks(): string[] {
  const start = README.indexOf(QUICK_START_START)
  const end = README.indexOf(QUICK_START_END)
  if (start === -1 || end === -1) throw new Error('README has no Quick Start section')
  // Anchored to the line start so a fence inside a blockquote is not one of these.
  return Array.from(
    README.slice(start, end).matchAll(/^```typescript\n([\s\S]*?)^```$/gm),
    (match) => match[1] ?? ''
  )
}

/** The one block that contains `marker`; zero or several is a README this suite no longer reads. */
function block(marker: string): string {
  const found = quickStartBlocks().filter((candidate) => candidate.includes(marker))
  if (found.length !== 1) {
    throw new Error(`Expected one Quick Start block containing "${marker}", found ${found.length}`)
  }
  return found[0] as string
}

type Modules = Readonly<Record<string, unknown>>

/** Compiles one README block and runs it, resolving its imports through `modules` only. */
function runBlock(
  source: string,
  modules: Modules,
  globals: Readonly<Record<string, unknown>> = {}
): Record<string, unknown> {
  const { outputText } = transpileModule(source, {
    compilerOptions: {
      module: ModuleKind.CommonJS,
      target: ScriptTarget.ES2022,
      esModuleInterop: true,
      experimentalDecorators: true,
      emitDecoratorMetadata: true
    }
  })
  const exported: Record<string, unknown> = {}
  const load = (specifier: string): unknown => {
    if (specifier in modules) return modules[specifier]
    throw new Error(`The Quick Start imports "${specifier}", which this suite does not provide`)
  }
  // `Reflect` is passed in because `vm` compiles outside Jest's sandbox, where `reflect-metadata`
  // has not run, so decorator metadata would silently not be recorded.
  const scope = { Reflect, ...globals }
  compileFunction(outputText, ['require', 'exports', ...Object.keys(scope)])(
    load,
    exported,
    ...Object.values(scope)
  )
  return exported
}

// ---------------------------------------------------------------------------
// Stand-ins for what the reader owns
// ---------------------------------------------------------------------------

type Row = Record<string, unknown>

/** The filter a Prisma `where` expresses for the calls the repository block makes. */
function matches(row: Row, where: Row): boolean {
  return Object.entries(where).every(([key, value]) => {
    if (key === 'email_tenantId') return matches(row, value as Row)
    return row[key] === value
  })
}

/** An in-memory stand-in for the reader's `PrismaService`, covering what the README calls. */
@Injectable()
class PrismaService {
  readonly rows: Row[] = []

  readonly user = {
    findFirst: async ({ where }: { where: Row }): Promise<Row | null> =>
      this.rows.find((row) => matches(row, where)) ?? null,
    findUnique: async ({ where }: { where: Row }): Promise<Row | null> =>
      this.rows.find((row) => matches(row, where)) ?? null,
    create: async ({ data }: { data: Row }): Promise<Row> => {
      const row: Row = {
        id: randomUUID(),
        lastLoginAt: null,
        mfaSecret: null,
        mfaRecoveryCodes: null,
        oauthProvider: null,
        oauthProviderId: null,
        createdAt: new Date(),
        ...data
      }
      this.rows.push(row)
      return row
    },
    updateMany: async ({ where, data }: { where: Row; data: Row }): Promise<{ count: number }> => {
      const hit = this.rows.filter((row) => matches(row, where))
      hit.forEach((row) => Object.assign(row, data))
      return { count: hit.length }
    }
  }
}

/** Every mail the transport stand-in was asked to send. */
const sentMail: Row[] = []

class Resend {
  readonly emails = {
    send: async (message: Row): Promise<void> => {
      sentMail.push(message)
    }
  }
}

const ENV: Record<string, string> = {
  JWT_SECRET: 'quick-start-secret-that-is-at-least-32-chars-long',
  RESEND_API_KEY: 're_test',
  APP_URL: 'https://app.example.com'
}

@Injectable()
class ConfigService {
  get(key: string): string | undefined {
    return ENV[key]
  }
}

@Module({ providers: [ConfigService], exports: [ConfigService] })
class ConfigModule {}

@Injectable()
class RedisService {
  // `ioredis-mock` instances share one keyspace within a process, so every build starts it empty.
  readonly client = new RedisMock()

  async onModuleInit(): Promise<void> {
    await this.client.flushall()
  }
}

/**
 * A minimal `cookie-parser`: fills `req.cookies` from the `Cookie` header, which is the whole of
 * what the library needs from the real one. The package is not installed here.
 */
function cookieParser(): (
  req: { headers: Record<string, string | undefined>; cookies?: Record<string, string> },
  res: unknown,
  next: () => void
) => void {
  return (req, _res, next) => {
    req.cookies = Object.fromEntries(
      (req.headers['cookie'] ?? '')
        .split('; ')
        .filter(Boolean)
        .map((pair) => {
          const at = pair.indexOf('=')
          return [pair.slice(0, at), decodeURIComponent(pair.slice(at + 1))]
        })
    )
    next()
  }
}

/** The identifiers the module block uses without importing them: the reader's own. */
const READER_OWNED = [
  'ConfigModule',
  'ConfigService',
  'DatabaseModule',
  'RedisModule',
  'RedisService'
]

/** A fresh app built from the (possibly altered) README blocks, plus the database behind it. */
async function buildApp(
  alter: (marker: string, source: string) => string = (_marker, source) => source
): Promise<{ app: INestApplication; db: PrismaService }> {
  const db = new PrismaService()
  sentMail.length = 0

  @Module({ providers: [{ provide: PrismaService, useValue: db }], exports: [PrismaService] })
  class DatabaseModule {}

  @Module({ providers: [RedisService], exports: [RedisService] })
  class RedisModule {}

  const common: Modules = { '@nestjs/common': nestCommon, '@bymax-one/nest-auth': nestAuth }
  const source = (marker: string): string => alter(marker, block(marker))

  const repository = runBlock(source('// user.repository.ts'), {
    ...common,
    './prisma.service': { PrismaService }
  })
  const email = runBlock(source('// email.provider.ts'), { ...common, resend: { Resend } })
  const appModule = runBlock(
    source('// app.module.ts'),
    { ...common },
    {
      ConfigModule,
      ConfigService,
      DatabaseModule,
      RedisModule,
      RedisService,
      PrismaUserRepository: repository['PrismaUserRepository'],
      ResendEmailProvider: email['ResendEmailProvider']
    }
  )
  const controller = runBlock(source('// users.controller.ts'), common)

  // The README does not show where `UsersController` is registered. A reader adds it to the
  // `controllers` of the module that imports `BymaxAuthModule`, which is what this does.
  const AppModule = appModule['AppModule'] as Type<unknown>
  Reflect.defineMetadata('controllers', [controller['UsersController']], AppModule)

  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .setLogger({
      log: () => undefined,
      error: () => undefined,
      warn: () => undefined,
      debug: () => undefined,
      verbose: () => undefined
    })
    .compile()
  // `main.ts` as the README writes it. `NestFactory.create` hands back the application this suite
  // built (and `listen` initializes it instead of binding port 3000), so what runs is the README's
  // own `app.use(cookieParser())`, not a parser installed here.
  let listening: () => void = () => undefined
  const started = new Promise<void>((resolve) => {
    listening = resolve
  })
  let app: INestApplication | undefined
  runBlock(source("import cookieParser from 'cookie-parser'"), {
    '@nestjs/core': {
      NestFactory: {
        create: async (): Promise<INestApplication> => {
          app = moduleRef.createNestApplication()
          app.listen = async (): Promise<never> => {
            await (app as INestApplication).init()
            listening()
            return undefined as never
          }
          return app
        }
      }
    },
    'cookie-parser': { __esModule: true, default: cookieParser },
    './app.module': { AppModule }
  })
  await started
  return { app: app as INestApplication, db }
}

const CREDENTIALS = { email: 'ada@example.com', password: 'Str0ng-Passw0rd!', tenantId: 'acme' }

/**
 * Walks the journey the Quick Start promises and answers the first step that does not hold, or
 * `null` when every step does. Answering instead of asserting lets the planted-defect table below
 * prove each defect is caught by the same walk.
 */
async function walk(app: INestApplication, db: PrismaService): Promise<string | null> {
  const http = app.getHttpServer()
  const agent = request.agent(http)

  const registered = await agent.post('/register').send({ ...CREDENTIALS, name: 'Ada Lovelace' })
  if (registered.status !== 201) return `register answered ${registered.status}`

  // A new account is pending until its address is verified: the code reaches the reader's mail
  // provider, here the README's own `ResendEmailProvider`, and comes back through `/verify-email`.
  const verification = sentMail.find((mail) => mail['to'] === CREDENTIALS.email)
  const otp = /<strong>(\d+)<\/strong>/.exec(String(verification?.['html'] ?? ''))?.[1]
  if (!otp) return 'the README email provider was never handed a verification code'
  const verified = await agent
    .post('/verify-email')
    .send({ email: CREDENTIALS.email, tenantId: CREDENTIALS.tenantId, otp })
  if (verified.status !== 204)
    return `verify-email answered ${verified.status} ${JSON.stringify(verified.body)} for otp ${otp}`

  const login = await agent.post('/login').send(CREDENTIALS)
  if (login.status !== 200) return `login answered ${login.status}`

  // The login cookies are `Secure`, which a browser honours on localhost but supertest does not
  // over plain http, so they are forwarded by hand. Nothing else about them is altered.
  const cookie = (login.headers['set-cookie'] as unknown as string[])
    .map((c) => c.split(';')[0])
    .join('; ')
  const me = await request(http).get('/users/me').set('Cookie', cookie)
  if (me.status !== 200) return `GET /users/me answered ${me.status} ${JSON.stringify(me.body)}`
  const profile = me.body as Row
  if (profile['role'] !== 'user' || profile['tenantId'] !== 'acme' || !profile['id']) {
    return `GET /users/me answered ${JSON.stringify(profile)}`
  }

  const refused = await request(http).get('/users').set('Cookie', cookie)
  if (refused.status !== 403) return `GET /users as a user answered ${refused.status}`

  const anonymous = await request(http).get('/users/me')
  if (anonymous.status !== 401)
    return `GET /users/me without credentials answered ${anonymous.status}`

  // Promote the account in the reader's database, then sign in again: the role rides in the token.
  await db.user.updateMany({ where: { email: CREDENTIALS.email }, data: { role: 'admin' } })
  const again = await request(http).post('/login').send(CREDENTIALS)
  if (again.status !== 200) return `second login answered ${again.status}`
  const adminCookie = (again.headers['set-cookie'] as unknown as string[])
    .map((c) => c.split(';')[0])
    .join('; ')
  const listed = await request(http).get('/users').set('Cookie', adminCookie)
  if (listed.status !== 200) return `GET /users as an admin answered ${listed.status}`

  return null
}

/** The Quick Start blocks this suite compiles and runs, by a marker only that block contains. */
const EXECUTED = [
  '// user.repository.ts',
  '// email.provider.ts',
  '// app.module.ts',
  "import cookieParser from 'cookie-parser'",
  '// users.controller.ts'
]

/** The blocks it does not run, each with the reason. A block in neither list fails the suite. */
const NOT_EXECUTED: [marker: string, reason: string][] = [
  [
    "import { BYMAX_AUTH_EMAIL_PROVIDER } from '@bymax-one/nest-auth'",
    'a one-line `extraProviders` entry, not a program; the module block carries the same entry and runs'
  ],
  ['// proxy.ts — Next.js 16 Edge middleware', 'Section 7: the Next.js half is not run here'],
  ['// app/api/auth/silent-refresh/route.ts', 'Section 7: the Next.js half is not run here'],
  ['// app/api/auth/client-refresh/route.ts', 'Section 7: the Next.js half is not run here'],
  ['// app/api/auth/logout/route.ts', 'Section 7: the Next.js half is not run here'],
  [
    '// 1. Mint from an authenticated session',
    'the WebSocket upgrade example is browser code that needs a socket server'
  ],
  [
    '// The module factory runs before the app exists',
    'the WebSocket upgrade example is a configuration excerpt for a gateway this suite does not mount'
  ]
]

/**
 * Defects planted into the README text, each of which the walk (or the boot) must catch. A suite
 * that only ever sees a passing README cannot say whether it would notice a broken one: each row
 * removes or breaks one thing the Quick Start depends on, and `from` must occur exactly once in
 * its block so a README edit that moves it is a failure here rather than a silently dead row.
 */
const PLANTED: { name: string; marker: string; from: string; to: string }[] = [
  {
    name: 'the rate-limit client address source is dropped',
    marker: '// app.module.ts',
    from: "rateLimit: { clientIpSource: 'trusted-proxy' }, // 'peer' | 'trusted-proxy'",
    to: ''
  },
  {
    name: 'the email provider is not bound',
    marker: '// app.module.ts',
    from: 'provide: BYMAX_AUTH_EMAIL_PROVIDER',
    to: 'provide: Symbol("unbound")'
  },
  {
    name: 'the cookie parser is never mounted',
    marker: "import cookieParser from 'cookie-parser'",
    from: 'app.use(cookieParser())',
    to: ''
  },
  {
    name: 'a new account is stored with another password hash than the library supplied',
    marker: '// user.repository.ts',
    from: 'passwordHash: data.passwordHash,\n        role',
    to: "passwordHash: 'x',\n        role"
  },
  {
    name: 'a new account is created with the wrong role',
    marker: '// user.repository.ts',
    from: "role: data.role ?? 'user',\n        status: data.status ?? 'pending'",
    to: "role: 'admin',\n        status: data.status ?? 'pending'"
  },
  {
    name: 'the admin-only route loses its role requirement',
    marker: '// users.controller.ts',
    from: "@Roles('admin')",
    to: ''
  }
]

describe('README Quick Start executes as written (E2E)', () => {
  // Scenario: every name the module block uses without importing is named in the README as the
  // reader's own. Expected: the block's comments say so, so a reader is not left to guess.
  it('says which modules in the module block are the reader’s own', () => {
    const source = block('// app.module.ts')
    const comments = source
      .split('\n')
      .filter((line) => line.trimStart().startsWith('//'))
      .join('\n')
    for (const name of READER_OWNED) {
      const used = new RegExp(`\\b${name}\\b`).test(source.replace(comments, ''))
      if (used) expect(comments).toContain(name)
    }
  })

  // Scenario: the README's repository, email provider, module and controller are composed into one
  // application and a user signs up, signs in, reads their profile and meets the role guard.
  // Expected: every step of the journey holds.
  it('registers, signs in, reads the profile and is held to its role', async () => {
    const { app, db } = await buildApp()
    try {
      expect(await walk(app, db)).toBeNull()
    } finally {
      await app.close()
    }
  })

  // Scenario: every fenced block of the Quick Start is either run by this suite or listed with the
  // reason it is not. Expected: each marker names exactly one block and no block is left over, so
  // a block added to the README cannot go unexecuted without anyone deciding that.
  it('accounts for every Quick Start block', () => {
    const blocks = quickStartBlocks()
    const markers = [...EXECUTED, ...NOT_EXECUTED.map(([marker]) => marker)]
    for (const marker of markers) {
      expect(blocks.filter((candidate) => candidate.includes(marker))).toHaveLength(1)
    }
    const unaccounted = blocks.filter((candidate) => !markers.some((m) => candidate.includes(m)))
    expect(unaccounted.map((candidate) => candidate.split('\n')[0])).toEqual([])
  })

  // Scenario: a defect is planted into one block of the README text. Expected: the application
  // either refuses to boot or the walk reports a step that does not hold; a defect nothing notices
  // would mean this suite cannot tell a working Quick Start from a broken one.
  it.each(PLANTED)('notices when $name', async ({ marker, from, to }) => {
    // Outside the try below: a row whose text is gone from the README must fail loudly, not be
    // counted as a defect the suite caught.
    expect(block(marker).split(from)).toHaveLength(2)
    const planted = (m: string, source: string): string =>
      m === marker ? source.replace(from, to) : source
    let verdict: string | null
    try {
      const { app, db } = await buildApp(planted)
      try {
        verdict = await walk(app, db)
      } finally {
        await app.close()
      }
    } catch (error) {
      verdict = `the application did not boot: ${String(error).slice(0, 120)}`
    }
    expect(verdict).not.toBeNull()
  })
})
