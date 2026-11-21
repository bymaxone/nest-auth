/**
 * The Nth-operation sweep over what the library reads from the host.
 *
 * A host object (the options, a record a repository returns) can throw from any read: a getter, a Proxy, a
 * revoked handle. Wrap the object so that the Nth trap throws a sentinel, run the call, and raise N until a run
 * never reaches trap N. Every N must end the way the library's contract says a failed host read ends: in a library
 * error that carries the host's error as its `cause`, with none of the host's text in the message.
 *
 * A host error that escapes unwrapped reaches the HTTP filter or a log as the host wrote it, and a code path that
 * reads a field in an unexpected order is found by the sweep where no hand-written case would look.
 *
 * @layer Test
 */
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY
} from '../../src/server/bymax-auth.constants'
import { BymaxAuthModule } from '../../src/server/bymax-auth.module'
import { AUTH_ERROR_CODES } from '../../src/server/errors/auth-error-codes'
import { AuthException } from '../../src/server/errors/auth-exception'
import { AuthService } from '../../src/server/services/auth.service'
import { bootstrapTestApp, JWT_SECRET, MFA_ENCRYPTION_KEY } from './setup'

/** The error a host read throws; its text must never reach the library's error. */
class HostFault extends Error {
  constructor() {
    super('host-fault-text-that-must-not-leak')
  }
}

/** Counts the traps a run reaches and throws the fault at the one numbered `at`, while `on`. */
interface Trap {
  n: number
  at: number
  on: boolean
}

/** Wraps an object and everything reachable from it by reads, so that each read is a numbered trap. */
function trapped<T>(target: T, trap: Trap, fault: HostFault): T {
  if (target === null || typeof target !== 'object') return target
  const tick = (): void => {
    if (!trap.on) return
    trap.n += 1
    if (trap.n === trap.at) throw fault
  }
  return new Proxy(target as object, {
    get(object, key, receiver) {
      tick()
      const value: unknown = Reflect.get(object, key, receiver)
      return typeof value === 'function' ? value : trapped(value, trap, fault)
    },
    has(object, key) {
      tick()
      return Reflect.has(object, key)
    },
    ownKeys(object) {
      tick()
      return Reflect.ownKeys(object)
    },
    getOwnPropertyDescriptor(object, key) {
      tick()
      return Reflect.getOwnPropertyDescriptor(object, key)
    }
  }) as T
}

/** What one run of the sweep ended in, for every N it reached. */
interface Outcome {
  ops: number
  failures: string[]
}

/**
 * Runs `run` once per N and returns how many traps the call reaches and which N ended wrongly.
 *
 * @param build - Prepares one run; the traps are armed only for `run`.
 * @param run - The call under test.
 * @param ends - Whether an error is the library's wrapping of the fault.
 */
async function sweep<C>(
  build: (trap: Trap, fault: HostFault) => Promise<C>,
  run: (context: C) => Promise<unknown>,
  ends: (error: unknown, fault: HostFault) => boolean,
  max = 400
): Promise<Outcome> {
  const failures: string[] = []
  for (let at = 1; at <= max; at += 1) {
    const fault = new HostFault()
    const trap: Trap = { n: 0, at, on: false }
    const context = await build(trap, fault)
    trap.on = true
    let error: unknown
    try {
      await run(context)
    } catch (caught) {
      error = caught
    }
    trap.on = false
    if (trap.n < at) return { ops: trap.n, failures }
    if (error === undefined) {
      failures.push(`${at}: swallowed`)
      continue
    }
    if (!ends(error, fault))
      failures.push(`${at}: ${error instanceof Error ? error.constructor.name : typeof error}`)
  }
  throw new Error('the sweep did not end within its bound')
}

const BASE_OPTIONS = (): Record<string, unknown> => ({
  jwt: { secret: JWT_SECRET },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] }, platformHierarchy: { SUPER_ADMIN: [] } },
  tokenDelivery: 'bearer',
  emailVerification: { required: false },
  sessions: { enabled: true },
  mfa: { encryptionKey: MFA_ENCRYPTION_KEY, issuer: 'T' },
  environment: 'test',
  secureCookies: false,
  rateLimit: { enabled: false },
  passwordReset: { method: 'token' },
  bruteForce: { maxAttempts: 5, windowSeconds: 900 },
  cookies: { sameSite: 'lax', trustedOrigins: ['https://a.example'] },
  password: { minLength: 12, blocklist: ['x'] },
  oauth: {}
})

/** A library error that carries the fault and none of its text. */
const wrapsFault = (error: unknown, fault: HostFault): boolean =>
  error instanceof Error &&
  error !== fault &&
  error.cause === fault &&
  !error.message.includes(fault.message)

const request = { headers: { 'user-agent': 'sweep' }, ip: '127.0.0.1', socket: {}, cookies: {} }

describe('the host-read sweep', () => {
  jest.setTimeout(300_000)

  // Scenario: the options the host returns from the factory. Expected: every read that throws ends in the
  // library's configuration error with the fault as its cause. Why: the options are read by property access in
  // dozens of places at startup, and none of them may let the host's own error out as if it were the library's.
  it('ends every failed read of the options in a configuration error with the cause', async () => {
    const outcome = await sweep(
      async (trap, fault) => ({ trap, fault }),
      async ({ trap, fault }) => {
        const module = BymaxAuthModule.registerAsync({
          useFactory: () => trapped(BASE_OPTIONS(), trap, fault) as never,
          controllers: { auth: true },
          extraProviders: [
            { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} },
            { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} }
          ]
        })
        const provider = module.providers?.find(
          (item) => (item as { provide?: unknown }).provide === BYMAX_AUTH_OPTIONS
        ) as { useFactory: () => Promise<unknown> }
        return provider.useFactory()
      },
      (error, fault) =>
        wrapsFault(error, fault) && String((error as Error).message).startsWith('[BymaxAuthModule]')
    )

    expect(outcome.ops).toBeGreaterThan(100)
    expect(outcome.failures).toEqual([])
  })

  // Scenario: the user record the repository returns to a login. Expected: every read that throws ends in
  // AuthException INTERNAL with the fault as its cause. Why: the record is read field by field across the login,
  // and a host row whose getter throws must become the library's internal error, not the host's.
  it('ends every failed read of a returned user record in an internal error with the cause', async () => {
    const outcome = await sweep(
      async (trap, fault) => {
        const booted = await bootstrapTestApp({}, { listen: false })
        const auth = booted.app.get(AuthService)
        await auth.register(
          { email: 'u@example.com', password: 'SuperSecret123!', name: 'U', tenantId: 't1' },
          request as never
        )
        const find = booted.repo.findByEmail.bind(booted.repo)
        booted.repo.findByEmail = async (...args: Parameters<typeof find>) => {
          const user = await find(...args)
          return user === null ? user : trapped(user, trap, fault)
        }
        return { auth, close: () => booted.app.close() }
      },
      async ({ auth, close }) => {
        try {
          return await auth.login(
            { email: 'u@example.com', password: 'SuperSecret123!', tenantId: 't1' },
            request as never
          )
        } finally {
          await close()
        }
      },
      (error, fault) =>
        wrapsFault(error, fault) &&
        error instanceof AuthException &&
        (error.getResponse() as { error: { code: string } }).error.code ===
          AUTH_ERROR_CODES.INTERNAL,
      200
    )

    expect(outcome.ops).toBeGreaterThan(10)
    expect(outcome.failures).toEqual([])
  })
})
