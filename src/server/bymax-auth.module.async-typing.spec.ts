/**
 * @fileoverview Pins what `BymaxAuthModule.registerAsync` accepts as its options factory.
 * @layer test
 *
 * The factory's parameters are whatever the consumer's `inject` list supplies, and the consumer
 * is the one who declares their types. A factory written the ordinary way, with a typed
 * parameter, has to be accepted without a cast. This suite is compiled by the type checker, so
 * the positive cases fail the suite to run at all when the options type stops accepting them,
 * and the negative case is a type-level assertion rather than a suppression comment.
 */

import { BYMAX_AUTH_REDIS_CLIENT, BYMAX_AUTH_USER_REPOSITORY } from './bymax-auth.constants'
import { BymaxAuthModule } from './bymax-auth.module'
import type {
  AuthModuleAsyncOptions,
  BymaxAuthModuleOptions
} from './interfaces/auth-module-options.interface'

class ConfigService {
  get(_key: string): string | undefined {
    return undefined
  }
  getOrThrow(_key: string): string {
    return 'a-secret-that-is-at-least-32-characters-long'
  }
}

class Clock {
  now(): number {
    return 0
  }
}

/** The two providers `registerAsync` insists on at build time; nothing here resolves them. */
const extraProviders = [
  { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: {} },
  { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: {} }
]

/** What a factory has to return; the secret is the field whose type a careless `get` breaks. */
function optionsFor(secret: string): BymaxAuthModuleOptions {
  return { jwt: { secret } } as BymaxAuthModuleOptions
}

/** `true` when a function of type `F` is NOT acceptable as the options factory. */
type Rejected<F> = F extends AuthModuleAsyncOptions['useFactory'] ? false : true

describe('registerAsync options factory typing', () => {
  // Scenario: the README's own shape, a factory with one typed parameter. Expected: it type-checks
  // and registerAsync builds a module. Why: a consumer should not need a cast to hand Nest the
  // value Nest injects, and the exported type is what their compiler reads.
  it('accepts a factory with one typed parameter', () => {
    const built = BymaxAuthModule.registerAsync({
      useFactory: (config: ConfigService) => optionsFor(config.getOrThrow('JWT_SECRET')),
      inject: [ConfigService],
      extraProviders
    })

    expect(built.module).toBe(BymaxAuthModule)
  })

  // Scenario: two typed parameters, asynchronous. Expected: accepted.
  it('accepts an asynchronous factory with several typed parameters', () => {
    const built = BymaxAuthModule.registerAsync({
      useFactory: async (config: ConfigService, clock: Clock) =>
        optionsFor(`${config.getOrThrow('JWT_SECRET')}${clock.now()}`),
      inject: [ConfigService, Clock],
      extraProviders
    })

    expect(built.module).toBe(BymaxAuthModule)
  })

  // Scenario: the forms that already worked. Expected: they still do, so loosening the parameter
  // type breaks nobody.
  it('still accepts a factory with no parameters and one written with rest unknown', () => {
    const none = BymaxAuthModule.registerAsync({
      useFactory: () => optionsFor('x'),
      extraProviders
    })
    const rest = BymaxAuthModule.registerAsync({
      useFactory: (...args: unknown[]) => optionsFor(String(args.length)),
      extraProviders
    })

    expect([none.module, rest.module]).toEqual([BymaxAuthModule, BymaxAuthModule])
  })

  // Scenario: two factories that differ only in the secret's type, `string` and `string |
  // undefined` (what `config.get` returns). Expected: the first is acceptable and the second is
  // not, both asserted at compile time without any suppression. Why: loosening the parameter must
  // not loosen the returned options, and the control proves the second is refused for its secret
  // and not for its parameter.
  it('refuses an undefined secret and accepts the same factory with a string secret', () => {
    type WithSecret<S> = Omit<BymaxAuthModuleOptions, 'jwt'> & {
      jwt: Omit<BymaxAuthModuleOptions['jwt'], 'secret'> & { secret: S }
    }
    const control: Rejected<(config: ConfigService) => WithSecret<string>> = false
    const undefinedSecret: Rejected<(config: ConfigService) => WithSecret<string | undefined>> =
      true

    expect([control, undefinedSecret]).toEqual([false, true])
  })
})
