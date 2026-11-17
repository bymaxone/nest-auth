/**
 * @fileoverview The shape of the hooks and the email provider, and the controller flags, that
 * `registerAsync` is handed: refused at registration when they can be seen, never at the first event.
 *
 * @layer Test
 */

import { REQUIRED_EMAIL_METHODS, validateRegistrationShapes } from './provider-shape'
import { BYMAX_AUTH_EMAIL_PROVIDER, BYMAX_AUTH_HOOKS } from '../bymax-auth.constants'

/** An email provider carrying every required method. */
function emailProvider(): Record<string, () => Promise<void>> {
  return Object.fromEntries(REQUIRED_EMAIL_METHODS.map((name) => [name, async () => undefined]))
}

describe('validateRegistrationShapes', () => {
  // Scenario: no providers at all, hooks and an email provider that are objects of functions, and a
  // class registered through useClass. Expected: nothing is refused.
  it('accepts no provider, a valid value, and any provider it cannot see', () => {
    class Hooks {
      async afterLogin(): Promise<void> {}
    }
    expect(() => validateRegistrationShapes(undefined, [])).not.toThrow()
    expect(() =>
      validateRegistrationShapes(undefined, [
        { provide: BYMAX_AUTH_HOOKS, useValue: { afterLogin: async () => undefined } },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: emailProvider() }
      ])
    ).not.toThrow()
    expect(() =>
      validateRegistrationShapes(undefined, [
        { provide: BYMAX_AUTH_HOOKS, useClass: Hooks },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useFactory: () => ({}) }
      ])
    ).not.toThrow()
  })

  // Scenario: a hook that is present and is not a function, an empty object, and a value that is not an
  // object. Expected: refused, naming the member and the type, never the content. Why: every hook is
  // called as `hooks.x?.(...)`, so a value that is not a function throws at the first event.
  it.each([
    [
      { onLoginFailed: true },
      'BYMAX_AUTH_HOOKS.onLoginFailed must be a function (received a boolean)'
    ],
    [
      { afterLogin: 'hunter2' },
      'BYMAX_AUTH_HOOKS.afterLogin must be a function (received a string)'
    ],
    ['hunter2', 'BYMAX_AUTH_HOOKS must be an object (received a string)'],
    [5, 'BYMAX_AUTH_HOOKS must be an object (received 5)']
  ])('refuses hooks %p', (value, message) => {
    expect(() =>
      validateRegistrationShapes(undefined, [{ provide: BYMAX_AUTH_HOOKS, useValue: value }])
    ).toThrow(message)
  })

  // Scenario: hooks registered as null or undefined. Expected: read as no hooks, the way an unset option is.
  it.each([null, undefined])('reads hooks %p as no hooks', (value) => {
    expect(() =>
      validateRegistrationShapes(undefined, [{ provide: BYMAX_AUTH_HOOKS, useValue: value }])
    ).not.toThrow()
  })

  // Scenario: a hooks object that is a class instance with methods. Expected: its inherited methods
  // count and are accepted.
  it('accepts hooks that are a class instance', () => {
    class Hooks {
      async afterLogin(): Promise<void> {}
    }

    expect(() =>
      validateRegistrationShapes(undefined, [{ provide: BYMAX_AUTH_HOOKS, useValue: new Hooks() }])
    ).not.toThrow()
  })

  // Scenario: an email provider missing each required method in turn, one with a non-function member,
  // and one that is not an object. Expected: refused naming the method.
  it.each(REQUIRED_EMAIL_METHODS)('refuses an email provider without %s', (missing) => {
    const provider = emailProvider()
    Reflect.deleteProperty(provider, missing)

    expect(() =>
      validateRegistrationShapes(undefined, [
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: provider }
      ])
    ).toThrow(`BYMAX_AUTH_EMAIL_PROVIDER.${missing} is required and must be a function.`)
  })

  it('refuses an email provider that holds a member that is not a function', () => {
    expect(() =>
      validateRegistrationShapes(undefined, [
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: { ...emailProvider(), from: 'a@b.c' } }
      ])
    ).toThrow('BYMAX_AUTH_EMAIL_PROVIDER.from must be a function (received a string)')
    expect(() =>
      validateRegistrationShapes(undefined, [{ provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: 5 }])
    ).toThrow('BYMAX_AUTH_EMAIL_PROVIDER must be an object (received 5)')
  })

  // Scenario: the optional email methods absent. Expected: accepted, since the library guards them.
  it('does not require the optional email methods', () => {
    expect(() =>
      validateRegistrationShapes(undefined, [
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: emailProvider() }
      ])
    ).not.toThrow()
  })

  // Scenario: the controller flags handed to registerAsync. Expected: checked by the same call.
  it('checks the controller flags', () => {
    expect(() => validateRegistrationShapes({ mfa: 'yes' }, [])).toThrow(
      'controllers.mfa must be true or false (received a string)'
    )
  })
})
