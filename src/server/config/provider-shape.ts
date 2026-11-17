/**
 * @fileoverview Boot-time check of the shape of the hooks and the email provider a host registers.
 *
 * A host supplies both as providers, and only a ready-made `useValue` object can be inspected before
 * the application is built: a class, a factory or an alias is given the benefit of the doubt, as it is
 * for the API-key audit hook. For an object that can be seen, a property that is present must be a
 * function, because every hook is called as `hooks.x?.(...)` and a value that is not a function throws
 * at the first event that fires it; and the email provider must carry the methods the library calls
 * without a guard.
 *
 * @layer Config
 */

import type { Provider } from '@nestjs/common'

import { describeReceived } from './describe-received'
import { validateControllerFlags } from './enum-boolean-options'
import { BYMAX_AUTH_EMAIL_PROVIDER, BYMAX_AUTH_HOOKS } from '../bymax-auth.constants'

/** The email methods the library calls with no guard, so a provider without one fails on that message. */
export const REQUIRED_EMAIL_METHODS: readonly string[] = [
  'sendPasswordResetToken',
  'sendPasswordResetOtp',
  'sendEmailVerificationOtp',
  'sendMfaEnabledNotification',
  'sendMfaDisabledNotification',
  'sendInvitation'
]

/** The `useValue` of the provider registered under `token`, when it is a ready-made value. */
function readyMadeValue(providers: Provider[], token: symbol): { found: boolean; value: unknown } {
  const entry = providers.find(
    (p) => typeof p !== 'function' && 'provide' in p && p.provide === token
  )
  if (entry === undefined || !('useValue' in entry)) return { found: false, value: undefined }
  return { found: true, value: entry.useValue }
}

/** Every property name an object carries, own or inherited, except the constructor. */
function memberNames(value: object): string[] {
  const names = new Set<string>()
  for (let node: object | null = value; node !== null && node !== Object.prototype;) {
    for (const name of Object.getOwnPropertyNames(node)) {
      if (name !== 'constructor') names.add(name)
    }
    node = Object.getPrototypeOf(node)
  }
  return [...names]
}

/**
 * Refuses a ready-made value that is not an object, or that holds a property that is not a function.
 *
 * @param label - The provider, for the message.
 * @param value - The `useValue`.
 */
function assertFunctionMembers(label: string, value: unknown): asserts value is object {
  if (typeof value !== 'object' || value === null) {
    throw new Error(
      `[BymaxAuthModule] ${label} must be an object (received ${describeReceived(value)}).`
    )
  }
  for (const name of memberNames(value)) {
    const member: unknown = Reflect.get(value, name)
    if (typeof member !== 'function') {
      throw new Error(
        `[BymaxAuthModule] ${label}.${name} must be a function (received ${describeReceived(member)}).`
      )
    }
  }
}

/**
 * Checks the hooks and the email provider when they are registered as ready-made values.
 *
 * @param providers - The host's `extraProviders`.
 * @throws {Error} naming the provider and the member that is not usable.
 */
export function assertProviderShapes(providers: Provider[]): void {
  const hooks = readyMadeValue(providers, BYMAX_AUTH_HOOKS)
  if (hooks.found && hooks.value !== null && hooks.value !== undefined) {
    assertFunctionMembers('BYMAX_AUTH_HOOKS', hooks.value)
  }

  const email = readyMadeValue(providers, BYMAX_AUTH_EMAIL_PROVIDER)
  if (!email.found) return
  assertFunctionMembers('BYMAX_AUTH_EMAIL_PROVIDER', email.value)
  for (const name of REQUIRED_EMAIL_METHODS) {
    if (typeof Reflect.get(email.value, name) !== 'function') {
      throw new Error(
        `[BymaxAuthModule] BYMAX_AUTH_EMAIL_PROVIDER.${name} is required and must be a function.`
      )
    }
  }
}

/**
 * Checks what `registerAsync` is handed before it builds anything: the controller flags, and the
 * shape of the hooks and the email provider.
 *
 * @param controllers - The host's `controllers`, if any.
 * @param providers - The host's `extraProviders`.
 * @throws {Error} naming the option or provider member that is not usable.
 */
export function validateRegistrationShapes(controllers: unknown, providers: Provider[]): void {
  validateControllerFlags(controllers)
  assertProviderShapes(providers)
}
