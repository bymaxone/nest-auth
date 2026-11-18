/**
 * @fileoverview Boot-time check of the options that are a flag or one of a documented set of values.
 *
 * A flag is read as `if (options.x.enabled)` in some places and `=== false` in others, so a value that
 * is neither `true` nor `false` is decided by whichever reader sees it: `''` or `0` switches the
 * feature off at a guard while the boot check still reads it as enabled, and `'false'` is truthy.
 * An option that is a set of strings is compared with `===` where it is used, so a typo falls through
 * to whichever branch is the default there: `environment: 'prodution'` is read as not production.
 * Each is therefore refused unless it is exactly one of its documented values; unset (`undefined` or
 * `null`) was dropped before this runs and means the default.
 *
 * @layer Config
 */

import { describeReceived } from './describe-received'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/** The dotted path of every option that is exactly `true` or `false`. */
export const BOOLEAN_OPTIONS: readonly string[] = [
  'secureCookies',
  'enforceTenantBinding',
  'sessions.enabled',
  'emailVerification.required',
  'platform.enabled',
  'invitations.enabled',
  'rateLimit.enabled',
  'workspaces.enabled',
  'apiKeys.enabled'
]

/** The dotted path of every option that is `true`, `false` or a function. */
export const BOOLEAN_OR_FUNCTION_OPTIONS: readonly string[] = ['workspaces.allowCreate']

/** The controller flags a host passes to `registerAsync`, each `true` or `false`. */
export const CONTROLLER_FLAGS: readonly string[] = [
  'auth',
  'mfa',
  'passwordReset',
  'sessions',
  'platform',
  'oauth',
  'invitations',
  'emailChange',
  'workspaces',
  'workspaceInvitations'
]

/** Every option that is one of a documented set of strings, with the set. */
export const ENUM_OPTIONS: Readonly<Record<string, readonly string[]>> = {
  tokenDelivery: ['cookie', 'bearer', 'both'],
  environment: ['production', 'development', 'test'],
  'cookies.sameSite': ['lax', 'strict', 'none'],
  'passwordReset.method': ['token', 'otp']
}

/** The value at a dotted path, or `undefined` when a step is missing. */
function readPath(root: unknown, path: string): unknown {
  let node: unknown = root
  for (const step of path.split('.')) {
    if (typeof node !== 'object' || node === null) return undefined
    node = Reflect.get(node, step)
  }
  return node
}

/**
 * Refuses a flag that is not `true` or `false`.
 *
 * @param path - The option's path, for the message.
 * @param value - The configured value.
 * @throws {Error} when the value is present and is not a boolean.
 */
function assertBoolean(path: string, value: unknown): void {
  if (value === undefined || typeof value === 'boolean') return
  throw new Error(
    `[BymaxAuthModule] ${path} must be true or false (received ${describeReceived(value)}).`
  )
}

/**
 * Refuses a value that is not one of the documented strings. The refusal never prints a string: it
 * could be a secret passed to the wrong option.
 */
function assertOneOf(path: string, value: unknown, allowed: readonly string[]): void {
  if (value === undefined || (typeof value === 'string' && allowed.includes(value))) return
  throw new Error(
    `[BymaxAuthModule] ${path} must be one of ${allowed.map((entry) => `'${entry}'`).join(', ')} ` +
      `(received ${describeReceived(value)}).`
  )
}

/**
 * Checks the controller flags a host passes to `registerAsync`.
 *
 * @param flags - The host's `controllers`, if any. A `null` flag is unset, as everywhere else.
 * @throws {Error} naming the first flag that is not `true` or `false`.
 */
export function validateControllerFlags(flags: unknown): void {
  for (const name of CONTROLLER_FLAGS) {
    const flag = readPath(flags, name)
    if (flag !== null) assertBoolean(`controllers.${name}`, flag)
  }
}

/**
 * Checks every flag and every documented-set option.
 *
 * @param userOptions - The user-supplied options, with unset keys already dropped.
 * @throws {Error} naming the first option whose value is not one of its documented values.
 */
export function validateEnumAndBooleanOptions(userOptions: BymaxAuthModuleOptions): void {
  for (const path of BOOLEAN_OPTIONS) assertBoolean(path, readPath(userOptions, path))
  for (const path of BOOLEAN_OR_FUNCTION_OPTIONS) {
    const value = readPath(userOptions, path)
    if (typeof value !== 'function') assertBoolean(path, value)
  }
  for (const [path, allowed] of Object.entries(ENUM_OPTIONS)) {
    assertOneOf(path, readPath(userOptions, path), allowed)
  }
  validateControllerFlags(userOptions.controllers)
}
