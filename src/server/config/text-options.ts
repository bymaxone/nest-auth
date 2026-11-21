/**
 * @fileoverview Boot-time check of the options that are text, a list of text, or a group of settings.
 *
 * Each of these is read where it is used with a string method or a property access, so a value of
 * another type surfaces as a raw `TypeError` at boot (`value.trim is not a function`) or, worse, is
 * ignored: a group that is a string reads as an empty one and a list that is a string reads as no
 * list at all. Every one is refused by option name and type received, never by content, because a
 * boot error is logged and the value may be a credential pasted into the wrong option.
 *
 * @layer Config
 */

import { describeReceived } from './describe-received'
import { assertObject } from './shape-checks'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/** The dotted path of every option that is text. */
export const TEXT_OPTIONS: readonly string[] = [
  'jwt.issuer',
  'jwt.audience',
  'cookies.accessTokenName',
  'cookies.refreshTokenName',
  'cookies.sessionSignalName',
  'cookies.refreshCookiePath',
  'cookies.mfaTempCookiePath',
  'mfa.issuer',
  'apiKeys.pepper',
  'redisNamespace',
  'routePrefix'
]

/** The dotted path of every option that is a list of text. */
export const TEXT_LIST_OPTIONS: readonly string[] = [
  'blockedStatuses',
  'cookies.trustedOrigins',
  'password.blocklist'
]

/** The groups a host passes as an object, each optional. */
export const OBJECT_GROUPS: readonly string[] = [
  'password',
  'cookies',
  'sessions',
  'bruteForce',
  'passwordReset',
  'emailVerification',
  'platform',
  'invitations',
  'emailChange',
  'oauth',
  'roles',
  'workspaces',
  'workspaces.roles'
]

/** The value at a dotted path, or `undefined` when a step is missing or is not an object. */
function readPath(root: unknown, path: string): unknown {
  let node: unknown = root
  for (const step of path.split('.')) {
    if (Object(node) !== node) return undefined
    node = Reflect.get(node as object, step)
  }
  return node
}

/**
 * Refuses an option that is present and is not text.
 *
 * @param path - The option's dotted path.
 * @param value - The configured value.
 * @throws {Error} Naming the option and the type received.
 */
function assertText(path: string, value: unknown): void {
  if (value === undefined || typeof value === 'string') return
  throw new Error(
    `[BymaxAuthModule] ${path} must be a string (received ${describeReceived(value)}).`
  )
}

/**
 * Refuses an option that is present and is not a list of text.
 *
 * @param path - The option's dotted path.
 * @param value - The configured value.
 * @throws {Error} Naming the option, and the position of the first entry that is not text.
 */
function assertTextList(path: string, value: unknown): void {
  if (value === undefined) return
  if (!Array.isArray(value)) {
    throw new Error(
      `[BymaxAuthModule] ${path} must be an array of strings (received ${describeReceived(value)}).`
    )
  }
  const index = value.findIndex((entry: unknown) => typeof entry !== 'string')
  if (index !== -1) {
    throw new Error(
      `[BymaxAuthModule] ${path} must contain only strings (entry ${index} is ` +
        `${describeReceived(value[index])}).`
    )
  }
}

/**
 * Checks every text option, list of text and group of settings.
 *
 * @param userOptions - The user-supplied options, with unset keys dropped.
 * @throws {Error} naming the first option whose value has the wrong type.
 */
export function validateTextOptions(userOptions: BymaxAuthModuleOptions): void {
  for (const path of OBJECT_GROUPS) {
    const group = readPath(userOptions, path)
    if (group !== undefined) assertObject(path, group)
  }
  for (const path of TEXT_OPTIONS) assertText(path, readPath(userOptions, path))
  for (const path of TEXT_LIST_OPTIONS) assertTextList(path, readPath(userOptions, path))
}
