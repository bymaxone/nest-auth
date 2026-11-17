/**
 * @fileoverview Reads an option that holds `undefined` or `null` as unset, so that unset means the
 * default and never "no bound".
 *
 * A spread of the defaults and a user's group lets an own key holding `undefined` override the
 * default, and the validators treat `undefined` as unset and accept it, so a value such as
 * `Number(process.env.X) || undefined` would leave a cap with no bound. The keys are dropped once,
 * before anything reads the options, so every validator and every merge sees the same thing.
 *
 * @layer Config
 */

import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/**
 * Whether a value is a plain data bag: its prototype is absent, or is itself a root prototype. That
 * covers `Object.create(null)` and objects made in another realm, which a configuration parser can
 * return, and still excludes a class instance, whose prototype chain continues past its class.
 */
function isGroup(value: unknown): value is Record<string, unknown> {
  if (Object(value) !== value) return false
  const prototype: unknown = Object.getPrototypeOf(value)
  return prototype === null || Object.getPrototypeOf(prototype) === null
}

/**
 * Copies `value` without the keys that hold `undefined` or `null`, one level deep.
 *
 * @param value - An option group.
 * @returns The group, with unset keys absent.
 */
export function dropUnsetKeys<T extends object>(value: T): T {
  const copy = { ...value }
  for (const [key, entry] of Object.entries(copy)) {
    if (entry === undefined || entry === null) Reflect.deleteProperty(copy, key)
  }
  return copy
}

/**
 * The option groups whose keys are fixed settings. Only these are cleaned: a group that is a
 * host-defined map (`roles`, `oauth`) is left as given, because a `null` there is a mistake to
 * refuse, and a map this list does not name is untouched by construction.
 */
const FIXED_GROUPS = new Set([
  'jwt',
  'password',
  'cookies',
  'sessions',
  'bruteForce',
  'passwordReset',
  'emailVerification',
  'platform',
  'invitations',
  'emailChange',
  'controllers',
  'rateLimit',
  'mfa',
  'apiKeys',
  'workspaces'
])

/** The `workspaces` sub-groups that carry numbers and a status, beside its own scalar options. */
const WORKSPACE_SUBGROUPS = ['accessDeniedEvents', 'invitations'] as const

/**
 * Returns the options with every unset key dropped: at the top level, inside each option group, and
 * inside the `workspaces` sub-groups that hold plain settings. Host-defined maps are left as given.
 *
 * @param options - The options as the host wrote them.
 * @returns A copy in which unset means absent.
 */
export function dropUnset(options: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const copy = dropUnsetKeys(options)
  for (const [key, entry] of Object.entries(copy)) {
    if (!FIXED_GROUPS.has(key) || !isGroup(entry)) continue
    const group = dropUnsetKeys(entry)
    if (key === 'workspaces') {
      for (const name of WORKSPACE_SUBGROUPS) {
        const sub = group[name]
        if (isGroup(sub)) group[name] = dropUnsetKeys(sub)
      }
    }
    Reflect.set(copy, key, group)
  }
  return copy
}
