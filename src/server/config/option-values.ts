/**
 * @fileoverview The boot checks of option values that are not a plain range: the type of a text option,
 * the numeric bounds, and the flags and documented-set options.
 *
 * @layer Config
 */

import { validateEnumAndBooleanOptions } from './enum-boolean-options'
import { validateNumericOptions } from './numeric-options'
import { validateTextOptions } from './text-options'
import { dropUnset } from './unset-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/**
 * Reads the options with unset keys dropped and refuses an option of the wrong type, before any
 * other check reads one.
 *
 * @param given - The options as the host wrote them.
 * @returns The options as a plain object in which unset means absent, and in which the lists and hierarchies the host keeps are copies.
 * @throws {Error} naming the first text option, list or group that has the wrong type.
 */
export function readOptions(given: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const options = dropUnset(given)
  validateTextOptions(options)
  return pinCopied(options)
}

/** A hierarchy as a plain copy of the entries of what the host answered; a value that is no object is left for the checks. */
function copyHierarchy(held: unknown): unknown {
  if (Object(held) !== held) return held
  return Object.fromEntries(
    Object.entries(held as object).map(([role, children]) => [
      role,
      Array.isArray(children) ? [...children] : children
    ])
  )
}

/** A list as a copy; a value that is no list is left for the checks. */
function copyList(held: unknown): unknown {
  return Array.isArray(held) ? [...held] : held
}

/** What the host keeps by reference and the library checks once: the group, the keys in it and how each is copied. */
const COPIED: readonly {
  readonly path: readonly string[]
  readonly keys: readonly string[]
  readonly copy: (held: unknown) => unknown
}[] = [
  { path: ['roles'], keys: ['hierarchy', 'platformHierarchy'], copy: copyHierarchy },
  { path: ['workspaces', 'roles'], keys: ['hierarchy'], copy: copyHierarchy },
  {
    path: ['workspaces', 'permissions'],
    keys: ['manageWorkspace', 'deleteWorkspace', 'manageMembers', 'viewMembers'],
    copy: copyList
  },
  { path: ['jwt'], keys: ['previousSecrets'], copy: copyList },
  { path: ['mfa'], keys: ['previousEncryptionKeys'], copy: copyList },
  { path: ['apiKeys'], keys: ['scopes'], copy: copyList }
]

/**
 * Replaces what the host keeps by reference (the role hierarchies, the permissions of the workspaces, the retired secrets
 * and keys, the scopes of the API keys) by copies, read from the host once, so a later read or change cannot grant what
 * was never validated. The options and each group on the paths are the fresh plain objects `dropUnset` made.
 */
function pinCopied(options: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  for (const { path, keys, copy } of COPIED) {
    let group: unknown = options
    for (const step of path)
      group = Object(group) === group ? (group as Record<string, unknown>)[step] : undefined
    if (Object(group) !== group) continue
    const plain = group as Record<string, unknown>
    for (const key of keys) if (plain[key] !== undefined) plain[key] = copy(plain[key])
  }
  return options
}

/**
 * Runs the value checks of the numeric options, the flags and the documented-set options.
 *
 * @param userOptions - The user-supplied options, with unset keys already dropped.
 * @throws {Error} naming the first option whose value is not usable.
 */
export function validateOptionValues(userOptions: BymaxAuthModuleOptions): void {
  validateNumericOptions(userOptions)
  validateEnumAndBooleanOptions(userOptions)
}
