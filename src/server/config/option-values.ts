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
 * @returns The options as a plain object in which unset means absent, and in which the role hierarchies are copies.
 * @throws {Error} naming the first text option, list or group that has the wrong type.
 */
export function readOptions(given: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const options = dropUnset(given)
  validateTextOptions(options)
  return pinHierarchies(options)
}

/** A hierarchy as a plain copy of what the host answered, whatever it is, children included; the checks judge the copy. */
function copyHierarchy(held: unknown): unknown {
  return Object.fromEntries(
    Object.entries(held as object).map(([role, children]) => [
      role,
      Array.isArray(children) ? [...children] : children
    ])
  )
}

/**
 * A copy of a group with the hierarchies named in it copied too. The group is copied, never written to: it is usually the
 * plain object `dropUnset` made, but a function that carries the hierarchy is the host's own and is accepted as a group.
 */
function pinIn<G>(group: G, keys: readonly string[]): G {
  const copy = { ...group } as Record<string, unknown>
  for (const key of keys) if (copy[key] != null) copy[key] = copyHierarchy(copy[key])
  return copy as G
}

/**
 * The role hierarchies (of the account, of the platform and of the workspaces) as copies, read from the host once, so a
 * later read cannot grant a role that was never validated.
 */
function pinHierarchies(options: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const { roles, workspaces } = options
  const { roles: workspaceRoles, ...workspaceRest } = (workspaces ?? {}) as { roles?: unknown }
  return {
    ...options,
    roles: pinIn(roles, ['hierarchy', 'platformHierarchy']),
    ...(workspaceRoles === undefined
      ? {}
      : {
          workspaces: { ...workspaceRest, roles: pinIn(workspaceRoles, ['hierarchy']) }
        })
  } as BymaxAuthModuleOptions
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
