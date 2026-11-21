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

/** A hierarchy as a copy of what the host answered, children included; anything else is left for the checks to refuse. */
function copyHierarchy(held: unknown): unknown {
  if (typeof held !== 'object' || held === null || Array.isArray(held)) return held
  return Object.fromEntries(
    Object.entries(held).map(([role, children]) => [
      role,
      Array.isArray(children) ? [...children] : children
    ])
  )
}

/** Replaces the hierarchies named in a group by copies. The group is the fresh plain object `dropUnset` made. */
function pinIn<G>(group: G, keys: readonly string[]): G {
  // Stryker disable next-line ConditionalExpression: a null group never reaches the pin, `dropUnset` has dropped it
  if (typeof group !== 'object' || group === null) return group
  const plain = group as Record<string, unknown>
  for (const key of keys) if (plain[key] !== undefined) plain[key] = copyHierarchy(plain[key])
  return group
}

/**
 * The role hierarchies (of the account, of the platform and of the workspaces) as copies, read from the host once, so a
 * later read cannot grant a role that was never validated.
 */
function pinHierarchies(options: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const { roles, workspaces } = options
  const { roles: workspaceRoles, ...workspaceRest } = (
    typeof workspaces === 'object' && workspaces !== null ? workspaces : {}
  ) as { roles?: unknown }
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
