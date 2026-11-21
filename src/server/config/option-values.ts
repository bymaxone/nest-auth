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
 * @returns The options as a plain object in which unset means absent, and in which the role hierarchy is a copy.
 * @throws {Error} naming the first text option, list or group that has the wrong type.
 */
export function readOptions(given: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const options = dropUnset(given)
  validateTextOptions(options)
  return pinHierarchy(options)
}

/** The role hierarchy as a copy, read from the host once, so a later read cannot grant a role that was never validated. */
function pinHierarchy(options: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const { hierarchy, ...rest } = options.roles ?? {}
  if (typeof hierarchy !== 'object' || hierarchy === null || Array.isArray(hierarchy))
    return options
  const pinned = Object.fromEntries(
    Object.entries(hierarchy).map(([role, children]) => [
      role,
      Array.isArray(children) ? [...children] : children
    ])
  )
  return { ...options, roles: { ...rest, hierarchy: pinned } }
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
