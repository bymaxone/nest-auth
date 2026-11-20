/**
 * @fileoverview The boot checks of option values that are not a plain range: the numeric bounds, and
 * the flags and documented-set options.
 *
 * @layer Config
 */

import { validateEnumAndBooleanOptions } from './enum-boolean-options'
import { validateNumericOptions } from './numeric-options'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

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
