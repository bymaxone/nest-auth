/**
 * @fileoverview The boot checks of the platform: when it is enabled it needs a role hierarchy, and that hierarchy is
 * judged as the other hierarchies are.
 *
 * @layer Config
 */

import { assertArray, assertKnownChildren, assertObject } from './shape-checks'
import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/**
 * Requires the hierarchy of the platform when the platform is enabled, and requires it to be an object that names at least
 * one role, whose children are lists of roles it declares.
 *
 * @param platform - The platform group.
 * @param roles - The roles group, which holds `platformHierarchy`.
 * @throws {Error} Naming the option and what is wrong with it.
 */
export function validatePlatformAdmin(
  platform: BymaxAuthModuleOptions['platform'],
  roles: BymaxAuthModuleOptions['roles']
): void {
  if (!platform?.enabled) return
  const hierarchy = roles.platformHierarchy
  if (!hierarchy) {
    throw new Error(
      `[BymaxAuthModule] roles.platformHierarchy is required when platform.enabled is true. ` +
        `Define the platform role hierarchy (e.g. { SUPER_ADMIN: ['SUPPORT'], SUPPORT: [] }).`
    )
  }
  assertObject('roles.platformHierarchy', hierarchy)
  const names = new Set(Object.keys(hierarchy))
  if (names.size === 0) {
    throw new Error(
      `[BymaxAuthModule] roles.platformHierarchy must not be an empty object. ` +
        `Define at least one role (e.g. { SUPER_ADMIN: [] }).`
    )
  }
  for (const [role, children] of Object.entries(hierarchy)) {
    assertArray(`roles.platformHierarchy['${role}']`, children)
    assertKnownChildren(`roles.platformHierarchy['${role}']`, children, names)
  }
}
