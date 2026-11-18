/**
 * @fileoverview An email provider double that carries every method the library calls without a guard,
 * so a test about one feature does not trip the shape check `registerAsync` makes of the provider.
 *
 * @layer Test
 */

import { REQUIRED_EMAIL_METHODS } from '../config/provider-shape'

/**
 * Builds an email provider with every required method, as `jest.fn()`s.
 *
 * @param extra - Further members, or replacements, for the case under test.
 * @returns The provider.
 */
export function completeEmailProvider(
  extra: Record<string, unknown> = {}
): Record<string, unknown> {
  const required = Object.fromEntries(REQUIRED_EMAIL_METHODS.map((name) => [name, jest.fn()]))
  return { ...required, ...extra }
}
