/**
 * @fileoverview Reads an option that holds `undefined` or `null` as unset, so that unset means the
 * default and never "no bound".
 *
 * A spread of the defaults and a user's group lets an own key holding `undefined` override the
 * default: `{ ...DEFAULT.sessions, ...{ defaultMaxSessions: undefined } }` has no session cap, and
 * the validators treat `undefined` as unset and accept it. `Number(process.env.X) || undefined`
 * produces exactly that value. Dropping the keys once, before anything reads the options, makes every
 * validator and every merge see the same thing.
 *
 * @layer Config
 */

import type { BymaxAuthModuleOptions } from '../interfaces/auth-module-options.interface'

/** Whether a value is a plain object, the shape an option group has. */
function isGroup(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype
  )
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

/** The `workspaces` sub-groups that carry numbers and a status, beside its own scalar options. */
const WORKSPACE_SUBGROUPS = ['accessDeniedEvents', 'invitations'] as const

/**
 * Returns the options with every unset key dropped: at the top level, inside each option group, and
 * inside the `workspaces` sub-groups that hold plain settings. The role hierarchies and other
 * host-defined maps are left as given, because a `null` there is a mistake to refuse, not an unset
 * option.
 *
 * @param options - The options as the host wrote them.
 * @returns A copy in which unset means absent.
 */
export function dropUnset(options: BymaxAuthModuleOptions): BymaxAuthModuleOptions {
  const copy = dropUnsetKeys(options)
  for (const [key, entry] of Object.entries(copy)) {
    if (!isGroup(entry) || key === 'roles') continue
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
