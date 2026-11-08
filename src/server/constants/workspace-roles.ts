/**
 * @fileoverview The marker a workspace permission list uses for "every active member".
 *
 * @layer Constants
 */

/**
 * Stands in a role list for "any active member of the workspace, whatever the role".
 *
 * A unique symbol rather than a string such as `'*'`, so it can never equal a role name a host
 * defines, and so a role list that contains it is visibly different in the types.
 */
export const ANY_WORKSPACE_MEMBER: unique symbol = Symbol('ANY_WORKSPACE_MEMBER')
