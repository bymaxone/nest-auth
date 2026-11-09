/**
 * @fileoverview The member whose role authorized a workspace or membership write, in the two forms
 * the services and the repositories use.
 *
 * @layer Interface
 */

/**
 * The member whose role authorized a write, and the role the library read for them.
 *
 * The library decides what an actor may do from a role it read BEFORE the write. Handing it back
 * lets the repository check, in the write's own transaction, that the actor still holds it.
 */
export interface ActingMember {
  /** The actor, a member of the same workspace and tenant as the write. */
  userId: string
  /** The role the library read for the actor and judged the action against. */
  expectedRole: string
}

/** Who is making a change: their id, and the role they hold in the workspace. */
export interface WorkspaceActor {
  /** The actor. */
  userId: string
  /** The role the actor holds in the workspace, as the guard resolved it. */
  role: string
}
