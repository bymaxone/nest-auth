/**
 * @fileoverview The role ceiling of the membership service is decided after the lookup of the member that it waits for, so it checks
 * the runtime right before it decides: a built-in replaced during the lookup must refuse the action before the write.
 *
 * @layer Test
 */

import { EDITOR, OWNER, build, code, member } from './__tests__/membership-service-harness'
import { CONTEXT, WORKSPACE_REF } from './__tests__/workspace-service-harness'

// The test's own copies: the window below replaces a built-in, so nothing inside it may call a live one.
const define = Object.defineProperty
const getOwn = Object.getOwnPropertyDescriptor

/** A lookup that replaces `Array.prototype.includes` while it is awaited and then answers the owner as the member. */
function lookupReplacingIncludes(
  restore: { current: () => void },
  role: string
): () => Promise<unknown> {
  return async () => {
    await Promise.resolve()
    const held = getOwn(Array.prototype, 'includes') as PropertyDescriptor
    define(Array.prototype, 'includes', { ...held, value: () => true })
    restore.current = (): void => void define(Array.prototype, 'includes', held)
    return member('owner-2', role)
  }
}

describe('the role ceiling of the membership service while a built-in is replaced', () => {
  // Scenario: an editor removes a member while the lookup replaces `Array.prototype.includes` with a function that answers true and
  // then returns an OWNER. Expected: the library's refusal and no write. Why: with `includes` replaced an editor outranks the owner,
  // and the removal would be committed before any later check.
  it('refuses a removal of an owner by an editor, and writes nothing', async () => {
    const { service, memberships } = build()
    const restore = { current: (): void => undefined }
    memberships['find']?.mockImplementation(lookupReplacingIncludes(restore, 'owner'))
    let outcome: string | undefined
    try {
      outcome = await code(service.remove(WORKSPACE_REF, 'owner-2', EDITOR, CONTEXT))
    } finally {
      restore.current()
    }

    expect(outcome).toBe('auth.internal')
    expect(memberships['remove']).not.toHaveBeenCalled()
  })

  // Scenario: the same lookup for a change of role. Expected: the library's refusal and no write.
  it('refuses a demotion of an owner by an editor, and writes nothing', async () => {
    const { service, memberships } = build()
    const restore = { current: (): void => undefined }
    memberships['find']?.mockImplementation(lookupReplacingIncludes(restore, 'owner'))
    let outcome: string | undefined
    try {
      outcome = await code(service.changeRole(WORKSPACE_REF, 'owner-2', 'viewer', EDITOR, CONTEXT))
    } finally {
      restore.current()
    }

    expect(outcome).toBe('auth.internal')
    expect(memberships['changeRole']).not.toHaveBeenCalled()
  })

  // Scenario: the same removal with nothing replaced. Expected: refused as a role below the owner's, so the rows above are the
  // refusal of the runtime and not of the role.
  it('still refuses the removal of an owner by an editor as a role refusal with nothing replaced', async () => {
    const { service, memberships } = build()
    memberships['find']?.mockResolvedValue(member('owner-2', 'owner'))

    await expect(code(service.remove(WORKSPACE_REF, 'owner-2', EDITOR, CONTEXT))).resolves.toBe(
      'auth.insufficient_workspace_role'
    )
    expect(OWNER.role).toBe('owner')
  })
})
