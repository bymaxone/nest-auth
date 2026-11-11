/**
 * @fileoverview Tests for the access decision a route, a stream and a socket share.
 *
 * @layer Test
 */

import { assertWorkspaceAccess } from './workspace-access-decision'
import { ANY_WORKSPACE_MEMBER } from '../constants/workspace-roles'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { AuthException } from '../errors/auth-exception'
import { WorkspaceAccessRefusal } from '../errors/workspace-access-refusal'
import type { WorkspaceAccess } from '../services/workspace-access.service'

const HIERARCHY = { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] }
const REF = { tenantId: 't1', workspaceId: 'w1', userId: 'u1' }

/** The code an assertion refuses with, or `undefined` when it admits. */
function refusal(run: () => unknown): string | undefined {
  try {
    run()
  } catch (error) {
    return ((error as AuthException).getResponse() as { error: { code: string } }).error.code
  }
  return undefined
}

const member = (role: string): WorkspaceAccess => ({ kind: 'member', member: { ...REF, role } })
const pending = (role: string): WorkspaceAccess => ({
  kind: 'pending_deletion',
  member: { ...REF, role }
})

describe('assertWorkspaceAccess', () => {
  it('admits a member whose role is accepted, and answers the member', () => {
    expect(assertWorkspaceAccess(member('editor'), ['editor'], HIERARCHY, false)).toEqual({
      ...REF,
      role: 'editor'
    })
  })

  it('admits a role that inherits the accepted one', () => {
    expect(() => assertWorkspaceAccess(member('owner'), ['viewer'], HIERARCHY, false)).not.toThrow()
  })

  it('admits any member for ANY_WORKSPACE_MEMBER', () => {
    expect(() =>
      assertWorkspaceAccess(member('viewer'), [ANY_WORKSPACE_MEMBER], HIERARCHY, false)
    ).not.toThrow()
  })

  it('refuses a role below every accepted one', () => {
    expect(
      refusal(() => assertWorkspaceAccess(member('viewer'), ['editor'], HIERARCHY, false))
    ).toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
  })

  it('answers not found for a denied access, before it looks at any role', () => {
    expect(
      refusal(() => assertWorkspaceAccess({ kind: 'denied' }, ['editor'], HIERARCHY, true))
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND)
  })

  it('refuses the owner of a workspace pending deletion unless the surface admits it', () => {
    expect(
      refusal(() => assertWorkspaceAccess(pending('owner'), ['owner'], HIERARCHY, false))
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION)
    expect(() => assertWorkspaceAccess(pending('owner'), ['owner'], HIERARCHY, true)).not.toThrow()
  })

  it('judges the role of an admitted pending owner like any other', () => {
    expect(
      refusal(() => assertWorkspaceAccess(pending('viewer'), ['owner'], HIERARCHY, true))
    ).toBe(AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE)
  })

  it('judges the pending state before the role', () => {
    expect(
      refusal(() => assertWorkspaceAccess(pending('viewer'), ['owner'], HIERARCHY, false))
    ).toBe(AUTH_ERROR_CODES.WORKSPACE_PENDING_DELETION)
  })

  describe('the reason the host is told', () => {
    /** The refusal an assertion raises, for its code and reason. */
    function refusedWith(access: WorkspaceAccess, allowPending = false): WorkspaceAccessRefusal {
      try {
        assertWorkspaceAccess(access, ['owner'], HIERARCHY, allowPending)
      } catch (error) {
        if (error instanceof WorkspaceAccessRefusal) return error
      }
      throw new Error('the assertion did not refuse')
    }

    it.each([
      [
        'a stranger',
        { kind: 'denied' } as WorkspaceAccess,
        'auth.workspace_not_found',
        'not_member'
      ],
      [
        'a non-owner of a workspace pending deletion',
        { kind: 'denied', pendingDeletion: true } as WorkspaceAccess,
        'auth.workspace_not_found',
        'pending_deletion'
      ],
      [
        'the owner of a workspace pending deletion',
        pending('owner'),
        'auth.workspace_pending_deletion',
        'pending_deletion'
      ],
      [
        'a member below the role',
        member('viewer'),
        'auth.insufficient_workspace_role',
        'insufficient_role'
      ]
    ])('refuses %s with the code %s and the reason %s', (_name, access, code, reason) => {
      const refusalOf = refusedWith(access)

      expect(refusalOf.refusalCode).toBe(code)
      expect(refusalOf.reason).toBe(reason)
      expect(refusalOf.getResponse()).toEqual({
        error: { code, message: expect.any(String), details: null }
      })
    })
  })
})
