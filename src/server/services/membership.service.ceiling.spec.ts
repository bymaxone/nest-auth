/**
 * @fileoverview Tests for the role ceiling the membership service applies to a grant, and for the
 * receiver check of an ownership hand-over.
 *
 * @layer Test
 */

import {
  EDITOR,
  OWNER,
  build,
  code,
  detailsOf,
  member
} from './__tests__/membership-service-harness'
import { CONTEXT, NOW, WORKSPACE_REF } from './__tests__/workspace-service-harness'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

describe('MembershipService', () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(NOW)
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  describe('assertMayGrant', () => {
    it('lets the owner grant every role, its own included', () => {
      const { service } = build()

      for (const role of ['owner', 'editor', 'viewer']) {
        expect(() => service.assertMayGrant('owner', role)).not.toThrow()
      }
    })

    it('lets another role grant only a role strictly below its own', async () => {
      const { service } = build()

      expect(() => service.assertMayGrant('editor', 'viewer')).not.toThrow()
      const refused: Array<[string, string]> = [
        ['editor', 'editor'],
        ['editor', 'owner'],
        ['viewer', 'editor']
      ]
      for (const [actor, role] of refused) {
        expect(await code(Promise.resolve().then(() => service.assertMayGrant(actor, role)))).toBe(
          AUTH_ERROR_CODES.INSUFFICIENT_WORKSPACE_ROLE
        )
      }
    })

    it('refuses a role outside the hierarchy with a validation error naming it', async () => {
      const { service } = build()
      const refuse = (role: string): Promise<void> =>
        Promise.resolve().then(() => service.assertMayGrant('owner', role))

      expect(await code(refuse('ghost'))).toBe(AUTH_ERROR_CODES.VALIDATION)
      expect(await detailsOf(refuse('ghost'))).toEqual([
        { field: 'role', message: 'role must be one of the workspace roles' }
      ])
      expect(await code(refuse('constructor'))).toBe(AUTH_ERROR_CODES.VALIDATION)
    })
  })

  describe('mayActOn', () => {
    it('answers for the owner on every role and for others only on a role strictly below', () => {
      const { service } = build()

      expect(service.mayActOn('owner', 'owner')).toBe(true)
      expect(service.mayActOn('editor', 'viewer')).toBe(true)
      expect(service.mayActOn('editor', 'editor')).toBe(false)
      expect(service.mayActOn('editor', 'owner')).toBe(false)
    })
  })

  describe('assertTransferTarget', () => {
    it.each([
      ['absent', null],
      ['suspended', member('u2', 'viewer', 'suspended')]
    ])('refuses a receiver who is %s, naming userId', async (_name, found) => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(found)

      expect(await code(service.assertTransferTarget(WORKSPACE_REF, 'u2'))).toBe(
        AUTH_ERROR_CODES.VALIDATION
      )
      expect(memberships['find']).toHaveBeenCalledWith({ ...WORKSPACE_REF, userId: 'u2' })
    })

    it('accepts an active receiver', async () => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer'))

      await expect(service.assertTransferTarget(WORKSPACE_REF, 'u2')).resolves.toBeUndefined()
    })

    it('is run by the hand-over itself, which then writes nothing for a suspended receiver', async () => {
      const { service, memberships } = build()
      memberships['find']?.mockResolvedValue(member('u2', 'viewer', 'suspended'))

      expect(await code(service.transferOwnership(WORKSPACE_REF, OWNER, 'u2', null, CONTEXT))).toBe(
        AUTH_ERROR_CODES.VALIDATION
      )

      expect(memberships['transferOwnership']).not.toHaveBeenCalled()
    })
  })
})
