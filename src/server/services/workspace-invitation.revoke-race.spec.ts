/**
 * @fileoverview Tests for a revoke of a workspace invitation that races another writer of the same
 * address: a replacement published between the read of the revoke and its removal.
 *
 * @layer Test
 */

import {
  COOLDOWN_MS,
  EDITOR,
  NOW,
  OWNER,
  build,
  code
} from './__tests__/workspace-invitation-harness'
import type { Harness } from './__tests__/workspace-invitation-harness'
import { CONTEXT, WORKSPACE_REF } from './__tests__/workspace-service-harness'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import type { WorkspaceRef } from '../interfaces/workspace-repository.interface'

const EMAIL = 'a@example.com'

/**
 * Runs `write` between the read of a revoke and its removal, for the first `times` removals.
 *
 * @param h - The harness.
 * @param times - How many removals are preceded by the write.
 * @param write - What the other writer does.
 */
function raceTheRemoval(h: Harness, times: number, write: () => Promise<void>): jest.SpyInstance {
  const remove = h.store.remove.bind(h.store)
  let raced = 0
  return jest
    .spyOn(h.store, 'remove')
    .mockImplementation(async (ref: WorkspaceRef, email: string, key: string) => {
      if (raced < times) {
        raced += 1
        await write()
      }
      return remove(ref, email, key)
    })
}

/** Invites the address again once the cooldown has passed, which replaces its live invitation. */
async function reinvite(h: Harness, role: string): Promise<void> {
  jest.mocked(Date.now).mockReturnValue(Date.now() + COOLDOWN_MS)
  await h.service.invite(WORKSPACE_REF, OWNER, EMAIL, role, CONTEXT)
}

/** The roles of the `invitation.revoked` events reported so far. */
function revokedRoles(h: Harness): unknown[] {
  return h.events.emit.mock.calls
    .map(([event]) => event as { type: string; role: string })
    .filter((event) => event.type === 'invitation.revoked')
    .map((event) => event.role)
}

describe('WorkspaceInvitationService revoke against a concurrent writer', () => {
  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  // Scenario: a re-invite lands between the read and the removal. Expected: the replacement is read
  // and withdrawn too, and the one event names the role that was removed. Why: reporting the revoke
  // after removing only the retired record leaves the new token acceptable.
  it('withdraws the replacement that landed between its read and its removal', async () => {
    const h = build()
    await h.service.invite(WORKSPACE_REF, OWNER, EMAIL, 'viewer', CONTEXT)
    raceTheRemoval(h, 1, () => reinvite(h, 'editor'))

    await h.service.revoke(WORKSPACE_REF, OWNER, EMAIL, CONTEXT)

    expect(await h.store.readByEmail(WORKSPACE_REF, EMAIL)).toBeNull()
    expect(await h.store.pending(WORKSPACE_REF)).toEqual([])
    expect(revokedRoles(h)).toEqual(['editor'])
  })

  // Scenario: the replacement grants a role the actor may not act on. Expected: it stays, and no
  // revoke is reported. Why: the ceiling applies to what is there, not to what was read first.
  it('leaves a replacement above the actor and reports nothing', async () => {
    const h = build()
    await h.service.invite(WORKSPACE_REF, OWNER, EMAIL, 'viewer', CONTEXT)
    raceTheRemoval(h, 1, () => reinvite(h, 'owner'))

    await h.service.revoke(WORKSPACE_REF, EDITOR, EMAIL, CONTEXT)

    expect((await h.store.readByEmail(WORKSPACE_REF, EMAIL))?.record?.role).toBe('owner')
    expect(revokedRoles(h)).toEqual([])
  })

  // Scenario: the address is replaced before each of the first three removals. Expected: `auth.too_many_requests` after
  // three attempts and no revoke reported. Why: nothing the caller asked for happened.
  it('refuses after three replacements, with no fourth attempt', async () => {
    const h = build()
    await h.service.invite(WORKSPACE_REF, OWNER, EMAIL, 'viewer', CONTEXT)
    const remove = raceTheRemoval(h, 3, () => reinvite(h, 'viewer'))

    expect(await code(h.service.revoke(WORKSPACE_REF, OWNER, EMAIL, CONTEXT))).toBe(
      AUTH_ERROR_CODES.TOO_MANY_REQUESTS
    )

    expect(remove).toHaveBeenCalledTimes(3)
    expect(revokedRoles(h)).toEqual([])
  })

  // Scenario: the address is replaced before each of the first two removals. Expected: the third
  // attempt removes and reports. Why: the bound is three, not two.
  it('removes on the third attempt after two replacements', async () => {
    const h = build()
    await h.service.invite(WORKSPACE_REF, OWNER, EMAIL, 'viewer', CONTEXT)
    const remove = raceTheRemoval(h, 2, () => reinvite(h, 'viewer'))

    await h.service.revoke(WORKSPACE_REF, OWNER, EMAIL, CONTEXT)

    expect(remove).toHaveBeenCalledTimes(3)
    expect(revokedRoles(h)).toEqual(['viewer'])
  })

  // Scenario: another revoke removes the invitation first. Expected: success with no second event.
  // Why: the end state asked for holds, and this call removed nothing.
  it('succeeds without an event when someone else removed the invitation first', async () => {
    const h = build()
    await h.service.invite(WORKSPACE_REF, OWNER, EMAIL, 'viewer', CONTEXT)
    const remove = h.store.remove.bind(h.store)
    raceTheRemoval(h, 1, async () => {
      const indexed = await h.store.readByEmail(WORKSPACE_REF, EMAIL)
      await remove(WORKSPACE_REF, EMAIL, indexed?.key ?? '')
    })

    await h.service.revoke(WORKSPACE_REF, OWNER, EMAIL, CONTEXT)

    expect(revokedRoles(h)).toEqual([])
  })
})

describe('WorkspaceInvitationService revokeAsPlatform against a concurrent writer', () => {
  const PLATFORM = { tenantId: 't1', email: EMAIL, workspaceName: 'Acme', inviterName: 'Platform' }

  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(NOW)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  /** Invites the platform's bootstrap owner and answers the workspace it was invited to. */
  async function bootstrapRef(h: Harness): Promise<WorkspaceRef> {
    const { workspaceId } = await h.service.inviteAsPlatform(PLATFORM, CONTEXT)
    return { tenantId: PLATFORM.tenantId, workspaceId }
  }

  /** Publishes `record` of the address under a new key, as another writer of the address does. */
  async function replace(
    h: Harness,
    ref: WorkspaceRef,
    kind: 'bootstrap' | 'member'
  ): Promise<void> {
    const indexed = await h.store.readByEmail(ref, EMAIL)
    if (indexed?.record == null) throw new Error('nothing to replace')
    const record =
      kind === 'bootstrap'
        ? indexed.record
        : {
            kind,
            email: EMAIL,
            role: 'viewer',
            ...ref,
            inviterUserId: 'owner-1',
            createdAt: indexed.record.createdAt,
            resendCount: 0
          }
    const published = await h.store.publish(
      ref,
      EMAIL,
      `${indexed.key}-next`,
      record,
      600,
      0,
      indexed.key
    )
    if (published !== 'published') throw new Error(`not published: ${published}`)
  }

  // Scenario: the bootstrap invitation is replaced between the read and the removal. Expected: the
  // replacement is withdrawn and reported once. Why: the same rule as a member revoke.
  it('withdraws the bootstrap replacement', async () => {
    const h = build()
    const ref = await bootstrapRef(h)
    raceTheRemoval(h, 1, () => replace(h, ref, 'bootstrap'))

    await h.service.revokeAsPlatform(ref, EMAIL, CONTEXT)

    expect(await h.store.readByEmail(ref, EMAIL)).toBeNull()
    expect(revokedRoles(h)).toEqual(['owner'])
  })

  // Scenario: a member invitation replaces the bootstrap one. Expected: it stays, and nothing is
  // reported. Why: the platform withdraws bootstrap invitations only.
  it('leaves a member invitation that replaced the bootstrap one', async () => {
    const h = build()
    const ref = await bootstrapRef(h)
    raceTheRemoval(h, 1, () => replace(h, ref, 'member'))

    await h.service.revokeAsPlatform(ref, EMAIL, CONTEXT)

    expect((await h.store.readByEmail(ref, EMAIL))?.record?.kind).toBe('member')
    expect(revokedRoles(h)).toEqual([])
  })
})
