/**
 * @fileoverview The workspace types the browser entry points ship, held to the views the server
 * builds.
 *
 * The client types are written by hand in `src/shared`, which may not import the server. Nothing
 * at runtime would notice a field added to a view on one side only: the client would simply type
 * a key that is never there, or miss one that is. These cases compare each pair type for type, so
 * the build fails at the line that drifted.
 *
 * @layer Conformance
 */

import type {
  AcceptedWorkspaceInvitation,
  MembershipStatusClient,
  WorkspaceAccessClient,
  WorkspaceClient,
  WorkspaceInvitationClient,
  WorkspaceInvitationPage,
  WorkspaceInvitationPreview as PreviewClient,
  WorkspaceListResult,
  WorkspaceMemberClient,
  WorkspaceMemberPage,
  WorkspaceStatusClient
} from '../shared'
import type {
  WorkspaceInvitationPreview,
  WorkspaceInvitationView
} from './interfaces/workspace-invitation.interface'
import type { AuthMembership } from './interfaces/membership-repository.interface'
import type { AuthWorkspace } from './interfaces/workspace-repository.interface'
import type { AcceptedInvitation } from './services/workspace-invitation-accept.service'
import type { InvitationPage } from './utils/workspace-invitation-page'
import type {
  MemberView,
  MembersResponse,
  MyWorkspacesResponse,
  WorkspaceAccessResponse,
  WorkspaceView
} from './utils/workspace-views'

/** `true` only when the two types are identical, not merely assignable to each other. */
type Same<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false

/** Fails to compile unless every pair is identical. */
function identical<_Pairs extends readonly true[]>(): void {}

describe('workspace types shipped to the client', () => {
  // Verifies each client type is the server view it mirrors, key for key and type for type. The
  // check is the compile: a pair that drifted makes this file fail to build.
  it('mirrors every view the server answers with', () => {
    identical<
      [
        Same<WorkspaceClient, WorkspaceView>,
        Same<WorkspaceAccessClient, WorkspaceAccessResponse>,
        Same<WorkspaceListResult, MyWorkspacesResponse>,
        Same<WorkspaceMemberClient, MemberView>,
        Same<WorkspaceMemberPage, MembersResponse>,
        Same<WorkspaceInvitationClient, WorkspaceInvitationView>,
        Same<WorkspaceInvitationPage, InvitationPage>,
        Same<PreviewClient, WorkspaceInvitationPreview>,
        Same<AcceptedWorkspaceInvitation, AcceptedInvitation>,
        Same<WorkspaceStatusClient, AuthWorkspace['status']>,
        Same<MembershipStatusClient, AuthMembership['status']>
      ]
    >()

    expect(true).toBe(true)
  })

  // Verifies the comparison itself can fail: a type with one key more is not the same.
  it('tells a drifted pair from an identical one', () => {
    type Drifted = WorkspaceClient & { extra: string }

    const answer: Same<Drifted, WorkspaceView> = false

    expect(answer).toBe(false)
  })
})
