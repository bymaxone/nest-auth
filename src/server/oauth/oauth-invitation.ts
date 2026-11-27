/**
 * The invitation an OAuth flow carries, from the moment the provider has answered until the
 * account it signs in is known.
 */

import type { StoredOAuthState } from './oauth-state'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { HookContext } from '../interfaces/auth-hooks.interface'
import type { OAuthProfile } from '../interfaces/oauth-provider.interface'
import type { AuthUser } from '../interfaces/user-repository.interface'
import type {
  LoadedInvitation,
  WorkspaceInvitationAcceptService
} from '../services/workspace-invitation-accept.service'
import { checked, pinned } from '../utils/settle'

/** A vetted invitation, waiting for the account its flow signs in. */
export interface PendingInvitation {
  /** Told of an account the flow is about to create, for the host to judge; refuses by throwing. */
  judgeNewAccount(account: { email: string; name: string }, context: HookContext): Promise<void>
  /** Writes the membership for `user` and spends the token; `created` is whether the flow made the account. */
  complete(user: AuthUser, created: boolean, context: HookContext): Promise<void>
}

/**
 * Vets the invitation a flow was started with against the provider's profile.
 *
 * @param accepts - The accept service, or `null` when workspaces are not enabled.
 * @param record - The consumed state record.
 * @param profile - The provider's profile.
 * @returns What completes the invitation once the account is known, or `null` for a flow that
 *   carries none.
 * @throws `AuthException(INVALID_INVITATION_TOKEN)` when workspaces are not enabled, and the
 *   refusals of `WorkspaceInvitationAcceptService.prepareOAuth` otherwise.
 */
export async function vetInvitation(
  accepts: WorkspaceInvitationAcceptService | null,
  record: StoredOAuthState,
  profile: OAuthProfile
): Promise<PendingInvitation | null> {
  if (record.workspaceInvitation === undefined) return null
  if (accepts === null) throw new AuthException(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
  const loaded: LoadedInvitation = await pinned(
    accepts.prepareOAuth(record.workspaceInvitation, record.tenantId, {
      email: profile.email,
      emailVerified: profile.emailVerified
    })
  )
  let hostAsked = false
  return checked({
    judgeNewAccount: async (account, context): Promise<void> => {
      hostAsked = await pinned(accepts.judgeNewAccount(loaded, account, context))
    },
    complete: async (user, created, context): Promise<void> => {
      await pinned(accepts.completeOAuth(loaded, user, created, context, hostAsked))
    }
  })
}
