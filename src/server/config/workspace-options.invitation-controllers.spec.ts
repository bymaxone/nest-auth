/**
 * @fileoverview Tests for the startup check of the invitation controllers: the workspace one needs
 * the workspace layer, and `registration: 'invitation-only'` needs an invitation controller mounted,
 * because otherwise no account could ever be created.
 *
 * @layer Test
 */

import type { ResolvedOptions } from './resolved-options'
import { assertInvitationControllers } from './workspace-options'

/** The resolved options that matter here: the mode and which features resolved. */
function resolved(
  registration: 'open' | 'invitation-only',
  features: { workspaces?: boolean; invitations?: boolean }
): ResolvedOptions {
  return {
    registration,
    ...(features.workspaces === true ? { workspaces: { enabled: true } } : {}),
    invitations: { enabled: features.invitations === true }
  } as unknown as ResolvedOptions
}

describe('assertInvitationControllers', () => {
  // The configuration QA found: workspaces are enabled, which the old check took for a way in, but
  // no invitation controller is mounted and OAuth acceptance rides on the workspace one.
  it('refuses invitation-only with workspaces enabled and no invitation controller', () => {
    expect(() =>
      assertInvitationControllers(resolved('invitation-only', { workspaces: true }), false, false)
    ).toThrow(
      "[BymaxAuthModule] registration: 'invitation-only' leaves no way to create an account. " +
        'Enable one invitation path: workspaces (missing: controllers.workspaceInvitations) or ' +
        'tenant invitations (missing: invitations.enabled, controllers.invitations).'
    )
  })

  it('names every missing piece when nothing is enabled', () => {
    expect(() =>
      assertInvitationControllers(resolved('invitation-only', {}), false, false)
    ).toThrow(
      'workspaces (missing: workspaces.enabled, controllers.workspaceInvitations) or ' +
        'tenant invitations (missing: invitations.enabled, controllers.invitations)'
    )
  })

  it('refuses tenant invitations that are enabled but whose controller is not mounted', () => {
    expect(() =>
      assertInvitationControllers(resolved('invitation-only', { invitations: true }), false, false)
    ).toThrow('tenant invitations (missing: controllers.invitations)')
  })

  it('accepts the workspace invitation controller with the workspace layer', () => {
    expect(() =>
      assertInvitationControllers(resolved('invitation-only', { workspaces: true }), true, false)
    ).not.toThrow()
  })

  it('accepts the tenant invitation controller with tenant invitations enabled', () => {
    expect(() =>
      assertInvitationControllers(resolved('invitation-only', { invitations: true }), false, true)
    ).not.toThrow()
  })

  it('asks nothing of an open registration', () => {
    expect(() => assertInvitationControllers(resolved('open', {}), false, false)).not.toThrow()
  })

  it('refuses the workspace invitation controller without the workspace layer, in either mode', () => {
    for (const mode of ['open', 'invitation-only'] as const) {
      expect(() =>
        assertInvitationControllers(resolved(mode, { invitations: true }), true, true)
      ).toThrow(
        '[BymaxAuthModule] controllers.workspaceInvitations: true requires workspaces.enabled: true ' +
          'and both workspace repository providers in extraProviders.'
      )
    }
  })
})
