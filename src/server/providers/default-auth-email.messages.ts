/**
 * @fileoverview The built-in copy of {@link DefaultAuthEmailProvider}: one pure renderer per message,
 * security shape first and wording second.
 *
 * Each entry is a pure function of its inputs, which is what makes an override a drop-in
 * replacement and keeps the copy testable without a provider around it. The provider attaches the
 * tenant and the recipient, escapes the text and delivers it.
 *
 * @layer Provider
 */

import type { AuthEmailCatalogue } from './default-auth-email.provider'
import type { WorkspaceInviteData } from '../interfaces/email-provider.interface'

/** How long a verification or reset code stays valid, stated in the message that carries it. */
const CODE_VALIDITY_TEXT = 'It expires shortly, so use it soon.'

/** Closing line on every message announcing a change the recipient may not have made. */
const UNEXPECTED_CHANGE_TEXT =
  'If this was not you, secure your account immediately: change your password and sign out of every session.'

/** Whether the platform named a person for a bootstrap invitation. */
function hasInviter(invite: WorkspaceInviteData): boolean {
  return invite.inviterName.trim() !== ''
}

/** The subject of a workspace invitation; a bootstrap one names no inviter the invitee may not know. */
function workspaceInvitationSubject(invite: WorkspaceInviteData): string {
  if (invite.kind === 'member') {
    return `${invite.inviterName} invited you to ${invite.workspaceName}`
  }
  return hasInviter(invite)
    ? `${invite.inviterName} invited you to set up ${invite.workspaceName}`
    : `You have been invited to set up ${invite.workspaceName}`
}

/** The opening line: what the invitation is for, and who sent it where that is a person. */
function workspaceInvitationOpening(invite: WorkspaceInviteData): string {
  if (invite.kind === 'member') {
    return `${invite.inviterName} invited you to the workspace ${invite.workspaceName} as ${invite.role}.`
  }
  const subject = hasInviter(invite) ? `${invite.inviterName} invited you` : 'You have been invited'
  return `${subject} to set up the workspace ${invite.workspaceName} as its owner.`
}

/** The body of a workspace invitation: the opening, the token, the expiry and the disclaimer. */
function workspaceInvitationText(invite: WorkspaceInviteData): string {
  const step = invite.accountExists ? 'Sign in' : 'Create your account'
  return [
    workspaceInvitationOpening(invite),
    `${step} and use this token to accept: ${invite.inviteToken}`,
    `It expires on ${invite.expiresAt.toISOString()}.`,
    'If you were not expecting this invitation, ignore this message.'
  ].join('\n\n')
}

/**
 * The built-in copy, security shape first and wording second.
 *
 * Each entry is a pure function of its inputs, which is what makes an override a drop-in
 * replacement and keeps the copy testable without a provider around it.
 */
export const DEFAULT_MESSAGES: AuthEmailCatalogue = {
  passwordResetToken: ({ token }) => ({
    subject: 'Reset your password',
    text: `Use this token to reset your password: ${token}\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change.`
  }),
  passwordResetOtp: ({ otp }) => ({
    subject: 'Your password reset code',
    text: `Your password reset code is ${otp}.\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not ask to reset your password, ignore this message and nothing will change.`
  }),
  emailVerificationOtp: ({ otp }) => ({
    subject: 'Verify your email address',
    text: `Your verification code is ${otp}.\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not create an account, ignore this message.`
  }),
  passwordChanged: () => ({
    subject: 'Your password was changed',
    text: `The password on your account was changed.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  emailChangeVerification: ({ token }) => ({
    subject: 'Confirm your new email address',
    text: `Your confirmation code is ${token}.\n\n${CODE_VALIDITY_TEXT}\n\nIf you did not ask to change your email address, ignore this message.`
  }),
  emailChanged: ({ newEmail }) => ({
    subject: 'Your email address was changed',
    text: `The email address on your account was changed to ${newEmail}, and this address no longer signs in to it.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  mfaEnabled: () => ({
    subject: 'Two-factor authentication is on',
    text: `Two-factor authentication was enabled on your account.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  mfaDisabled: () => ({
    subject: 'Two-factor authentication is off',
    text: `Two-factor authentication was disabled on your account.\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  newSessionAlert: ({ sessionInfo }) => ({
    subject: 'New sign-in to your account',
    text: `A new session was started on your account.\n\nDevice: ${sessionInfo.device}\nIP: ${sessionInfo.ip}\nSession: ${sessionInfo.sessionHash}\n\n${UNEXPECTED_CHANGE_TEXT}`
  }),
  invitation: ({ invite }) => ({
    subject: `${invite.inviterName} invited you to ${invite.tenantName}`,
    text: `${invite.inviterName} invited you to join ${invite.tenantName}.\n\nUse this token to accept: ${invite.inviteToken}\n\nIt expires on ${invite.expiresAt.toISOString()}.\n\nIf you were not expecting this invitation, ignore this message.`
  }),
  workspaceInvitation: ({ invite }) => ({
    subject: workspaceInvitationSubject(invite),
    text: workspaceInvitationText(invite)
  })
}
