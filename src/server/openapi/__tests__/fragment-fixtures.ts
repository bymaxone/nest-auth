/**
 * @fileoverview Shared fixtures of the OpenAPI fragment specs: the registrations they build from and
 * the resolved options a delivery mode produces.
 *
 * @layer Test
 */

import { resolveOptions } from '../../config/resolved-options'
import type { ResolvedOptions } from '../../config/resolved-options'
import type { RegisteredControllers } from '../auth-openapi-fragment'

/** The default registration: `auth` and `passwordReset`, which is what a bare module mounts. */
export const DEFAULTS: RegisteredControllers = {
  auth: true,
  passwordReset: true,
  mfa: false,
  sessions: false,
  platform: false,
  platformMfa: false,
  invitations: false,
  emailChange: false,
  oauth: false,
  workspaces: false,
  workspaceInvitations: false
}

/** Everything mounted. */
export const EVERYTHING: RegisteredControllers = {
  auth: true,
  passwordReset: true,
  mfa: true,
  sessions: true,
  platform: true,
  platformMfa: true,
  invitations: true,
  emailChange: true,
  oauth: true,
  workspaces: true,
  workspaceInvitations: true
}

/** The options a deployment resolves with the given delivery mode and cookie names. */
export function optionsFor(
  tokenDelivery: ResolvedOptions['tokenDelivery'],
  cookies = { accessTokenName: 'access_token', refreshTokenName: 'refresh_token' }
): ResolvedOptions {
  return resolveOptions({
    jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
    roles: { hierarchy: { ADMIN: [] } },
    rateLimit: { clientIpSource: 'peer' },
    tokenDelivery,
    cookies
  })
}
