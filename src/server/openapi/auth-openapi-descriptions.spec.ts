/**
 * @fileoverview The prose the OpenAPI fragment contributes to an operation: which operations carry
 * it, and what the workspace lists say about whose data they answer.
 *
 * @layer Test
 */

import { buildAuthOpenApiFragment } from './auth-openapi-fragment'
import type { RegisteredControllers } from './auth-openapi-fragment'
import type { ResolvedOptions } from '../config/resolved-options'

/** Every controller family mounted, so every operation the fragment can describe is present. */
const EVERYTHING: RegisteredControllers = {
  auth: true,
  passwordReset: true,
  mfa: true,
  sessions: true,
  platform: true,
  platformMfa: true,
  invitations: true,
  emailChange: true,
  oauth: true,
  workspaces: true
}

function optionsFor(tokenDelivery: ResolvedOptions['tokenDelivery']): ResolvedOptions {
  return {
    tokenDelivery,
    cookies: { accessTokenName: 'access_token', refreshTokenName: 'refresh_token' }
  } as unknown as ResolvedOptions
}

describe('the prose the fragment contributes', () => {
  // The map is deliberate, not a habit: a description restating what `security` already says is
  // noise in a rendered document, and nest-core drops a contributed one only where the consumer
  // wrote their own. Adding another entry should therefore be a decision someone makes on
  // purpose, which this assertion forces by failing when one appears.
  it('contributes prose to the operations that need it and no other', () => {
    const described = Object.entries(
      buildAuthOpenApiFragment(optionsFor('both'), EVERYTHING).operations
    )
      .filter(([, operation]) => 'description' in operation)
      .map(([handler]) => handler)

    expect(described).toEqual([
      'AuthController.logout',
      'WorkspaceController.list',
      'WorkspaceController.members'
    ])
  })

  // Scenario: the two workspace lists. Expected: each says it answers only data the caller already
  // belongs to. Why: a list route reads as an enumeration, and the security requirement cannot say
  // that it is not one.
  it("says the workspace lists answer only the caller's own data", () => {
    const operations = buildAuthOpenApiFragment(optionsFor('bearer'), EVERYTHING).operations

    expect(operations['WorkspaceController.list']?.['description']).toMatch(/only the caller's own/)
    expect(operations['WorkspaceController.members']?.['description']).toMatch(
      /never which workspace is listed/
    )
  })
})
