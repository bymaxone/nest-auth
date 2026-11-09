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
      'WorkspaceController.members',
      'WorkspaceController.scheduleDeletion',
      'WorkspaceController.transferOwnership'
    ])
  })

  // Scenario: the two workspace lists. Expected: each says it answers only data the caller already
  // belongs to. Why: a list route reads as an enumeration, and the security requirement cannot say
  // that it is not one.
  it("says the workspace lists answer only the caller's own data", () => {
    const operations = buildAuthOpenApiFragment(optionsFor('bearer'), EVERYTHING).operations

    expect(operations['WorkspaceController.list']?.['description']).toBe(
      "Lists only the caller's own active memberships. The tenant and the member come from the " +
        'access token, and the cursor says where the next page starts, never whose memberships ' +
        'are listed.'
    )
    expect(operations['WorkspaceController.members']?.['description']).toBe(
      'Lists the members of the workspace named in the path, to a caller the workspace guard ' +
        'admitted to it with a role the deployment allows to view members. The cursor says where ' +
        'the next page starts, never which workspace is listed.'
    )
  })

  // Scenario: the schedule-deletion operation. Expected: it says it re-proves the caller and why it
  // is a POST. Why: the security requirement cannot say that a password or a fresh sign-in is
  // needed, and a client generated from a DELETE-shaped guess would drop the body.
  it('says the schedule-deletion operation needs the caller to be re-proved', () => {
    const operations = buildAuthOpenApiFragment(optionsFor('bearer'), EVERYTHING).operations

    expect(operations['WorkspaceController.scheduleDeletion']?.['description']).toBe(
      "Schedules the workspace for deletion and ends every member's access at once. The caller is " +
        're-proved: by the account password in the request body, or, for an account with no ' +
        'password, by a recent sign-in. It is a POST because a body on DELETE has no defined semantics.'
    )
  })

  // Scenario: the transfer-ownership operation. Expected: it says it needs the caller to be
  // re-proved and to be the owner. Why: neither fits in a security requirement.
  it('says the transfer-ownership operation needs the owner to be re-proved', () => {
    const operations = buildAuthOpenApiFragment(optionsFor('bearer'), EVERYTHING).operations

    expect(operations['WorkspaceController.transferOwnership']?.['description']).toBe(
      'Hands ownership to another active member. Only an owner may do it. The caller is re-proved: by ' +
        'the account password in the request body, or, for an account with no password, by a recent ' +
        'sign-in. The caller is checked as the owner before the password is looked at.'
    )
  })
})
