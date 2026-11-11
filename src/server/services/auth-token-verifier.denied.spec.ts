/**
 * @fileoverview The verifier's `workspace` option reports a refusal to the `access.denied` emitter
 * as the `verifier` surface, with the token's tenant and account, and still refuses with the
 * decision's own code. Kept apart from the verifier's specs, which are over the size limit.
 *
 * @layer Test
 */

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { AccountStatusService } from './account-status.service'
import { AuthRevocationService } from './auth-revocation.service'
import { AuthTokenVerifierService } from './auth-token-verifier.service'
import { WorkspaceAccessService } from './workspace-access.service'
import { WorkspaceDeniedEventsService } from './workspace-denied-events.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

const PAYLOAD = {
  jti: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard',
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  epoch: 1,
  iat: 1,
  exp: 2
}

async function build(access: unknown) {
  const admit = jest.fn((_denied: unknown, decide: () => unknown) => decide())
  const module = await Test.createTestingModule({
    providers: [
      AuthTokenVerifierService,
      { provide: JwtService, useValue: { verify: jest.fn().mockReturnValue({ ...PAYLOAD }) } },
      {
        provide: BYMAX_AUTH_OPTIONS,
        useValue: {
          jwt: { algorithm: 'HS256', issuer: 'iss', audience: 'aud', previousSecrets: [] },
          workspaces: {
            enabled: true,
            roles: { hierarchy: { owner: ['viewer'], viewer: [] }, ownerRole: 'owner' }
          }
        }
      },
      {
        provide: AuthRevocationService,
        useValue: { isAccessTokenRevoked: jest.fn().mockResolvedValue(false) }
      },
      {
        provide: AccountStatusService,
        useValue: { assertDashboardAccountUsable: jest.fn().mockResolvedValue(undefined) }
      },
      { provide: WorkspaceAccessService, useValue: { resolveAccess: async () => access } },
      { provide: WorkspaceDeniedEventsService, useValue: { admit } }
    ]
  }).compile()
  return { verifier: module.get(AuthTokenVerifierService), admit }
}

const CHECK = { workspaceId: 'w1', roles: ['viewer'] }

describe('verifyAccessToken reporting a refusal', () => {
  it('reports a refused workspace as the verifier surface and still refuses', async () => {
    const { verifier, admit } = await build({ kind: 'denied' })

    await expect(
      verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK })
    ).rejects.toMatchObject({ response: { error: { code: AUTH_ERROR_CODES.WORKSPACE_NOT_FOUND } } })

    expect(admit).toHaveBeenCalledTimes(1)
    expect(admit.mock.calls[0]?.[0]).toEqual({
      tenantId: 'tenant-1',
      userId: 'user-1',
      workspaceId: 'w1',
      surface: 'verifier'
    })
  })

  it('returns the membership for an admitted caller', async () => {
    const member = { tenantId: 'tenant-1', workspaceId: 'w1', userId: 'user-1', role: 'viewer' }
    const { verifier } = await build({ kind: 'member', member })

    const result = await verifier.verifyAccessToken('tok', { plane: 'dashboard', workspace: CHECK })

    expect(result.workspace).toEqual(member)
  })

  it('does not report a malformed workspace id, which is refused before any decision', async () => {
    const { verifier, admit } = await build({ kind: 'denied' })

    await expect(
      verifier.verifyAccessToken('tok', {
        plane: 'dashboard',
        workspace: { workspaceId: '', roles: ['viewer'] }
      })
    ).rejects.toMatchObject({ response: { error: { code: AUTH_ERROR_CODES.VALIDATION } } })

    expect(admit).not.toHaveBeenCalled()
  })
})
