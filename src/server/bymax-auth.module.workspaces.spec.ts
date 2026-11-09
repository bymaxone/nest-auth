/**
 * @fileoverview Tests for the startup cross-validation of the workspace feature: the
 * `workspaces.enabled` flag and the two repository providers must agree.
 *
 * @layer Test
 */

import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from './bymax-auth.constants'
import { BymaxAuthModule } from './bymax-auth.module'
import type { BymaxAuthModuleOptions } from './interfaces/auth-module-options.interface'
import { WorkspaceAccessService } from './services/workspace-access.service'

const OPTIONS: BymaxAuthModuleOptions = {
  jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
  roles: { hierarchy: { ADMIN: ['MEMBER'], MEMBER: [] } },
  rateLimit: { clientIpSource: 'peer' }
}

const WORKSPACES: BymaxAuthModuleOptions = {
  ...OPTIONS,
  workspaces: {
    enabled: true,
    roles: { hierarchy: { owner: ['viewer'], viewer: [] }, ownerRole: 'owner' }
  }
}

const BASE = [
  { provide: BYMAX_AUTH_REDIS_CLIENT, useValue: { get: jest.fn(), set: jest.fn() } },
  { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: { findById: jest.fn() } }
]
const WORKSPACE_REPOSITORY = { provide: BYMAX_AUTH_WORKSPACE_REPOSITORY, useValue: {} }
const MEMBERSHIP_REPOSITORY = { provide: BYMAX_AUTH_MEMBERSHIP_REPOSITORY, useValue: {} }

/** Compiles the module with the given options and extra providers. */
function compile(
  options: BymaxAuthModuleOptions,
  extra: Array<{ provide: symbol; useValue: unknown }>
) {
  return Test.createTestingModule({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => options,
        extraProviders: [...BASE, ...extra]
      })
    ]
  }).compile()
}

describe('BymaxAuthModule — workspace providers', () => {
  it('compiles an enabled feature with both repositories', async () => {
    await expect(
      compile(WORKSPACES, [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY])
    ).resolves.toBeDefined()
  })

  it('registers the access service when the feature is on', async () => {
    const module = await compile(WORKSPACES, [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY])

    expect(module.get(WorkspaceAccessService, { strict: false })).toBeInstanceOf(
      WorkspaceAccessService
    )
  })

  it('does not register the access service when the feature is off', async () => {
    const module = await compile(OPTIONS, [])

    expect(() => module.get(WorkspaceAccessService, { strict: false })).toThrow()
  })

  it('compiles with the feature off and no repository', async () => {
    await expect(compile(OPTIONS, [])).resolves.toBeDefined()
  })

  it('refuses an enabled feature that lacks the membership repository', async () => {
    await expect(compile(WORKSPACES, [WORKSPACE_REPOSITORY])).rejects.toThrow(
      /requires BYMAX_AUTH_MEMBERSHIP_REPOSITORY in extraProviders/
    )
  })

  it('refuses an enabled feature that lacks the workspace repository', async () => {
    await expect(compile(WORKSPACES, [MEMBERSHIP_REPOSITORY])).rejects.toThrow(
      /requires BYMAX_AUTH_WORKSPACE_REPOSITORY in extraProviders/
    )
  })

  it('refuses a repository provided while the feature is off', async () => {
    await expect(compile(OPTIONS, [WORKSPACE_REPOSITORY])).rejects.toThrow(
      /provided but workspaces\.enabled is not true/
    )
  })

  it('refuses a feature explicitly disabled with a repository provided', async () => {
    const disabled = { ...WORKSPACES, workspaces: { ...WORKSPACES.workspaces!, enabled: false } }

    await expect(compile(disabled, [MEMBERSHIP_REPOSITORY])).rejects.toThrow(
      /provided but workspaces\.enabled is not true/
    )
  })
})
