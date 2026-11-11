/**
 * @fileoverview Tests for the startup cross-validation of the workspace feature: the
 * `workspaces.enabled` flag and the two repository providers must agree.
 *
 * @layer Test
 */

import { Inject, Injectable } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_MEMBERSHIP_REPOSITORY,
  BYMAX_AUTH_REDIS_CLIENT,
  BYMAX_AUTH_USER_REPOSITORY,
  BYMAX_AUTH_WORKSPACE_REPOSITORY
} from './bymax-auth.constants'
import { BymaxAuthModule } from './bymax-auth.module'
import { WorkspaceController } from './controllers/workspace.controller'
import { WorkspaceInvitationController } from './controllers/workspace-invitation.controller'
import type { BymaxAuthModuleOptions } from './interfaces/auth-module-options.interface'
import { WorkspaceGuard } from './guards/workspace.guard'
import { MembershipService } from './services/membership.service'
import { WorkspaceAccessService } from './services/workspace-access.service'
import { WorkspaceInvitationService } from './services/workspace-invitation.service'
import { WorkspaceEventsService } from './services/workspace-events.service'
import { WorkspaceService } from './services/workspace.service'

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
  extra: Array<{ provide: symbol; useValue: unknown }>,
  controllers: BymaxAuthModuleOptions['controllers'] = {}
) {
  return Test.createTestingModule({
    imports: [
      BymaxAuthModule.registerAsync({
        useFactory: () => options,
        controllers,
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

  it('registers the lifecycle services when the feature is on', async () => {
    const module = await compile(WORKSPACES, [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY])

    for (const service of [WorkspaceService, MembershipService, WorkspaceEventsService]) {
      expect(module.get(service, { strict: false })).toBeInstanceOf(service)
    }
  })

  it('registers the guard when the feature is on', async () => {
    const module = await compile(WORKSPACES, [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY])

    expect(module.get(WorkspaceGuard, { strict: false })).toBeInstanceOf(WorkspaceGuard)
  })

  it('does not register the access service when the feature is off', async () => {
    const module = await compile(OPTIONS, [])

    expect(() => module.get(WorkspaceAccessService, { strict: false })).toThrow()
    expect(() => module.get(WorkspaceGuard, { strict: false })).toThrow()
    expect(() => module.get(WorkspaceService, { strict: false })).toThrow()
    expect(() => module.get(MembershipService, { strict: false })).toThrow()
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

describe('BymaxAuthModule — workspace controller', () => {
  it('mounts the controller only when it is switched on', async () => {
    const on = await compile(WORKSPACES, [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY], {
      workspaces: true
    })
    const off = await compile(WORKSPACES, [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY])

    expect(on.get(WorkspaceController, { strict: false })).toBeInstanceOf(WorkspaceController)
    expect(() => off.get(WorkspaceController, { strict: false })).toThrow()
  })

  it('refuses to boot with the controller switched on and the feature off', async () => {
    await expect(compile(OPTIONS, [], { workspaces: true })).rejects.toThrow(
      '[BymaxAuthModule] controllers.workspaces: true requires workspaces.enabled: true ' +
        'and both workspace repository providers in extraProviders.'
    )
  })
})

describe('BymaxAuthModule — workspace invitations', () => {
  const REPOSITORIES = [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY]

  it('mounts the controller and its service only when it is switched on', async () => {
    const on = await compile(WORKSPACES, REPOSITORIES, {
      workspaces: true,
      workspaceInvitations: true
    })
    const off = await compile(WORKSPACES, REPOSITORIES, { workspaces: true })

    expect(on.get(WorkspaceInvitationController, { strict: false })).toBeInstanceOf(
      WorkspaceInvitationController
    )
    expect(on.get(WorkspaceInvitationService, { strict: false })).toBeInstanceOf(
      WorkspaceInvitationService
    )
    expect(() => off.get(WorkspaceInvitationController, { strict: false })).toThrow()
    expect(() => off.get(WorkspaceInvitationService, { strict: false })).toThrow()
  })

  it('refuses to boot with the controller switched on and the feature off', async () => {
    await expect(compile(OPTIONS, [], { workspaceInvitations: true })).rejects.toThrow(
      '[BymaxAuthModule] controllers.workspaceInvitations: true requires workspaces.enabled: true ' +
        'and both workspace repository providers in extraProviders.'
    )
  })

  it('refuses to start when the email provider cannot deliver a workspace invitation', async () => {
    const module = await compile(
      WORKSPACES,
      [...REPOSITORIES, { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: {} }],
      { workspaces: true, workspaceInvitations: true }
    )

    await expect(module.init()).rejects.toThrow('sendWorkspaceInvitation')
  })

  it('exports the invitation service to a host module, which calls the platform invitations through it', async () => {
    @Injectable()
    class HostAdmin {
      constructor(
        @Inject(WorkspaceInvitationService) readonly invitations: WorkspaceInvitationService
      ) {}
    }
    const module = await Test.createTestingModule({
      imports: [
        BymaxAuthModule.registerAsync({
          useFactory: () => WORKSPACES,
          controllers: { workspaces: true, workspaceInvitations: true },
          extraProviders: [...BASE, ...REPOSITORIES]
        })
      ],
      providers: [HostAdmin]
    }).compile()

    const host = module.get(HostAdmin)

    expect(host.invitations).toBeInstanceOf(WorkspaceInvitationService)
    expect(typeof host.invitations.inviteAsPlatform).toBe('function')
    expect(typeof host.invitations.revokeAsPlatform).toBe('function')
  })

  it('does not export the invitation service when the feature is off', async () => {
    @Injectable()
    class HostAdmin {
      constructor(
        @Inject(WorkspaceInvitationService) readonly invitations: WorkspaceInvitationService
      ) {}
    }

    await expect(
      Test.createTestingModule({
        imports: [
          BymaxAuthModule.registerAsync({
            useFactory: () => WORKSPACES,
            controllers: { workspaces: true },
            extraProviders: [...BASE, ...REPOSITORIES]
          })
        ],
        providers: [HostAdmin]
      }).compile()
    ).rejects.toThrow()
  })
})

describe('BymaxAuthModule — invitation-only registration', () => {
  const INVITATION_ONLY: BymaxAuthModuleOptions = { ...WORKSPACES, registration: 'invitation-only' }
  const REPOSITORIES = [WORKSPACE_REPOSITORY, MEMBERSHIP_REPOSITORY]

  // The configuration QA found: the workspace layer is on and the workspace controller is mounted,
  // but there is no invitation controller, so no account could ever be created.
  it('refuses to boot with workspaces on and no invitation controller mounted', async () => {
    await expect(compile(INVITATION_ONLY, REPOSITORIES, { workspaces: true })).rejects.toThrow(
      'leaves no way to create an account'
    )
  })

  it('boots with the workspace invitation controller mounted', async () => {
    const mounted = { workspaces: true, workspaceInvitations: true }

    await expect(compile(INVITATION_ONLY, REPOSITORIES, mounted)).resolves.toBeDefined()
  })
})
