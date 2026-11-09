/**
 * @fileoverview Shared fixtures for the workspace lifecycle service specs.
 *
 * @layer Test
 */

import { resolveOptions } from '../../config/resolved-options'
import type { ResolvedOptions } from '../../config/resolved-options'
import type { HookContext } from '../../interfaces/auth-hooks.interface'
import type { WorkspaceOptions } from '../../interfaces/workspace-options.interface'
import type { AuthWorkspace } from '../../interfaces/workspace-repository.interface'

/** The workspace every case acts on. */
export const WORKSPACE_REF = { tenantId: 't1', workspaceId: 'w1' }

/** Request metadata a controller would hand the service. */
export const CONTEXT: HookContext = {
  plane: 'dashboard',
  tenantId: 't1',
  ip: '203.0.113.7',
  userAgent: 'jest',
  sanitizedHeaders: {}
}

/** A fixed instant the fake clock is set to, so audit timestamps and deadlines are exact. */
export const NOW = new Date('2026-01-10T12:00:00.000Z')

/**
 * Resolved module options with a three-level hierarchy: owner includes editor, which includes
 * viewer.
 *
 * @param extra - Workspace settings to add or override.
 * @returns The options the services read.
 */
export function workspaceOptions(extra: Partial<WorkspaceOptions> = {}): ResolvedOptions {
  return resolveOptions({
    jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
    roles: { hierarchy: { ADMIN: [] } },
    rateLimit: { clientIpSource: 'peer' },
    workspaces: {
      enabled: true,
      roles: {
        hierarchy: { owner: ['editor', 'viewer'], editor: ['viewer'], viewer: [] },
        ownerRole: 'owner'
      },
      ...extra
    }
  })
}

/**
 * A workspace row.
 *
 * @param overrides - Fields to change.
 * @returns The workspace.
 */
export function workspaceRow(overrides: Partial<AuthWorkspace> = {}): AuthWorkspace {
  return {
    id: 'w1',
    tenantId: 't1',
    name: 'Acme',
    status: 'active',
    createdAt: new Date(0),
    deletionScheduledAt: null,
    ...overrides
  }
}

/**
 * Resolved module options with the workspace feature off.
 *
 * @returns Options whose `workspaces` group is absent.
 */
export function optionsWithoutWorkspaces(): ResolvedOptions {
  return resolveOptions({
    jwt: { secret: 'xY9!kL2@mN5#pQ8$rS1%tU4^vW7&zA0B' },
    roles: { hierarchy: { ADMIN: [] } },
    rateLimit: { clientIpSource: 'peer' }
  })
}
