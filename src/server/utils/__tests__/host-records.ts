/**
 * @fileoverview Complete records for the repository contracts: every field the interface requires, so a spec that
 * reads a record through a guarded view changes only the field it is about.
 *
 * @layer Test
 */

import type { AuthApiKey } from '../../interfaces/api-key-repository.interface'
import type {
  AuthMembership,
  MembershipWithWorkspace
} from '../../interfaces/membership-repository.interface'
import type { AuthPlatformUser } from '../../interfaces/platform-user-repository.interface'
import type { AuthUser } from '../../interfaces/user-repository.interface'
import type { AuthWorkspace } from '../../interfaces/workspace-repository.interface'

/** A user with every required field. */
export const userRecord = (overrides: Partial<AuthUser> = {}): AuthUser => ({
  id: 'u1',
  email: 'a@b.c',
  name: 'A',
  passwordHash: 'hash',
  role: 'MEMBER',
  status: 'active',
  tenantId: 't1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date(1),
  ...overrides
})

/** A platform user with every required field. */
export const platformRecord = (overrides: Partial<AuthPlatformUser> = {}): AuthPlatformUser => ({
  id: 'p1',
  email: 'admin@example.com',
  name: 'Admin',
  passwordHash: 'hash',
  role: 'SUPER_ADMIN',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  updatedAt: new Date(2),
  createdAt: new Date(1),
  ...overrides
})

/** An API key with every required field. */
export const apiKeyRecord = (overrides: Partial<AuthApiKey> = {}): AuthApiKey => ({
  id: 'k1',
  label: 'ci',
  digest: 'digest',
  scopes: ['read'],
  createdAt: new Date(1),
  expiresAt: null,
  revokedAt: null,
  lastUsedAt: null,
  ...overrides
})

/** A workspace with every required field. */
export const workspaceRecord = (overrides: Partial<AuthWorkspace> = {}): AuthWorkspace => ({
  id: 'w1',
  tenantId: 't1',
  name: 'W',
  status: 'active',
  createdAt: new Date(1),
  deletionScheduledAt: null,
  ...overrides
})

/** A membership with every required field. */
export const membershipRecord = (overrides: Partial<AuthMembership> = {}): AuthMembership => ({
  tenantId: 't1',
  workspaceId: 'w1',
  userId: 'u1',
  role: 'MEMBER',
  status: 'active',
  invitedByUserId: null,
  createdAt: new Date(1),
  updatedAt: new Date(2),
  ...overrides
})

/** A membership with its workspace. */
export const membershipWithWorkspace = (
  overrides: Partial<MembershipWithWorkspace> = {}
): MembershipWithWorkspace => ({
  ...membershipRecord(),
  workspace: workspaceRecord(),
  ...overrides
})

/**
 * A record served the way an ORM entity serves it: no own field, every field an accessor of its prototype over the
 * values of the record.
 */
export function onPrototype<T extends object>(record: T): T {
  const prototype = {}
  for (const key of Object.keys(record))
    Object.defineProperty(prototype, key, {
      get: (): unknown => (record as Record<string, unknown>)[key]
    })
  return Object.create(prototype) as T
}
