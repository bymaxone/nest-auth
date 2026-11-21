/**
 * @fileoverview What the library reads from each answer of each repository, written once as data.
 *
 * A repository answers with the host's own objects, and an object of a host can carry fields the library has no
 * business with: an ORM entity holds its relations as getters, and one of them may throw until it is loaded. The
 * guarded view therefore reads, from an answer, only the fields its method promises, at the path where the promise is
 * made, and nothing else. These tables are that promise. The compiler checks them both ways: a method of a repository
 * interface without an entry, an entry for a method that does not exist, a field that is not a key of what the method
 * returns, and a key of what the method returns that the entry leaves out, each fail the build.
 *
 * @layer Utility
 */

import type { IApiKeyRepository, AuthApiKey } from '../interfaces/api-key-repository.interface'
import type {
  AuthMembership,
  IMembershipRepository,
  MembershipPage,
  MembershipWithWorkspace,
  RemovedMembership
} from '../interfaces/membership-repository.interface'
import type {
  AuthPlatformUser,
  IPlatformUserRepository
} from '../interfaces/platform-user-repository.interface'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import type {
  AuthWorkspace,
  IWorkspaceRepository
} from '../interfaces/workspace-repository.interface'

/** Every key of every member of a union. */
type KeysOfUnion<T> = T extends unknown ? keyof T : never

/** The type of the key `K` in each member of a union that has it. */
type ValueOf<T, K extends PropertyKey> = T extends unknown
  ? K extends keyof T
    ? T[K]
    : never
  : never

/** The values that are data, not records: nothing to describe field by field. */
type Plain = string | number | boolean | bigint | symbol | Date | null | undefined | void

/** Whether a value type holds a record the contract has to describe: anything but plain values and arrays of them. */
type HoldsRecord<V> = [Exclude<V, Plain>] extends [never]
  ? false
  : [Exclude<V, Plain>] extends [readonly (infer E)[]]
    ? HoldsRecord<E>
    : true

/** The entries for the fields of a record whose value holds a record, which are the only ones that need one. */
type NestedOf<R> = {
  readonly [K in KeysOfUnion<R> as HoldsRecord<ValueOf<R, K>> extends true ? K : never]: Contract<
    NonNullable<ValueOf<R, K>>
  >
}

/**
 * What is read from a value of type `R`: nothing but the value itself (`'value'`), each element of a list (`list`), or
 * the fields of a record (`fields`, every key of `R` and no other) with what is read from the ones that hold records
 * (`nested`).
 */
export type Contract<R> = [R] extends [readonly (infer E)[]]
  ? { readonly list: Contract<E> }
  : [R] extends [Plain]
    ? 'value'
    : {
        readonly fields: { readonly [K in KeysOfUnion<R>]: true }
        readonly nested: NestedOf<R>
      }

/** The contract of every method of a repository interface, for the value its promise resolves to. */
export type RepositoryContract<I> = {
  readonly [M in keyof I]-?: NonNullable<I[M]> extends (...args: never[]) => Promise<infer R>
    ? Contract<NonNullable<R>>
    : never
}

/** A contract with the types erased, which is what the guarded view reads. */
export type ErasedContract =
  | 'value'
  | { readonly list: ErasedContract }
  | {
      readonly fields: Readonly<Record<string, true>>
      readonly nested: Readonly<Record<string, ErasedContract>>
    }

/** The contract of each method of a repository, by method name, with the types erased. */
export type ErasedRepositoryContract = Readonly<Record<string, ErasedContract>>

const WORKSPACE: Contract<AuthWorkspace> = {
  fields: {
    id: true,
    tenantId: true,
    name: true,
    status: true,
    createdAt: true,
    deletionScheduledAt: true
  },
  nested: {}
}

const MEMBERSHIP: Contract<AuthMembership> = {
  fields: {
    tenantId: true,
    workspaceId: true,
    userId: true,
    role: true,
    status: true,
    invitedByUserId: true,
    createdAt: true,
    updatedAt: true
  },
  nested: {}
}

const MEMBERSHIP_WITH_WORKSPACE: Contract<MembershipWithWorkspace> = {
  fields: { ...MEMBERSHIP.fields, workspace: true },
  nested: { workspace: WORKSPACE }
}

const REMOVED_MEMBERSHIP: Contract<RemovedMembership> = {
  fields: { workspaceId: true, role: true },
  nested: {}
}

const USER: Contract<AuthUser> = {
  fields: {
    id: true,
    email: true,
    name: true,
    passwordHash: true,
    role: true,
    status: true,
    tenantId: true,
    emailVerified: true,
    mfaEnabled: true,
    mfaSecret: true,
    mfaRecoveryCodes: true,
    oauthProvider: true,
    oauthProviderId: true,
    lastLoginAt: true,
    createdAt: true
  },
  nested: {}
}

const PLATFORM_USER: Contract<AuthPlatformUser> = {
  fields: {
    id: true,
    email: true,
    name: true,
    passwordHash: true,
    role: true,
    status: true,
    mfaEnabled: true,
    mfaSecret: true,
    mfaRecoveryCodes: true,
    platformId: true,
    lastLoginAt: true,
    updatedAt: true,
    createdAt: true
  },
  nested: {}
}

const API_KEY: Contract<AuthApiKey> = {
  fields: {
    id: true,
    label: true,
    digest: true,
    scopes: true,
    createdAt: true,
    expiresAt: true,
    revokedAt: true,
    lastUsedAt: true
  },
  nested: {}
}

const PAGE_OF_MEMBERSHIPS_WITH_WORKSPACE: Contract<MembershipPage<MembershipWithWorkspace>> = {
  fields: { items: true, nextCursor: true },
  nested: { items: { list: MEMBERSHIP_WITH_WORKSPACE } }
}

const PAGE_OF_MEMBERSHIPS: Contract<MembershipPage<AuthMembership>> = {
  fields: { items: true, nextCursor: true },
  nested: { items: { list: MEMBERSHIP } }
}

const PAGE_OF_WORKSPACES: Contract<MembershipPage<AuthWorkspace>> = {
  fields: { items: true, nextCursor: true },
  nested: { items: { list: WORKSPACE } }
}

/** What is read from each answer of the user repository. */
export const USER_REPOSITORY_CONTRACT: RepositoryContract<IUserRepository> = {
  findById: USER,
  findByEmail: USER,
  create: USER,
  updatePassword: 'value',
  updateMfa: 'value',
  updateLastLogin: 'value',
  updateStatus: 'value',
  updateEmailVerified: 'value',
  updateEmail: 'value',
  findByOAuthId: USER,
  linkOAuth: 'value',
  createWithOAuth: USER
}

/** What is read from each answer of the platform user repository. */
export const PLATFORM_USER_REPOSITORY_CONTRACT: RepositoryContract<IPlatformUserRepository> = {
  findById: PLATFORM_USER,
  findByEmail: PLATFORM_USER,
  updateLastLogin: 'value',
  updateMfa: 'value',
  updatePassword: 'value',
  updateStatus: 'value'
}

/** What is read from each answer of the API key repository. */
export const API_KEY_REPOSITORY_CONTRACT: RepositoryContract<IApiKeyRepository> = {
  findById: API_KEY,
  create: API_KEY,
  markRevoked: 'value',
  setExpiry: 'value',
  limitExpiry: 'value',
  touchLastUsed: 'value',
  listByLabel: { list: API_KEY }
}

/** What is read from each answer of the workspace repository. */
export const WORKSPACE_REPOSITORY_CONTRACT: RepositoryContract<IWorkspaceRepository> = {
  createWithOwner: {
    fields: { status: true, workspace: true },
    nested: { workspace: WORKSPACE }
  },
  findById: WORKSPACE,
  rename: 'value',
  updateStatus: 'value'
}

/** What is read from each answer of the membership repository. */
export const MEMBERSHIP_REPOSITORY_CONTRACT: RepositoryContract<IMembershipRepository> = {
  find: MEMBERSHIP,
  listForUser: PAGE_OF_MEMBERSHIPS_WITH_WORKSPACE,
  listForWorkspace: PAGE_OF_MEMBERSHIPS,
  create: 'value',
  changeRole: 'value',
  remove: 'value',
  removeAllForUser: {
    fields: { result: true, removed: true, workspaceIds: true },
    nested: { removed: { list: REMOVED_MEMBERSHIP } }
  },
  transferOwnership: 'value',
  countOwned: 'value',
  listSoleOwned: PAGE_OF_WORKSPACES,
  getLastActiveWorkspaceId: 'value',
  setLastActiveWorkspaceId: 'value'
}

/**
 * The fields that are credentials: a copy hands them on only as visible as the host's own record made them, so no
 * spread of the copy can carry them out, and the library reads them by name, so a spread that loses one fails closed.
 */
export const CREDENTIAL_FIELDS: ReadonlySet<string> = new Set([
  'passwordHash',
  'mfaSecret',
  'mfaRecoveryCodes',
  'digest'
] as const satisfies readonly (keyof AuthUser | keyof AuthPlatformUser | keyof AuthApiKey)[])
