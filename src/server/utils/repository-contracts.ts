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

/** The type of the key `K` in each member of a union: `undefined` where a member lacks it, which makes it optional. */
type ValueOf<T, K extends PropertyKey> = T extends unknown
  ? K extends keyof T
    ? T[K]
    : undefined
  : never

/** The kinds a value of type `V` (without its `null` and `undefined`) can be read as. */
type BaseKind<V> = [V] extends [boolean]
  ? 'boolean'
  : [V] extends [number]
    ? 'number'
    : [V] extends [string]
      ? 'string' | 'id'
      : [V] extends [Date]
        ? 'date'
        : [V] extends [readonly string[]]
          ? 'strings'
          : 'nested'

/** The kinds a field that only informs can be read as: lenient, so absence, `null` and an object of the host pass. */
type LenientKind<V> = [V] extends [string]
  ? '~id' | '~string'
  : [V] extends [Date]
    ? '~date'
    : never

/**
 * How a field of type `V` is read. A field that decides an admission is strict: its kind, then `|null` when `null` is
 * promised and `?` when it may be absent, so a required field has no `?` and one that holds a record or a list of them
 * is `nested`. A field that only informs (an id, a name, a date the library returns or displays) may be lenient: `~id`,
 * `~string` or `~date`, which accept absence and `null`, and an object of the host's own classes, and refuse a function,
 * a symbol and a bigint.
 */
export type FieldSpec<V> =
  | `${BaseKind<NonNullable<V>>}${null extends V ? '|null' : ''}${undefined extends V ? '?' : ''}`
  | LenientKind<NonNullable<V>>

/** The entries for the fields that hold a record or a list of records, which are the only ones that need one. */
type NestedOf<R> = {
  readonly [
    K in KeysOfUnion<R> as [BaseKind<NonNullable<ValueOf<R, K>>>] extends ['nested'] ? K : never
  ]: Contract<NonNullable<ValueOf<R, K>>>
}

/** How a plain answer of type `R` is read. */
type ScalarSpec<R> =
  `${[NonNullable<R>] extends [boolean] ? 'boolean' : [NonNullable<R>] extends [number] ? 'number' : [NonNullable<R>] extends [string] ? 'string' : 'date'}${null extends R ? '|null' : ''}`

/** A record or a list that a method may answer nothing for says so (`nullable`), and one that may not does not. */
type Nothing<R> = [R] extends [NonNullable<R>]
  ? { readonly nullable?: undefined }
  : { readonly nullable: true }

/**
 * What is read from a value of type `R`, and as which kind: a plain answer by its kind (`'boolean'`, `'string|null'`,
 * `'void'`...), each element of a list (`list`), or the fields of a record (`fields`, every key of `R` and no other,
 * each with the kind of its type) with what is read from the ones that hold records (`nested`).
 */
export type Contract<R> = [R] extends [void]
  ? 'void'
  : [NonNullable<R>] extends [readonly (infer E)[]]
    ? { readonly list: Contract<E> } & Nothing<R>
    : [NonNullable<R>] extends [boolean | number | string | Date]
      ? ScalarSpec<R>
      : {
          readonly fields: {
            readonly [K in KeysOfUnion<NonNullable<R>>]: FieldSpec<ValueOf<NonNullable<R>, K>>
          }
          readonly nested: NestedOf<NonNullable<R>>
        } & Nothing<R>

/** The contract of every method of a repository interface, for the value its promise resolves to. */
export type RepositoryContract<I> = {
  readonly [M in keyof I]-?: NonNullable<I[M]> extends (...args: never[]) => Promise<infer R>
    ? Contract<R>
    : never
}

/** A contract with the types erased, which is what the guarded view reads. */
export type ErasedContract =
  | string
  | { readonly list: ErasedContract; readonly nullable?: true | undefined }
  | {
      readonly fields: Readonly<Record<string, string>>
      readonly nested: Readonly<Record<string, ErasedContract>>
      readonly nullable?: true | undefined
    }

/** The contract of each method of a repository, by method name, with the types erased. */
export type ErasedRepositoryContract = Readonly<Record<string, ErasedContract>>

/**
 * The contract of each record, for the fields that decide (strict, unmarked) and the fields that only inform (lenient,
 * marked `~`). The strict ones are the fields a service reads to allow or deny; {@link SECURITY_FIELDS} lists them and a
 * spec asserts that none is lenient.
 */
export const RECORD_CONTRACTS = {
  workspace: {
    fields: {
      id: '~id',
      tenantId: 'id',
      name: '~string',
      status: 'string',
      createdAt: '~date',
      deletionScheduledAt: 'date|null'
    },
    nested: {}
  },
  membership: {
    fields: {
      tenantId: 'id',
      workspaceId: '~id',
      userId: '~id',
      role: 'string',
      status: 'string',
      invitedByUserId: '~id',
      createdAt: '~date',
      updatedAt: '~date'
    },
    nested: {}
  },
  user: {
    fields: {
      id: '~id',
      email: '~string',
      name: '~string',
      passwordHash: 'string|null',
      role: 'string',
      status: 'string',
      tenantId: 'id',
      emailVerified: 'boolean',
      mfaEnabled: 'boolean',
      mfaSecret: 'string?',
      mfaRecoveryCodes: 'strings?',
      oauthProvider: '~string',
      oauthProviderId: '~string',
      lastLoginAt: '~date',
      createdAt: '~date'
    },
    nested: {}
  },
  platformUser: {
    fields: {
      id: '~id',
      email: '~string',
      name: '~string',
      passwordHash: 'string',
      role: 'string',
      status: 'string',
      mfaEnabled: 'boolean',
      mfaSecret: 'string?',
      mfaRecoveryCodes: 'strings?',
      platformId: '~id',
      lastLoginAt: '~date',
      updatedAt: '~date',
      createdAt: '~date'
    },
    nested: {}
  },
  apiKey: {
    fields: {
      id: '~id',
      label: '~string',
      digest: 'string',
      scopes: 'strings',
      createdAt: '~date',
      expiresAt: 'date|null',
      revokedAt: 'date|null',
      lastUsedAt: '~date'
    },
    nested: {}
  },
  removedMembership: { fields: { workspaceId: '~id', role: 'string' }, nested: {} }
} as const satisfies {
  readonly workspace: Contract<AuthWorkspace>
  readonly membership: Contract<AuthMembership>
  readonly user: Contract<AuthUser>
  readonly platformUser: Contract<AuthPlatformUser>
  readonly apiKey: Contract<AuthApiKey>
  readonly removedMembership: Contract<RemovedMembership>
}

/**
 * The fields of each record that decide an admission: a service reads them to allow or to deny, so each is read strictly,
 * by kind, as required where the interface requires it, and never coerced.
 */
export const SECURITY_FIELDS = {
  workspace: ['tenantId', 'status', 'deletionScheduledAt'],
  membership: ['tenantId', 'role', 'status'],
  user: [
    'passwordHash',
    'role',
    'status',
    'tenantId',
    'emailVerified',
    'mfaEnabled',
    'mfaSecret',
    'mfaRecoveryCodes'
  ],
  platformUser: ['passwordHash', 'role', 'status', 'mfaEnabled', 'mfaSecret', 'mfaRecoveryCodes'],
  apiKey: ['digest', 'scopes', 'expiresAt', 'revokedAt'],
  removedMembership: ['role']
} as const satisfies {
  readonly workspace: readonly (keyof AuthWorkspace)[]
  readonly membership: readonly (keyof AuthMembership)[]
  readonly user: readonly (keyof AuthUser)[]
  readonly platformUser: readonly (keyof AuthPlatformUser)[]
  readonly apiKey: readonly (keyof AuthApiKey)[]
  readonly removedMembership: readonly (keyof RemovedMembership)[]
}

const WORKSPACE = RECORD_CONTRACTS.workspace
const MEMBERSHIP = RECORD_CONTRACTS.membership
const USER = RECORD_CONTRACTS.user
const PLATFORM_USER = RECORD_CONTRACTS.platformUser
const API_KEY = RECORD_CONTRACTS.apiKey
const REMOVED_MEMBERSHIP = RECORD_CONTRACTS.removedMembership

const MEMBERSHIP_WITH_WORKSPACE = {
  fields: { ...MEMBERSHIP.fields, workspace: 'nested' },
  nested: { workspace: WORKSPACE }
} as const satisfies Contract<MembershipWithWorkspace>

const PAGE_OF_MEMBERSHIPS_WITH_WORKSPACE = {
  fields: { items: 'nested', nextCursor: '~string' },
  nested: { items: { list: MEMBERSHIP_WITH_WORKSPACE } }
} as const satisfies Contract<MembershipPage<MembershipWithWorkspace>>

const PAGE_OF_MEMBERSHIPS = {
  fields: { items: 'nested', nextCursor: '~string' },
  nested: { items: { list: MEMBERSHIP } }
} as const satisfies Contract<MembershipPage<AuthMembership>>

const PAGE_OF_WORKSPACES = {
  fields: { items: 'nested', nextCursor: '~string' },
  nested: { items: { list: WORKSPACE } }
} as const satisfies Contract<MembershipPage<AuthWorkspace>>

/** The contract of a record, for a method that may find nothing and then answers `null` or `undefined`. */
const orNothing = <C extends object>(contract: C): C & { readonly nullable: true } => ({
  ...contract,
  nullable: true
})

/** What is read from each answer of the user repository. */
export const USER_REPOSITORY_CONTRACT: RepositoryContract<IUserRepository> = {
  findById: orNothing(USER),
  findByEmail: orNothing(USER),
  create: USER,
  updatePassword: 'void',
  updateMfa: 'void',
  updateLastLogin: 'void',
  updateStatus: 'void',
  updateEmailVerified: 'void',
  updateEmail: 'void',
  findByOAuthId: orNothing(USER),
  linkOAuth: 'void',
  createWithOAuth: USER
}

/** What is read from each answer of the platform user repository. */
export const PLATFORM_USER_REPOSITORY_CONTRACT: RepositoryContract<IPlatformUserRepository> = {
  findById: orNothing(PLATFORM_USER),
  findByEmail: orNothing(PLATFORM_USER),
  updateLastLogin: 'void',
  updateMfa: 'void',
  updatePassword: 'void',
  updateStatus: 'void'
}

/** What is read from each answer of the API key repository. */
export const API_KEY_REPOSITORY_CONTRACT: RepositoryContract<IApiKeyRepository> = {
  findById: orNothing(API_KEY),
  create: API_KEY,
  markRevoked: 'boolean',
  setExpiry: 'boolean',
  limitExpiry: 'boolean',
  touchLastUsed: 'void',
  listByLabel: { list: API_KEY }
}

/** What is read from each answer of the workspace repository. */
export const WORKSPACE_REPOSITORY_CONTRACT: RepositoryContract<IWorkspaceRepository> = {
  createWithOwner: {
    fields: { status: 'string', workspace: 'nested?' },
    nested: { workspace: WORKSPACE }
  },
  findById: orNothing(WORKSPACE),
  rename: 'string',
  updateStatus: 'string'
}

/** What is read from each answer of the membership repository. */
export const MEMBERSHIP_REPOSITORY_CONTRACT: RepositoryContract<IMembershipRepository> = {
  find: orNothing(MEMBERSHIP),
  listForUser: PAGE_OF_MEMBERSHIPS_WITH_WORKSPACE,
  listForWorkspace: PAGE_OF_MEMBERSHIPS,
  create: 'string',
  changeRole: 'string',
  remove: 'string',
  removeAllForUser: {
    fields: { result: 'string', removed: 'nested?', workspaceIds: 'strings?' },
    nested: { removed: { list: REMOVED_MEMBERSHIP } }
  },
  transferOwnership: 'string',
  countOwned: 'number',
  listSoleOwned: PAGE_OF_WORKSPACES,
  getLastActiveWorkspaceId: 'string|null',
  setLastActiveWorkspaceId: 'void'
}

/**
 * The fields that are credentials: a copy hands them on only as visible as the host's own record made them, so no
 * spread of the copy can carry them out.
 */
export const CREDENTIAL_FIELDS: ReadonlySet<string> = new Set([
  'passwordHash',
  'mfaSecret',
  'mfaRecoveryCodes',
  'digest'
] as const satisfies readonly (keyof AuthUser | keyof AuthPlatformUser | keyof AuthApiKey)[])
