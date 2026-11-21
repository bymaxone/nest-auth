/**
 * @fileoverview The contracts of the repositories at work: an answer is read for the fields its method promises and
 * for nothing else, and the tables that state those promises are checked by the compiler in both directions.
 *
 * @layer Test
 */

import {
  apiKeyRecord,
  membershipRecord,
  userRecord,
  workspaceRecord
} from './__tests__/host-records'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthApiKey, IApiKeyRepository } from '../interfaces/api-key-repository.interface'
import type {
  AuthMembership,
  IMembershipRepository,
  MembershipPage,
  MembershipWithWorkspace,
  RemoveAllMembershipsResult
} from '../interfaces/membership-repository.interface'
import type {
  AuthPlatformUser,
  IPlatformUserRepository
} from '../interfaces/platform-user-repository.interface'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import type {
  AuthWorkspace,
  CreateWorkspaceResult,
  IWorkspaceRepository
} from '../interfaces/workspace-repository.interface'
import { guardRepository } from './host-read'
import {
  API_KEY_REPOSITORY_CONTRACT,
  RECORD_CONTRACTS,
  SECURITY_FIELDS,
  MEMBERSHIP_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  type Contract,
  type FieldSpec,
  type RepositoryContract
} from './repository-contracts'

/** The host's own failure, with text a library error must never repeat. */
const fault = new Error('host-text-that-must-not-leak')

/** A getter that throws until a relation is loaded, and counts how often it was asked. */
const unloaded = (counter: { reads: number }): { get: () => never } => ({
  get: (): never => {
    counter.reads += 1
    throw new Error('relation not loaded')
  }
})

describe('an answer is read for what its method promises and for nothing else', () => {
  // Scenario: a user entity of a host ORM whose relations (`workspace`, `items`, `result`, `removed`) are getters that
  // throw until loaded, names that belong to the contracts of other repositories. Expected: the lookup answers, the
  // fields of the user arrive, no relation is asked. Why: a lookup that read a name from any other contract would
  // turn every login into the internal error for a host whose relation is not loaded.
  it('copies a user whose relations are unloaded getters named like fields of other contracts', async () => {
    const counter = { reads: 0 }
    class UserEntity {
      constructor() {
        Object.assign(this, userRecord())
      }
    }
    const entity = new UserEntity()
    for (const relation of ['workspace', 'items', 'result', 'removed', 'label'])
      Object.defineProperty(UserEntity.prototype, relation, unloaded(counter))
    const guarded = guardRepository(
      { findById: async (): Promise<unknown> => entity },
      USER_REPOSITORY_CONTRACT
    )

    const answered = (await guarded.findById()) as { id: string; email: string }

    expect(answered.id).toBe('u1')
    expect(answered.email).toBe('a@b.c')
    expect(counter.reads).toBe(0)
  })

  // Scenario: a plain membership whose `workspace` is a relation that throws until loaded; `workspace` belongs to the
  // contract of a membership read with its workspace, not to this one. Expected: the lookup answers, and the same
  // membership inside a page of a workspace answers too. Why: a name of another result must not be read from this one.
  it('copies a plain membership whose workspace relation is unloaded', async () => {
    const counter = { reads: 0 }
    class Membership {
      constructor() {
        Object.assign(this, membershipRecord())
      }
    }
    Object.defineProperty(Membership.prototype, 'workspace', unloaded(counter))
    const membership = new Membership()
    const guarded = guardRepository(
      {
        find: async (): Promise<unknown> => membership,
        listForWorkspace: async (): Promise<unknown> => ({ items: [membership], nextCursor: null })
      },
      MEMBERSHIP_REPOSITORY_CONTRACT
    )

    const found = (await guarded.find()) as { role: string }
    const page = (await guarded.listForWorkspace()) as { items: { role: string }[] }

    expect(found.role).toBe('MEMBER')
    expect(page.items[0]?.role).toBe('MEMBER')
    expect(counter.reads).toBe(0)
  })

  // Scenario: an API key record with relations that throw until loaded (`status`, `workspace`, `owner`). Expected:
  // the lookup, the creation and the list answer, and no relation is asked. Why: the API key contract has none of
  // these names.
  it('copies an API key whose relations are unloaded', async () => {
    const counter = { reads: 0 }
    class ApiKey {
      constructor() {
        Object.assign(this, apiKeyRecord({ label: 'ci' }))
      }
    }
    for (const relation of ['status', 'workspace', 'owner'])
      Object.defineProperty(ApiKey.prototype, relation, unloaded(counter))
    const key = new ApiKey()
    const guarded = guardRepository(
      {
        findById: async (): Promise<unknown> => key,
        create: async (): Promise<unknown> => key,
        listByLabel: async (): Promise<unknown> => [key, key]
      },
      API_KEY_REPOSITORY_CONTRACT
    )

    const found = (await guarded.findById()) as { label: string }
    const created = (await guarded.create()) as { label: string }
    const listed = (await guarded.listByLabel()) as { label: string }[]

    expect([found.label, created.label, listed[1]?.label]).toEqual(['ci', 'ci', 'ci'])
    expect(counter.reads).toBe(0)
  })

  // Scenario: the workspace inside a page of memberships is read by the contract of a workspace, and a relation of it
  // that throws is left alone. Expected: the page answers with the workspace's fields. Why: the contract follows the
  // path, down to the nested record.
  it('applies the contract of the nested workspace inside a page', async () => {
    const counter = { reads: 0 }
    class Workspace {
      constructor() {
        Object.assign(this, workspaceRecord({ createdAt: new Date(5) }))
      }
    }
    Object.defineProperty(Workspace.prototype, 'members', unloaded(counter))
    const item = { ...membershipRecord({ role: 'ADMIN' }), workspace: new Workspace() }
    const guarded = guardRepository(
      { listForUser: async (): Promise<unknown> => ({ items: [item], nextCursor: null }) },
      MEMBERSHIP_REPOSITORY_CONTRACT
    )

    const page = (await guarded.listForUser()) as { items: { workspace: { name: string } }[] }

    expect(page.items[0]?.workspace.name).toBe('W')
    expect(counter.reads).toBe(0)
  })

  // Scenario: a field the contract names whose getter throws. Expected: the lookup rejects with the internal error and
  // the fault as its cause. Why: the host owes what the contract promises, so a failure there is a refusal and never a
  // value that is quietly missing, which would fail open on a field like `mfaEnabled` or `status`.
  it('still refuses when a field of the contract throws', async () => {
    const entity = Object.defineProperty(userRecord(), 'mfaEnabled', {
      get(): boolean {
        throw fault
      },
      enumerable: true
    })
    const guarded = guardRepository(
      { findById: async (): Promise<unknown> => entity },
      USER_REPOSITORY_CONTRACT
    )

    const read = guarded.findById()

    await expect(read).rejects.toBeInstanceOf(AuthException)
    await expect(read).rejects.toMatchObject({ cause: fault })
    const error = (await read.catch((caught: unknown) => caught)) as AuthException
    expect((error.getResponse() as { error: { code: string } }).error.code).toBe(
      AUTH_ERROR_CODES.INTERNAL
    )
  })
})

describe('the tables of contracts are checked by the compiler', () => {
  type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
  type NotAssignable<A, B> = [A] extends [B] ? false : true
  type RecordContract<R> = Extract<Contract<R>, { fields: unknown }>
  type KeysOfContract<R> = keyof RecordContract<R>['fields']

  // Scenario: the shape a table has to take, stated as types. Expected: the methods a table must hold are exactly the
  // methods of each repository interface, the fields of an entry are exactly the keys of each record the repositories
  // answer with, and a table that leaves a method out or an entry that leaves a key out is not assignable. Why: a
  // method or a field added to an interface must not be forgotten in the table, and a misspelt one must not be
  // silently ignored. Each constant below fails to compile if its claim stops holding, so `typecheck` is the assertion.
  it('holds exactly the methods of each interface and exactly the keys of each record', () => {
    const methods: [
      Same<keyof RepositoryContract<IUserRepository>, keyof IUserRepository>,
      Same<keyof RepositoryContract<IPlatformUserRepository>, keyof IPlatformUserRepository>,
      Same<keyof RepositoryContract<IApiKeyRepository>, keyof IApiKeyRepository>,
      Same<keyof RepositoryContract<IWorkspaceRepository>, keyof IWorkspaceRepository>,
      Same<keyof RepositoryContract<IMembershipRepository>, keyof IMembershipRepository>
    ] = [true, true, true, true, true]
    const fields: [
      Same<KeysOfContract<AuthUser>, keyof AuthUser>,
      Same<KeysOfContract<AuthPlatformUser>, keyof AuthPlatformUser>,
      Same<KeysOfContract<AuthApiKey>, keyof AuthApiKey>,
      Same<KeysOfContract<AuthWorkspace>, keyof AuthWorkspace>,
      Same<KeysOfContract<AuthMembership>, keyof AuthMembership>,
      Same<KeysOfContract<MembershipWithWorkspace>, keyof MembershipWithWorkspace>,
      Same<KeysOfContract<MembershipPage<AuthMembership>>, keyof MembershipPage<AuthMembership>>,
      Same<KeysOfContract<RemoveAllMembershipsResult>, 'result' | 'removed' | 'workspaceIds'>,
      Same<KeysOfContract<CreateWorkspaceResult>, 'status' | 'workspace'>
    ] = [true, true, true, true, true, true, true, true, true]
    const missingMethod: NotAssignable<
      Pick<RepositoryContract<IUserRepository>, 'findById'>,
      RepositoryContract<IUserRepository>
    > = true
    const forgottenField: NotAssignable<
      { fields: { id: true }; nested: object },
      Contract<AuthUser>
    > = true

    expect([methods, fields, missingMethod, forgottenField].flat()).not.toContain(false)
  })

  // Scenario: the kind a field is read as, stated as types. Expected: a required field has no `?`, an optional one has
  // it, `null` is spelled `|null` only where the interface promises it, and a kind of the wrong type is not assignable.
  // Why: the kind is what refuses a wrapper, a missing field or garbage, so it has to follow the interface exactly.
  it('gives each field the kind of its type, with its absence and its null', () => {
    const kinds: [
      Same<FieldSpec<boolean>, 'boolean'>,
      Same<FieldSpec<AuthUser['mfaEnabled']>, 'boolean'>,
      Same<FieldSpec<AuthUser['mfaSecret']>, 'string?' | '~id' | '~string'>,
      Same<FieldSpec<AuthUser['passwordHash']>, 'string|null' | '~id' | '~string'>,
      Same<FieldSpec<AuthUser['lastLoginAt']>, 'date|null' | '~date'>,
      Same<FieldSpec<AuthUser['mfaRecoveryCodes']>, 'strings?'>,
      Same<FieldSpec<AuthApiKey['scopes']>, 'strings'>,
      Same<FieldSpec<MembershipWithWorkspace['workspace']>, 'nested'>,
      Same<FieldSpec<AuthUser['createdAt']>, 'date' | '~date'>
    ] = [true, true, true, true, true, true, true, true, true]
    const wrongKinds: [
      NotAssignable<'string', FieldSpec<boolean>>,
      NotAssignable<'boolean', FieldSpec<string>>,
      NotAssignable<'string', FieldSpec<AuthUser['mfaSecret']>>,
      NotAssignable<'boolean?', FieldSpec<AuthUser['mfaEnabled']>>,
      NotAssignable<'date', FieldSpec<AuthUser['lastLoginAt']>>,
      NotAssignable<'string', FieldSpec<AuthUser['passwordHash']>>
    ] = [true, true, true, true, true, true]

    expect([kinds, wrongKinds].flat()).not.toContain(false)
  })

  // Scenario: the fields that decide an admission, listed with the contracts. Expected: each is a key of its record and
  // none is lenient, at the type level (the literal of the table is not `~`) and in the data. Why: a lenient field lets a
  // wrapper, an absence or an object of the host through, which is right for a name and wrong for `mfaEnabled`.
  it('keeps every field that decides an admission strict', () => {
    type Strict<T> = T extends `~${string}` ? false : true
    const contracts = RECORD_CONTRACTS
    const types: [
      Strict<(typeof contracts)['user']['fields']['mfaEnabled']>,
      Strict<(typeof contracts)['user']['fields']['emailVerified']>,
      Strict<(typeof contracts)['user']['fields']['status']>,
      Strict<(typeof contracts)['platformUser']['fields']['mfaEnabled']>,
      Strict<(typeof contracts)['apiKey']['fields']['expiresAt']>,
      Strict<(typeof contracts)['apiKey']['fields']['revokedAt']>,
      Strict<(typeof contracts)['workspace']['fields']['deletionScheduledAt']>,
      Strict<(typeof contracts)['membership']['fields']['role']>
    ] = [true, true, true, true, true, true, true, true]

    for (const [record, names] of Object.entries(SECURITY_FIELDS)) {
      const fields = (contracts as Record<string, { fields: Record<string, string> }>)[record]
        ?.fields
      for (const name of names) expect(fields?.[name]).not.toMatch(/^~/u)
    }
    expect(types).not.toContain(false)
  })
})
