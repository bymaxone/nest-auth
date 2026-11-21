/**
 * @fileoverview The contracts of the repositories at work: an answer is read for the fields its method promises and
 * for nothing else, and the tables that state those promises are checked by the compiler in both directions.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import type { AuthUser, IUserRepository } from '../interfaces/user-repository.interface'
import { guardRepository } from './host-read'
import {
  API_KEY_REPOSITORY_CONTRACT,
  MEMBERSHIP_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  type Contract,
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
      id = 'u1'
      email = 'a@b.c'
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
      tenantId = 't1'
      workspaceId = 'w1'
      userId = 'u1'
      role = 'MEMBER'
      status = 'ACTIVE'
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
      id = 'k1'
      label = 'ci'
      digest = 'd'
      scopes = ['read']
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
      id = 'w1'
      tenantId = 't1'
      name = 'W'
      status = 'ACTIVE'
      createdAt = new Date(5)
      deletionScheduledAt = null
    }
    Object.defineProperty(Workspace.prototype, 'members', unloaded(counter))
    const item = {
      tenantId: 't1',
      workspaceId: 'w1',
      userId: 'u1',
      role: 'ADMIN',
      status: 'ACTIVE',
      invitedByUserId: null,
      createdAt: new Date(1),
      updatedAt: new Date(2),
      workspace: new Workspace()
    }
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
    const entity = {
      id: 'u1',
      get mfaEnabled(): boolean {
        throw fault
      }
    }
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

  // Scenario: the shape a table has to take, stated as types. Expected: the methods a table must hold are exactly the
  // methods of the repository interface, the fields of an entry are exactly the keys of the record, and a table that
  // leaves a method out or an entry that leaves a key out is not assignable. Why: a method or a field added to an
  // interface must not be forgotten in the table, and a misspelt one must not be silently ignored. Each constant
  // below fails to compile if its claim stops holding, so `typecheck` is the assertion.
  it('holds exactly the methods of the interface and exactly the keys of the record', () => {
    const methods: Same<keyof RepositoryContract<IUserRepository>, keyof IUserRepository> = true
    const fields: Same<keyof RecordContract<AuthUser>['fields'], keyof AuthUser> = true
    const missingMethod: NotAssignable<
      Pick<RepositoryContract<IUserRepository>, 'findById'>,
      RepositoryContract<IUserRepository>
    > = true
    const forgottenField: NotAssignable<
      { fields: { id: true }; nested: object },
      Contract<AuthUser>
    > = true

    expect([methods, fields, missingMethod, forgottenField]).toEqual([true, true, true, true])
  })
})
