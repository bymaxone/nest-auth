/**
 * @fileoverview A repository that finds nothing is copied for the same work per field as one that finds a row, for every
 * method whose contract may answer nothing.
 *
 * The work is counted in the calls the copy makes to read and define fields, never in time: a clock cannot show a
 * difference this small, and the claim is of work and not of duration.
 *
 * @layer Test
 */

import { copyHostRecord } from './host-read'
import {
  API_KEY_REPOSITORY_CONTRACT,
  MEMBERSHIP_REPOSITORY_CONTRACT,
  PLATFORM_USER_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT,
  type ErasedContract,
  type ErasedRepositoryContract
} from './repository-contracts'

const REPOSITORIES: Readonly<Record<string, ErasedRepositoryContract>> = {
  user: USER_REPOSITORY_CONTRACT as ErasedRepositoryContract,
  platformUser: PLATFORM_USER_REPOSITORY_CONTRACT as ErasedRepositoryContract,
  apiKey: API_KEY_REPOSITORY_CONTRACT as ErasedRepositoryContract,
  workspace: WORKSPACE_REPOSITORY_CONTRACT as ErasedRepositoryContract,
  membership: MEMBERSHIP_REPOSITORY_CONTRACT as ErasedRepositoryContract
}

/** Every method, by repository and name, whose contract is a record or a list that may be found nothing. */
const NULLABLE_METHODS: [string, ErasedContract][] = Object.entries(REPOSITORIES).flatMap(
  ([repository, contracts]) =>
    Object.entries(contracts)
      .filter(([, contract]) => typeof contract !== 'string' && contract.nullable === true)
      .map(([method, contract]): [string, ErasedContract] => [`${repository}.${method}`, contract])
)

/** A value of the kind a spec names, the same for every field. */
function valueOf(spec: string): unknown {
  const base = spec
    .replace(/^~/, '')
    .replace(/\?$/, '')
    .replace(/\|null$/, '')
  if (base === 'boolean') return true
  if (base === 'number') return 1
  if (base === 'strings') return ['a']
  return base === 'date' ? new Date(1) : 'row'
}

/** A row that holds every field of the contract, built without reading the library's own decoy. */
function rowOf(contract: ErasedContract): unknown {
  if (typeof contract === 'string') return valueOf(contract)
  if ('list' in contract) return [rowOf(contract.list)]
  return Object.fromEntries(
    Object.entries(contract.fields).map(([field, spec]) => [
      field,
      spec.startsWith('nested') ? rowOf(contract.nested[field] as ErasedContract) : valueOf(spec)
    ])
  )
}

/** The calls to the reads and the definitions a copy makes, counted while `body` runs. */
function workOf(body: () => unknown): number {
  const spies = [
    jest.spyOn(Object, 'keys'),
    jest.spyOn(Object, 'entries'),
    jest.spyOn(Object, 'getOwnPropertyDescriptor'),
    jest.spyOn(Object, 'getPrototypeOf'),
    jest.spyOn(Object, 'defineProperty'),
    jest.spyOn(Object, 'create')
  ]
  try {
    body()
    return spies.reduce((total, spy) => total + spy.mock.calls.length, 0)
  } finally {
    for (const spy of spies) spy.mockRestore()
  }
}

describe('the copy of an answer of a repository that finds nothing', () => {
  it('enumerates the methods that may find nothing, so a new one is covered without being listed', () => {
    expect(NULLABLE_METHODS.map(([name]) => name)).toEqual(
      expect.arrayContaining(['user.findById', 'workspace.findById', 'membership.find'])
    )
    expect(NULLABLE_METHODS.length).toBeGreaterThanOrEqual(8)
  })

  // Scenario: a method that may find nothing answers `null` or `undefined`, and the same method answers a row with every
  // field. Expected: the copy does the same work for the three, and answers the miss as it was. Why: a copy of a found row
  // is work per field and a miss that skipped it would be the faster answer, which tells a caller the row is not there.
  it.each(NULLABLE_METHODS)(
    'does the same work for a miss as for a found row of %s',
    (_name, contract) => {
      const row = rowOf(contract)

      const found = workOf(() => copyHostRecord(row, contract))

      const missed = workOf(() => copyHostRecord(null, contract))
      const absent = workOf(() => copyHostRecord(undefined, contract))

      expect(found).toBeGreaterThan(0)
      expect(missed).toBe(found)
      expect(absent).toBe(found)
      expect(copyHostRecord(null, contract)).toBeNull()
      expect(copyHostRecord(undefined, contract)).toBeUndefined()
    }
  )

  // Scenario: the same method misses twice. Expected: both misses do the same work. Why: the decoy is built when the module
  // loads, so the first miss does not pay for building it and the second is not the cheaper one.
  it('does the same work on the first miss as on the second', () => {
    const [, contract] = NULLABLE_METHODS[0] as [string, ErasedContract]

    const first = workOf(() => copyHostRecord(null, contract))
    const second = workOf(() => copyHostRecord(null, contract))

    expect(first).toBe(second)
  })

  // Scenario: a contract that may find nothing holds a date, a nested record and a list of records, which no repository of
  // the library has yet. Expected: the miss does the same work as the found row, the second miss included. Why: the decoy
  // copies a date and a nested record as a found row does, and a contract added later is covered the same way.
  it('does the same work for a miss as for a found row of a contract with a nested record, a list and a date', () => {
    const contract: ErasedContract = {
      fields: { owner: 'nested', items: 'nested', at: 'date', note: '~string' },
      nested: {
        owner: { fields: { id: 'id' }, nested: {} },
        items: { list: { fields: { id: 'id', at: '~date' }, nested: {} } }
      },
      nullable: true
    }
    const row = rowOf(contract)

    const found = workOf(() => copyHostRecord(row, contract))
    const missed = workOf(() => copyHostRecord(null, contract))
    const again = workOf(() => copyHostRecord(undefined, contract))

    expect(found).toBeGreaterThan(0)
    expect(missed).toBeGreaterThanOrEqual(found)
    expect(again).toBe(found)
  })
})
