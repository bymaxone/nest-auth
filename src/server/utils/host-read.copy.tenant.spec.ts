/**
 * @fileoverview The tenant of a record is a string and nothing else: it is compared to decide access and it is written
 * into the claims of a token, where an object that serializes to `{}` would make two tenants one.
 *
 * @layer Test
 */

import { membershipRecord, userRecord, workspaceRecord } from './__tests__/host-records'
import { copyHostRecord } from './host-read'
import {
  MEMBERSHIP_REPOSITORY_CONTRACT,
  USER_REPOSITORY_CONTRACT,
  WORKSPACE_REPOSITORY_CONTRACT
} from './repository-contracts'

const WRONG_KIND = 'the answer holds a value that is not the kind its method promises'

class DriverId {
  toString(): string {
    return 'a1'
  }
}

/** What a host could serve as a tenant that is not a string, or a string with nothing in it. */
const NOT_A_TENANT: readonly (readonly [string, unknown])[] = [
  ['a Date', new Date(0)],
  ['a Map', new Map()],
  ['an object with a plain prototype', Object.create({}) as object],
  ['an instance of a class with toString', new DriverId()],
  ['a finite number', 42],
  ['an empty string', ''],
  ['a string of spaces', '   '],
  ['a string of line breaks and tabs', '\n\t ']
]

/** The reason a copy ended in, or undefined when it ended in none. */
const causeOf = (thunk: () => unknown): unknown => {
  try {
    thunk()
  } catch (error) {
    return (error as { cause?: Error }).cause?.message
  }
  return undefined
}

describe('the tenant of a record', () => {
  // Scenario: a user, a workspace and a membership whose `tenantId` is a Date, a Map, an object that inherits from a
  // plain object, an instance of a class that has toString, and a number. Expected: each is refused with the library's
  // reason. Why: two tenants whose ids are Maps both serialize to `{}` in a token claim, so an id that is not a string
  // would conflate tenants for whoever reads the claim, and a comparison with `===` is not the only place it flows.
  it.each(NOT_A_TENANT)(
    'refuses %s as the tenant of a user, a workspace and a membership',
    (_name, tenant) => {
      const asked = [
        () =>
          copyHostRecord(
            userRecord({ tenantId: tenant as never }),
            USER_REPOSITORY_CONTRACT.findById
          ),
        () =>
          copyHostRecord(
            workspaceRecord({ tenantId: tenant as never }),
            WORKSPACE_REPOSITORY_CONTRACT.findById
          ),
        () =>
          copyHostRecord(
            membershipRecord({ tenantId: tenant as never }),
            MEMBERSHIP_REPOSITORY_CONTRACT.find
          )
      ]

      for (const ask of asked) expect(causeOf(ask)).toBe(WRONG_KIND)
    }
  )

  // Scenario: the same three records with a string tenant. Expected: each is copied with the tenant it names. Why: the
  // refusal above is of the kind, not of the field.
  it('copies a string tenant of a user, a workspace and a membership', () => {
    const user = copyHostRecord(userRecord({ tenantId: 'acme' }), USER_REPOSITORY_CONTRACT.findById)
    const workspace = copyHostRecord(
      workspaceRecord({ tenantId: 'acme' }),
      WORKSPACE_REPOSITORY_CONTRACT.findById
    )
    const membership = copyHostRecord(
      membershipRecord({ tenantId: 'acme' }),
      MEMBERSHIP_REPOSITORY_CONTRACT.find
    )

    expect(
      [user, workspace, membership].map((copy) => (copy as { tenantId: string }).tenantId)
    ).toEqual(['acme', 'acme', 'acme'])
  })
})
