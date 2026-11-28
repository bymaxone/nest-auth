/**
 * @fileoverview What the owner read off a session record carries.
 */

import { sessionOwner } from './session-records'

describe('sessionOwner', () => {
  // Scenario: the record names its family. Expected: returned only in the shape a token carries.
  // Why: it goes into a key.
  it.each([
    ['3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b', { familyId: '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b' }],
    ['a:b', {}],
    [42, {}],
    [undefined, {}]
  ])('reads a family id of %p', (familyId, expected) => {
    const record = { tenantId: 'tenant-1', familyId }

    expect(sessionOwner('user-1', record)).toStrictEqual({
      userId: 'user-1',
      tenantId: 'tenant-1',
      ...expected
    })
  })

  // Scenario: the tenant is blank or not a string. Expected: absent, one shape for "no tenant".
  it.each([[''], [42], [undefined]])('reads a tenant of %p as absent', (tenantId) => {
    expect(sessionOwner('user-1', { tenantId })).toStrictEqual({
      userId: 'user-1',
      tenantId: undefined
    })
  })
})
