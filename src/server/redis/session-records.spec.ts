/**
 * @fileoverview What the owner read off a session record carries, how a family and its owner are
 * read, and what a family revocation is read to have removed.
 *
 * @layer Test
 */

import { readFamily, removedSessions, sessionOwner } from './session-records'

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

describe('removedSessions', () => {
  // Scenario: a rotation between the read and the script moved a session to a new hash. Expected:
  // every hash either side saw, each once, counted by what the script removed.
  it('names every hash of either side and counts what the script removed', () => {
    expect(removedSessions(['h1', 'h2'], ['h1', 'h3'])).toEqual({
      removed: 2,
      sessionHashes: ['h1', 'h2', 'h3']
    })
  })

  // Scenario: a reply that is no list of strings. Expected: refused. Why: read as empty, it says
  // the family held no session.
  it.each([[null], ['OK'], [2], [[1]], [['h1', null]]])('refuses the reply %p', (reply) => {
    let refusal: unknown
    try {
      removedSessions([], reply)
    } catch (err: unknown) {
      refusal = err
    }

    expect(refusal).toMatchObject({
      response: { error: { code: 'auth.internal' } },
      cause: new Error('Redis answered a reply that is not a list of members')
    })
  })
})

describe('readFamily', () => {
  const none = { userId: '', tenantId: undefined }
  const owner = { userId: 'user-1', tenantId: 'tenant-1' }

  // Scenario: the first read has a record naming the owner. Expected: no second read.
  it('reads a family once when its owner is found', async () => {
    const read = jest.fn(async () => ['h1'])

    await expect(readFamily(read, async () => owner)).resolves.toEqual({
      ...owner,
      members: ['h1']
    })
    expect(read).toHaveBeenCalledTimes(1)
  })

  // Scenario: the member read first has rotated away. Expected: the next read names the owner, and
  // the members of both reads are kept.
  it('reads again when no record names an owner', async () => {
    const read = jest.fn(async () => ['h2']).mockResolvedValueOnce(['h1'])
    const ownerOf = jest.fn(async (members: string[]) => (members.includes('h2') ? owner : none))

    await expect(readFamily(read, ownerOf)).resolves.toEqual({ ...owner, members: ['h1', 'h2'] })
    expect(read).toHaveBeenCalledTimes(2)
  })

  // Scenario: no record ever names an owner. Expected: it gives up after the third read.
  it('stops after three reads', async () => {
    const read = jest.fn(async () => ['h1'])

    await expect(readFamily(read, async () => none)).resolves.toMatchObject(none)
    expect(read).toHaveBeenCalledTimes(3)
  })
})
