/**
 * @fileoverview Unit tests for the removal of rotation grace pointers.
 *
 * @layer Test
 */

import { deleteGracePointers } from './delete-grace-pointers'
import type { AuthRedisService } from '../redis/auth-redis.service'

describe('deleteGracePointers', () => {
  // Scenario: an index holding sessions and grace pointers. Expected: only the pointers go, from
  // the store and from the index.
  it('removes the pointers and nothing else', async () => {
    const del = jest.fn(async () => true)
    const srem = jest.fn(async () => 1)

    await deleteGracePointers({ del, srem }, 'sess:x', ['rt:a', 'rp:b'])

    expect(del.mock.calls).toEqual([['rp:b']])
    expect(srem.mock.calls).toEqual([['sess:x', 'rp:b']])
  })
})
