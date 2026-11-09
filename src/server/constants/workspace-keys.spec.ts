/**
 * @fileoverview Tests for the workspace subjects and the membership-cache Redis keys.
 *
 * @layer Test
 */

import {
  WORKSPACE_VERSION_RETENTION_SECONDS,
  membershipCacheKeyBase,
  membershipSubject,
  membershipVersionKey,
  workspaceSubject,
  workspaceVersionKey
} from './workspace-keys'

/** The identifier-HMAC key the wire contract pins its vectors with. */
const HMAC_KEY = '0dd66555bd2d89e0eb4ce050f1fef427bea6799bec27fb8e313f69ab965048c1'

/** Independently computed with `node:crypto`, and the same values the wire contract pins. */
const VECTORS = [
  {
    tenantId: 'tenant-1',
    workspaceId: 'ws-1',
    userId: 'user-1',
    workspaceSubject: 'wsp:8:tenant-1:4:ws-1',
    workspaceDigest: '89a04c5f97b071aa56b591f7e37dceb01b52ee8c2a71271cb267b33d24cfde2e',
    membershipSubject: 'wms:8:tenant-1:4:ws-1:user-1',
    membershipDigest: '2f327d73d12a8bec883620d297049993dd76ae8bb67bab530df39b1320f86a85'
  },
  {
    tenantId: 'a:b',
    workspaceId: 'c',
    userId: 'd',
    workspaceSubject: 'wsp:3:a:b:1:c',
    workspaceDigest: '011f691bbd27fe0938ba31ea7252013a00d652015bdbe09013f8f4894b1d1d32',
    membershipSubject: 'wms:3:a:b:1:c:d',
    membershipDigest: 'f6021fd1a75bce2006ea3ef15ca0e9b76f8b0f8933cb9c730256468b578cdf26'
  },
  {
    tenantId: 'a',
    workspaceId: 'b:c',
    userId: 'd',
    workspaceSubject: 'wsp:1:a:3:b:c',
    workspaceDigest: '85266538b8a0a5662a11c7438a1d992b811272b887538a4b144910b74130ad26',
    membershipSubject: 'wms:1:a:3:b:c:d',
    membershipDigest: 'a35441f9cf129077c814a12954483e02f8d4cfee47b0c0a84a2b228a4db6ef40'
  },
  {
    tenantId: 'açaí',
    workspaceId: 'wé',
    userId: 'u%1+x',
    workspaceSubject: 'wsp:6:açaí:3:wé',
    workspaceDigest: '1dd6af63723cd64b9cca358d7e438f67921fae276609f0923914dacd40d2cb0c',
    membershipSubject: 'wms:6:açaí:3:wé:u%1+x',
    membershipDigest: '4d4f6b2caf02eb381c25aab5c6185082cd268d2288b120bd7cb0e84d6142e3b1'
  }
]

describe('workspace subjects', () => {
  it.each(VECTORS)(
    'builds the pinned preimages for $tenantId / $workspaceId / $userId',
    (vector) => {
      expect(workspaceSubject(vector.tenantId, vector.workspaceId)).toBe(vector.workspaceSubject)
      expect(membershipSubject(vector.tenantId, vector.workspaceId, vector.userId)).toBe(
        vector.membershipSubject
      )
    }
  )

  // Without the length prefix both pairs below would read `a:b:c`.
  it('keeps two different (tenant, workspace) pairs apart', () => {
    expect(workspaceSubject('a:b', 'c')).not.toBe(workspaceSubject('a', 'b:c'))
  })

  it('keeps two different (tenant, workspace, user) triples apart', () => {
    expect(membershipSubject('a:b', 'c', 'd')).not.toBe(membershipSubject('a', 'b:c', 'd'))
    expect(membershipSubject('a', 'b', 'c:d')).not.toBe(membershipSubject('a', 'b:c', 'd'))
  })

  it('counts the length in UTF-8 bytes, not in UTF-16 code units', () => {
    // 'açaí' is 4 code units and 6 bytes.
    expect(workspaceSubject('açaí', 'w')).toBe('wsp:6:açaí:1:w')
  })

  it('does not collide the workspace subject with the membership subject', () => {
    expect(workspaceSubject('t', 'w')).not.toBe(membershipSubject('t', 'w', ''))
  })
})

describe('workspace Redis keys', () => {
  it.each(VECTORS)('derives the pinned keys for $tenantId / $workspaceId', (vector) => {
    expect(workspaceVersionKey(vector.tenantId, vector.workspaceId, HMAC_KEY)).toBe(
      `wsv:${vector.workspaceDigest}`
    )
    expect(membershipVersionKey(vector.tenantId, vector.workspaceId, vector.userId, HMAC_KEY)).toBe(
      `wmv:${vector.membershipDigest}`
    )
    expect(
      membershipCacheKeyBase(vector.tenantId, vector.workspaceId, vector.userId, HMAC_KEY)
    ).toBe(`wm:${vector.membershipDigest}`)
  })

  it('keys the same HMAC with a different key to a different name', () => {
    expect(workspaceVersionKey('t', 'w', 'key-one')).not.toBe(
      workspaceVersionKey('t', 'w', 'key-two')
    )
  })

  it('never writes an identifier in the clear', () => {
    const key = membershipVersionKey('tenant-1', 'ws-1', 'user-1', HMAC_KEY)

    expect(key).not.toContain('tenant-1')
    expect(key).not.toContain('user-1')
  })

  it('retains a version counter for thirty days', () => {
    expect(WORKSPACE_VERSION_RETENTION_SECONDS).toBe(2_592_000)
  })
})
