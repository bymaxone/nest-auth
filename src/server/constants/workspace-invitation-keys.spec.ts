/**
 * @fileoverview Tests for the workspace invitation key builders: the exact preimages and key
 * shapes, which rust-auth reproduces byte for byte.
 *
 * @layer Test
 */

import {
  invitationEmailSubject,
  invitationIndexKey,
  invitationKey,
  invitationKeyOfHash,
  invitationSetKey,
  inviterRateKey,
  inviterRateSubject
} from './workspace-invitation-keys'
import { workspaceSubject } from './workspace-keys'
import { hmacSha256, sha256 } from '../crypto/secure-token'

const HMAC_KEY = 'k'.repeat(64)

describe('workspace invitation subjects', () => {
  it('length-prefixes tenant and workspace in UTF-8 bytes and leaves the address last', () => {
    expect(invitationEmailSubject('t1', 'w1', 'a@example.com')).toBe('wie:2:t1:2:w1:a@example.com')
    expect(invitationEmailSubject('té', 'w1', 'a@example.com')).toBe('wie:3:té:2:w1:a@example.com')
  })

  it('does not collide for two tuples that concatenate alike', () => {
    expect(invitationEmailSubject('a', 'bc', 'x@y.z')).not.toBe(
      invitationEmailSubject('ab', 'c', 'x@y.z')
    )
  })

  it('length-prefixes the tenant of an inviter counter and leaves the user last', () => {
    expect(inviterRateSubject('t1', 'u1')).toBe('wir:2:t1:u1')
    expect(inviterRateSubject('té', 'u1')).toBe('wir:3:té:u1')
  })
})

describe('workspace invitation keys', () => {
  it('names a record by the digest of its token, from the token or from the digest', () => {
    expect(invitationKey('abc')).toBe(`winv:${sha256('abc')}`)
    expect(invitationKeyOfHash('d1')).toBe('winv:d1')
  })

  it('names the index by the HMAC of the address subject', () => {
    expect(invitationIndexKey('t1', 'w1', 'a@example.com', HMAC_KEY)).toBe(
      `winvidx:${hmacSha256('wie:2:t1:2:w1:a@example.com', HMAC_KEY)}`
    )
  })

  it('names the pending set by the HMAC of the workspace subject', () => {
    expect(invitationSetKey('t1', 'w1', HMAC_KEY)).toBe(
      `winvset:${hmacSha256(workspaceSubject('t1', 'w1'), HMAC_KEY)}`
    )
  })

  it('names the inviter counter by the HMAC of the inviter subject', () => {
    expect(inviterRateKey('t1', 'u1', HMAC_KEY)).toBe(
      `winvrl:${hmacSha256('wir:2:t1:u1', HMAC_KEY)}`
    )
  })
})
