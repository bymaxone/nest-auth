/**
 * @fileoverview Pins what the wire contract declares for ending the access tokens of one session
 * against what this library writes.
 *
 * @layer Test
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { sessionRevocationKey, sessionRevocationTtlSeconds } from './utils/session-access'
import { isWsTicketSnapshot } from './utils/ws-ticket-snapshot'

interface RevocationContract {
  version: number
  redisKeyPrefixes: Record<string, string>
  recordEncodings: Record<string, Record<string, unknown>>
}

const contract = JSON.parse(
  readFileSync(join(__dirname, '../../conformance/wire-contract.json'), 'utf8')
) as RevocationContract

const sid = '3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a1b'

describe('the session revocation entry in the contract', () => {
  // Scenario: both planes. Expected: the declared prefixes, key form, value and lifetime. Why: the
  // entry one backend writes is the one the other has to read.
  it('writes the declared keys for the declared lifetime', () => {
    const record = contract.recordEncodings['sessionRevocation']

    expect(contract.version).toBe(9)
    expect(sessionRevocationKey('dashboard', sid)).toBe(
      `${contract.redisKeyPrefixes['dashboardSessionRevocation']}:${sid}`
    )
    expect(sessionRevocationKey('platform', sid)).toBe(
      `${contract.redisKeyPrefixes['platformSessionRevocation']}:${sid}`
    )
    expect(record?.['key']).toContain('rvs:{sid}')
    expect(record?.['key']).toContain('prvs:{sid}')
    expect(record?.['value']).toBe('1')
    expect(record?.['ttl']).toContain('plus 60')
    expect(sessionRevocationTtlSeconds('15m')).toBe(960)
  })

  // Scenario: the records that carry the family id between requests. Expected: both fields are
  // declared optional. Why: a record without them is still a record, on either backend.
  it.each([
    ['logoutPending', 'familyId'],
    ['wsTicket', 'sid']
  ])('declares %s.%s as optional', (name, field) => {
    const record = contract.recordEncodings[name]

    expect(record?.['optionalFields']).toEqual([field])
    expect(record?.['fields']).not.toContain(field)
    expect(record?.[field]).toContain('optional')
  })

  const ticketRecord = {
    sub: 'u1',
    role: 'member',
    status: 'active',
    mfaEnabled: false,
    mfaVerified: false,
    jti: 'j1',
    epoch: 0
  }

  // Scenario: a ticket record whose sid another writer got wrong. Expected: still a ticket. Why:
  // the contract reads such a value as absent, as an access token's sid is read.
  it.each([null, 7, 'a:b', ''])('keeps a record whose sid is %p a ticket', (value) => {
    expect(isWsTicketSnapshot({ ...ticketRecord, sid: value })).toBe(true)
  })

  // Scenario: an expiry outside the declared range. Expected: not a ticket.
  it.each([null, -1, 1.5, 2 ** 53, '1'])('refuses a record whose exp is %p', (value) => {
    expect(isWsTicketSnapshot({ ...ticketRecord, exp: value })).toBe(false)
  })
})
