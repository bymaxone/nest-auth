/**
 * @fileoverview The optional expiry of a stored WebSocket ticket. The required fields are covered
 * through `redeemWsTicket` in `auth-redis.service.spec.ts`.
 *
 * @layer Test
 */

import { isWsTicketSnapshot } from './ws-ticket-snapshot'

const required = {
  sub: 'u',
  role: 'r',
  status: 's',
  mfaEnabled: false,
  mfaVerified: false,
  jti: 'j',
  epoch: 0
}

describe('isWsTicketSnapshot and exp', () => {
  // `exp` is additive, so a record with it and a record without it are both tickets.
  it.each([
    ['no exp', {}],
    ['an exp of 0', { exp: 0 }],
    ['an exp in seconds', { exp: 1_700_000_900 }]
  ])('accepts a record with %s', (_label, extra) => {
    expect(isWsTicketSnapshot({ ...required, ...extra })).toBe(true)
  })

  it.each([
    ['a string', '9'],
    ['negative', -1],
    ['fractional', 1.5],
    ['null', null]
  ])('refuses a record whose exp is %s', (_label, exp) => {
    expect(isWsTicketSnapshot({ ...required, exp })).toBe(false)
  })
})
