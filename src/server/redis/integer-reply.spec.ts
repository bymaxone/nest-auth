/**
 * @fileoverview The reader of an integer reply.
 *
 * @layer Test
 */

import { integerReply } from './integer-reply'

describe('integerReply', () => {
  // Scenario: each shape a client or script can answer. Expected: the integer it spells, else 0.
  it.each([
    ['a number', 3, 3],
    ['a negative number', -2, -2],
    ['a string', '12', 12],
    ['a negative string', '-1', -1],
    ['a string spelling no number', 'OK', 0],
    ['a fraction', '1.5', 0],
    ['a nil reply', null, 0],
    ['no reply', undefined, 0],
    ['a boolean', true, 0],
    ['an array', ['1'], 0]
  ])('reads %s', (_label, reply, expected) => {
    expect(integerReply(reply)).toBe(expected)
  })
})
