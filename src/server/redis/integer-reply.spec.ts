/**
 * @fileoverview The reader of an integer reply.
 *
 * @layer Test
 */

import { integerReply } from './integer-reply'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'

describe('integerReply', () => {
  // Scenario: each way a client or script spells an integer. Expected: that integer.
  it.each([
    ['a number', 3, 3],
    ['zero', 0, 0],
    ['a negative number', -2, -2],
    ['a string', '12', 12],
    ['a negative string', '-1', -1],
    ['the largest safe integer', '9007199254740991', Number.MAX_SAFE_INTEGER]
  ])('reads %s', (_label, reply, expected) => {
    expect(integerReply(reply)).toBe(expected)
  })

  // Scenario: a reply that spells no integer. Expected: `auth.internal`, never a number.
  it.each([
    ['a string spelling no number', 'OK'],
    ['an exponent string', '1e+21'],
    ['an integer past the safe range', 2 ** 53],
    ['a string past the safe range', '9007199254740992'],
    ['an empty string', ''],
    ['a blank string', ' '],
    ['a padded string', ' 1'],
    ['a hexadecimal string', '0x1'],
    ['a fraction', '1.5'],
    ['a fractional number', 1.5],
    ['a nil reply', null],
    ['no reply', undefined],
    ['a boolean', true],
    ['a symbol, which no number can be made of', Symbol('1')],
    ['an array', ['1']]
  ])('refuses %s', (_label, reply) => {
    expect(() => integerReply(reply)).toThrow(
      expect.objectContaining({
        response: { error: expect.objectContaining({ code: AUTH_ERROR_CODES.INTERNAL }) }
      })
    )
  })

  // Scenario: an operator reads the refusal. Expected: the cause names what was wrong.
  it('carries a cause that names the reply', () => {
    let thrown: unknown
    try {
      integerReply('OK')
    } catch (error) {
      thrown = error
    }
    expect((thrown as Error).cause).toEqual(
      new Error('Redis answered a reply that is not an integer')
    )
  })
})
