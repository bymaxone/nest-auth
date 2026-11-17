/**
 * @fileoverview How a refusal names the value it received: numbers as they are, anything else by its
 * type, so a secret passed to the wrong option never reaches a log.
 *
 * @layer Test
 */

import { describeReceived } from './describe-received'

describe('describeReceived', () => {
  // Scenario: a number, including the ones an operator needs to see. Expected: the number as text.
  it.each([
    [NaN, 'NaN'],
    [Infinity, 'Infinity'],
    [1e300, '1e+300'],
    [-1, '-1']
  ])('prints the number %s', (value, text) => {
    expect(describeReceived(value)).toBe(text)
  })

  // Scenario: anything that is not a number. Expected: its type, and never its content.
  it.each([
    ['hunter2', 'a string'],
    [true, 'a boolean'],
    [{ secret: 'x' }, 'an object'],
    [['x'], 'an array'],
    [null, 'null'],
    [undefined, 'undefined'],
    [() => 'x', 'a function'],
    [10n, 'a bigint']
  ])('names the type of %s', (value, text) => {
    expect(describeReceived(value)).toBe(text)
  })
})
