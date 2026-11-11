/**
 * Tests for the one slash trimmer: the ends of a string are stripped, the inside is left alone, a
 * long run of slashes costs linear time, and the leading run is kept when asked.
 */

import { trimSlashes } from '../utils/trim-slashes'

describe('trimSlashes', () => {
  it.each([
    ['', ''],
    ['/', ''],
    ['//', ''],
    ['///', ''],
    ['/a/', 'a'],
    ['a', 'a'],
    ['/api/', 'api'],
    ['////a////', 'a'],
    ['a/b', 'a/b'],
    ['/a//b/', 'a//b'],
    ['a///', 'a'],
    ['///a', 'a']
  ])('trims both ends of %j to %j', (value, trimmed) => {
    expect(trimSlashes(value)).toBe(trimmed)
    expect(trimSlashes(value, true)).toBe(trimmed)
  })

  it.each([
    ['', ''],
    ['/', ''],
    ['//', ''],
    ['/a/', '/a'],
    ['a', 'a'],
    ['/api/', '/api'],
    ['////a////', '////a'],
    ['a///', 'a'],
    ['///a', '///a']
  ])('keeps the leading run of %j when asked, giving %j', (value, trimmed) => {
    expect(trimSlashes(value, false)).toBe(trimmed)
  })

  it('does not touch another character at the ends', () => {
    expect(trimSlashes('\\a\\')).toBe('\\a\\')
    expect(trimSlashes(' /a/ ')).toBe(' /a/ ')
  })

  it('takes linear time on a long run of slashes', () => {
    const hostile = `a${'/'.repeat(200_000)}b`
    const started = performance.now()

    expect(trimSlashes(hostile)).toBe(hostile)
    expect(trimSlashes(`${'/'.repeat(200_000)}a${'/'.repeat(200_000)}`)).toBe('a')
    expect(trimSlashes('/'.repeat(200_000), false)).toBe('')

    expect(performance.now() - started).toBeLessThan(250)
  })
})
