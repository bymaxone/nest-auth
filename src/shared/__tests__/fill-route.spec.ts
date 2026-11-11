/**
 * Tests for the route filler: every value a caller supplies becomes exactly one path segment, and a
 * value that a URL parser would collapse or that would empty a segment is refused before any request.
 */

import { AUTH_ROUTES } from '../constants/routes'
import { fillRoute, pathSegment } from '../utils/fill-route'

describe('pathSegment', () => {
  it.each([
    ['a plain id', 'w1', 'w1'],
    ['a slash', 'a/b', 'a%2Fb'],
    ['a space', 'a b', 'a%20b'],
    ['a query and a fragment', 'x?y#z', 'x%3Fy%23z'],
    ['a backslash', 'a\\b', 'a%5Cb'],
    ['a percent sign', '100%', '100%25'],
    ['a non-ASCII letter', 'é', '%C3%A9'],
    ['three dots', '...', '...'],
    ['a trailing dot pair', 'a..', 'a..'],
    ['a leading dot', '.a', '.a']
  ])('encodes %s into one segment', (_name, value, encoded) => {
    expect(pathSegment('id', value)).toBe(encoded)
  })

  it.each([
    ['an empty string', ''],
    ['undefined', undefined],
    ['null', null],
    ['a number', 5],
    ['an object', {}]
  ])('refuses %s as a non-empty string', (_name, value) => {
    expect(() => pathSegment('id', value)).toThrow(new TypeError('id must be a non-empty string'))
  })

  it.each(['.', '..'])(
    'refuses the dot segment %j, which encoding cannot keep in place',
    (value) => {
      expect(() => pathSegment('id', value)).toThrow(new TypeError("id must not be '.' or '..'"))
    }
  )

  it('names the value in the message', () => {
    expect(() => pathSegment('workspaceId', '')).toThrow('workspaceId must be a non-empty string')
  })
})

describe('fillRoute', () => {
  it('fills one placeholder', () => {
    expect(fillRoute(AUTH_ROUTES.workspaces.access, { workspaceId: 'w1' })).toBe(
      'workspaces/w1/access'
    )
  })

  it('fills several placeholders, each as its own segment', () => {
    expect(fillRoute(AUTH_ROUTES.workspaces.member, { workspaceId: 'a/b', userId: 'c d' })).toBe(
      'workspaces/a%2Fb/members/c%20d'
    )
  })

  it('fills the placeholders of the session and OAuth routes a consumer calls', () => {
    expect(fillRoute(AUTH_ROUTES.sessions.revokeOne, { id: 's 1' })).toBe('sessions/s%201')
    expect(fillRoute(AUTH_ROUTES.oauth.callback, { provider: 'google' })).toBe(
      'oauth/google/callback'
    )
  })

  it('leaves a route with no placeholder as it is', () => {
    expect(fillRoute(AUTH_ROUTES.workspaces.list, {})).toBe('workspaces')
  })

  it('refuses a placeholder with no value, naming it', () => {
    expect(() => fillRoute(AUTH_ROUTES.workspaces.member, { workspaceId: 'w1' })).toThrow(
      new TypeError('userId must be a non-empty string')
    )
  })

  it('does not read a value from the prototype of the values object', () => {
    expect(() => fillRoute('x/:constructor', {})).toThrow(
      new TypeError('constructor must be a non-empty string')
    )
    expect(() => fillRoute('x/:toString', {})).toThrow(TypeError)
  })

  it.each(['.', '..', ''])('refuses %j in any position', (value) => {
    expect(() =>
      fillRoute(AUTH_ROUTES.workspaces.member, { workspaceId: 'w1', userId: value })
    ).toThrow(TypeError)
    expect(() =>
      fillRoute(AUTH_ROUTES.workspaces.member, { workspaceId: value, userId: 'u1' })
    ).toThrow(TypeError)
  })

  it('cannot be made to leave its route by a value that looks like a path', () => {
    const path = fillRoute(AUTH_ROUTES.workspaces.access, { workspaceId: '../admin' })

    expect(path).toBe('workspaces/..%2Fadmin/access')
    expect(new URL(`https://h/auth/${path}`).pathname).toBe('/auth/workspaces/..%2Fadmin/access')
  })
})
