/**
 * @fileoverview Tests for reading the workspace a request names.
 *
 * @layer Test
 */

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { resolveRequestWorkspace } from './resolve-request-workspace'
import type { WorkspaceRouteRequest } from './resolve-request-workspace'

/** A request carrying the given route parameters. */
function request(params?: Record<string, unknown>): WorkspaceRouteRequest {
  return { headers: {}, url: '/x', hostname: 'h', ...(params === undefined ? {} : { params }) }
}

/** Runs the resolver and returns the thrown exception's code and details. */
function failure(fn: () => unknown): { code: string; details: unknown } {
  try {
    fn()
  } catch (error) {
    const response = (error as AuthException).getResponse() as {
      error: { code: string; details: unknown }
    }
    return { code: response.error.code, details: response.error.details }
  }
  throw new Error('expected the resolver to throw')
}

describe('resolveRequestWorkspace', () => {
  it('reads the workspace from the route parameter', () => {
    expect(resolveRequestWorkspace(request({ workspaceId: 'w1' }), undefined)).toBe('w1')
  })

  it('reads the workspace from the host resolver when the route names none', () => {
    expect(resolveRequestWorkspace(request(), () => 'w2')).toBe('w2')
  })

  it('hands the host resolver the request itself', () => {
    const seen = request({ other: 'x' })
    const resolver = jest.fn().mockReturnValue('w1')

    resolveRequestWorkspace(seen, resolver)

    expect(resolver).toHaveBeenCalledWith(seen)
  })

  it('accepts the route and the resolver agreeing', () => {
    expect(resolveRequestWorkspace(request({ workspaceId: 'w1' }), () => 'w1')).toBe('w1')
  })

  it('refuses a request that names no workspace', () => {
    expect(failure(() => resolveRequestWorkspace(request(), undefined)).code).toBe(
      AUTH_ERROR_CODES.WORKSPACE_REQUIRED
    )
    expect(failure(() => resolveRequestWorkspace(request({}), () => undefined)).code).toBe(
      AUTH_ERROR_CODES.WORKSPACE_REQUIRED
    )
  })

  it('refuses two disagreeing answers, naming the field', () => {
    const result = failure(() =>
      resolveRequestWorkspace(request({ workspaceId: 'w1' }), () => 'w2')
    )

    expect(result.code).toBe(AUTH_ERROR_CODES.VALIDATION)
    expect(result.details).toEqual([
      {
        field: 'workspaceId',
        message: 'workspaceId differs between the route and the request resolver'
      }
    ])
  })

  it.each([
    ['an empty id', ''],
    ['a non-string id', 42],
    ['an id with a control character', 'w\u0000x'],
    ['an id over the length bound', 'w'.repeat(129)]
  ])('refuses %s from the route', (_name, value) => {
    const result = failure(() =>
      resolveRequestWorkspace(request({ workspaceId: value }), undefined)
    )

    expect(result.code).toBe(AUTH_ERROR_CODES.VALIDATION)
    expect(result.details).toEqual([
      {
        field: 'workspaceId',
        message: 'workspaceId must be 1 to 128 characters with no control characters'
      }
    ])
  })

  it('accepts an id at the length bound', () => {
    const id = 'w'.repeat(128)

    expect(resolveRequestWorkspace(request({ workspaceId: id }), undefined)).toBe(id)
  })

  it('refuses a malformed id from the host resolver', () => {
    const resolver = (): string => 7 as unknown as string

    expect(failure(() => resolveRequestWorkspace(request(), resolver)).code).toBe(
      AUTH_ERROR_CODES.VALIDATION
    )
  })

  it('never reads the body, the query or a header', () => {
    const hostile = {
      ...request(),
      headers: { 'x-workspace-id': 'w1' },
      body: { workspaceId: 'w1' },
      query: { workspaceId: 'w1' }
    }

    expect(failure(() => resolveRequestWorkspace(hostile, undefined)).code).toBe(
      AUTH_ERROR_CODES.WORKSPACE_REQUIRED
    )
  })
})
