/**
 * @fileoverview Tests for the hook context a dashboard route builds.
 *
 * @layer Test
 */

import type { Request } from 'express'

import { dashboardHookContext } from './request-hook-context'

function requestWith(headers: Record<string, unknown>): Request {
  return {
    headers,
    socket: { remoteAddress: '203.0.113.9' },
    ip: '203.0.113.9'
  } as unknown as Request
}

describe('dashboardHookContext', () => {
  it('names the plane, the caller and the tenant', () => {
    const context = dashboardHookContext(requestWith({}), { sub: 'u1', tenantId: 't1' })

    expect(context).toMatchObject({ plane: 'dashboard', userId: 'u1', tenantId: 't1' })
  })

  it('carries the user agent, and an empty one when the request has none', () => {
    const caller = { sub: 'u1', tenantId: 't1' }

    expect(dashboardHookContext(requestWith({ 'user-agent': 'jest' }), caller).userAgent).toBe(
      'jest'
    )
    expect(dashboardHookContext(requestWith({}), caller).userAgent).toBe('')
  })

  it('sanitizes the headers it hands on', () => {
    const context = dashboardHookContext(
      requestWith({ authorization: 'Bearer secret', 'x-trace': 'abc' }),
      { sub: 'u1', tenantId: 't1' }
    )

    expect(context.sanitizedHeaders).toEqual({ 'x-trace': 'abc' })
  })

  it('resolves the client address from the request', () => {
    const context = dashboardHookContext(requestWith({}), { sub: 'u1', tenantId: 't1' })

    expect(context.ip).toBe('203.0.113.9')
  })
})
