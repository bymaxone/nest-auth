/**
 * @fileoverview Tests for the `SameSite` attribute of the refresh cookie issued by
 * TokenDeliveryService: Strict unless the deployment is cross-site (`none`), independent of the
 * value the other auth cookies follow.
 */

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { TokenDeliveryService } from './token-delivery.service'

type SameSite = 'lax' | 'strict' | 'none'
type CookieCall = [string, string, Record<string, unknown>]

const AUTH_RESULT = {
  user: {
    id: 'user-1',
    email: 'user@example.com',
    name: 'Test User',
    role: 'member',
    status: 'active',
    tenantId: 'tenant-1',
    emailVerified: true,
    mfaEnabled: false,
    lastLoginAt: null,
    createdAt: new Date('2026-01-01')
  },
  accessToken: 'access.jwt.token',
  rawRefreshToken: 'raw-refresh-uuid'
}

async function buildService(sameSite: SameSite): Promise<TokenDeliveryService> {
  const options = {
    tokenDelivery: 'cookie',
    secureCookies: sameSite === 'none',
    jwt: { accessCookieMaxAgeMs: 900_000, refreshExpiresInDays: 7, algorithm: 'HS256' },
    cookies: {
      accessTokenName: 'access_token',
      refreshTokenName: 'refresh_token',
      sessionSignalName: 'has_session',
      refreshCookiePath: '/auth/refresh',
      sameSite
    }
  }
  const module = await Test.createTestingModule({
    providers: [TokenDeliveryService, { provide: BYMAX_AUTH_OPTIONS, useValue: options }]
  }).compile()
  return module.get(TokenDeliveryService)
}

function makeRes() {
  return { cookie: jest.fn(), clearCookie: jest.fn() }
}

const REQ = { cookies: {}, headers: {}, hostname: 'example.com', body: {} } as unknown as Request

function sameSiteOf(calls: CookieCall[], name: string): unknown {
  return calls.find((c) => c[0] === name)?.[2]['sameSite']
}

describe('TokenDeliveryService — refresh cookie SameSite', () => {
  // Scenario: the default posture (`lax`) is configured. Expected: the refresh cookie is
  // Strict while the access and session-signal cookies keep following the configured value.
  // Why: the refresh cookie is only ever read by the refresh route, so Strict withholds it from
  // every cross-site request at no cost, while Lax on the access cookie is what the OAuth return
  // trip needs.
  it('issues the refresh cookie Strict when the configured value is lax', async () => {
    const service = await buildService('lax')
    const res = makeRes()

    service.deliverAuthResponse(res as unknown as Response, AUTH_RESULT, REQ)

    const calls = res.cookie.mock.calls as CookieCall[]
    expect(sameSiteOf(calls, 'refresh_token')).toBe('strict')
    expect(sameSiteOf(calls, 'access_token')).toBe('lax')
    expect(sameSiteOf(calls, 'has_session')).toBe('lax')
  })

  // Scenario: `strict` is configured. Expected: every cookie is Strict.
  it('issues every cookie Strict when the configured value is strict', async () => {
    const service = await buildService('strict')
    const res = makeRes()

    service.deliverAuthResponse(res as unknown as Response, AUTH_RESULT, REQ)

    const calls = res.cookie.mock.calls as CookieCall[]
    expect(sameSiteOf(calls, 'refresh_token')).toBe('strict')
    expect(sameSiteOf(calls, 'access_token')).toBe('strict')
    expect(sameSiteOf(calls, 'has_session')).toBe('strict')
  })

  // Scenario: `none` is configured (a cross-site topology). Expected: the refresh cookie follows
  // it. Why: a browser does not send a Strict cookie on a cross-site request, so the refresh
  // call of a deployment whose frontend sits on another site would carry no credential at all.
  it('lets the refresh cookie follow a configured none', async () => {
    const service = await buildService('none')
    const res = makeRes()

    service.deliverAuthResponse(res as unknown as Response, AUTH_RESULT, REQ)

    const calls = res.cookie.mock.calls as CookieCall[]
    expect(sameSiteOf(calls, 'refresh_token')).toBe('none')
    expect(sameSiteOf(calls, 'access_token')).toBe('none')
  })

  // Scenario: a session is cleared under the default posture. Expected: the refresh cookie's
  // clear carries the same SameSite it was issued with, the signal cookie's the configured one.
  // Why: RFC 6265bis lets an overwrite replace a cookie only with the same or a stricter
  // SameSite, so a clear that is looser than the plant can be ignored.
  it('clears the refresh cookie with the SameSite it was issued with', async () => {
    const service = await buildService('lax')
    const res = makeRes()

    service.clearAuthSession(res as unknown as Response, REQ)

    const calls = res.clearCookie.mock.calls as Array<[string, Record<string, unknown>]>
    const clearedWith = (name: string): unknown => calls.find((c) => c[0] === name)?.[1]['sameSite']
    expect(clearedWith('refresh_token')).toBe('strict')
    expect(clearedWith('has_session')).toBe('lax')
  })
})
