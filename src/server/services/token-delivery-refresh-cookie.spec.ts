/**
 * @fileoverview Tests for the bound on a refresh token carried by cookie in `TokenDeliveryService`.
 */

import { Test } from '@nestjs/testing'
import type { Request } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { TokenDeliveryService } from './token-delivery.service'

const MAX_LENGTH = 2048

async function build(tokenDelivery: 'cookie' | 'both'): Promise<TokenDeliveryService> {
  const options = {
    tokenDelivery,
    jwt: { accessCookieMaxAgeMs: 900_000, refreshExpiresInDays: 7, algorithm: 'HS256' },
    cookies: {
      accessTokenName: 'access_token',
      refreshTokenName: 'refresh_token',
      sessionSignalName: 'has_session',
      refreshCookiePath: '/auth/refresh',
      sameSite: 'lax'
    }
  }
  const module = await Test.createTestingModule({
    providers: [TokenDeliveryService, { provide: BYMAX_AUTH_OPTIONS, useValue: options }]
  }).compile()
  return module.get(TokenDeliveryService)
}

function requestWith(cookie: unknown, body: unknown = {}): Request {
  return { cookies: { refresh_token: cookie }, headers: {}, body } as unknown as Request
}

describe.each(['cookie', 'both'] as const)('the refresh cookie in %s delivery', (delivery) => {
  it('refuses a cookie over the bound with a validation error naming the field', async () => {
    const service = await build(delivery)

    let thrown: unknown
    try {
      service.extractRefreshToken(requestWith('a'.repeat(MAX_LENGTH + 1)))
    } catch (error) {
      thrown = error
    }

    expect(thrown).toBeInstanceOf(AuthException)
    expect(thrown).toMatchObject({
      response: {
        error: {
          code: AUTH_ERROR_CODES.VALIDATION,
          details: [
            {
              field: 'refreshToken',
              message: 'refreshToken must be a string of 1 to 2048 characters'
            }
          ]
        }
      }
    })
  })

  it('returns a cookie of exactly the bound', async () => {
    const service = await build(delivery)
    const token = 'a'.repeat(MAX_LENGTH)

    expect(service.extractRefreshToken(requestWith(token))).toBe(token)
  })

  it('returns an empty cookie as it is, which no caller treats as a token', async () => {
    const service = await build(delivery)

    expect(service.extractRefreshToken(requestWith(''))).toBe('')
  })

  it('refuses an oversize cookie even when the body carries a valid token', async () => {
    const service = await build(delivery)
    const oversize = requestWith('a'.repeat(MAX_LENGTH + 1), { refreshToken: 'valid-token' })

    expect(() => service.extractRefreshToken(oversize)).toThrow(AuthException)
  })
})
