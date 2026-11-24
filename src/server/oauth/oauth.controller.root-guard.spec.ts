/**
 * @fileoverview The OAuth routes refuse while a key is planted on `Object.prototype`: the callback reads the redirect options
 * and answers with a redirect, so a planted `errorRedirectUrl` must not be what a failed callback sends the browser to.
 *
 * @layer Test
 */

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import type { ResolvedOptions } from '../config/resolved-options'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { OAuthController } from './oauth.controller'
import { OAuthService } from './oauth.service'

const service = { initiateOAuth: jest.fn(), handleCallback: jest.fn() }

describe('OAuthController while a key is planted on Object.prototype', () => {
  let controller: OAuthController
  const res = Object.assign({} as Response, {
    redirect: jest.fn(),
    cookie: jest.fn(),
    clearCookie: jest.fn()
  })
  const req = Object.assign({} as Request, { ip: '1.2.3.4', headers: {}, cookies: {} })

  beforeEach(async () => {
    jest.resetAllMocks()
    const module = await Test.createTestingModule({
      controllers: [OAuthController],
      providers: [
        { provide: OAuthService, useValue: service },
        { provide: TokenDeliveryService, useValue: {} },
        {
          provide: BYMAX_AUTH_OPTIONS,
          useValue: Object.assign({} as ResolvedOptions, {
            routePrefix: 'auth',
            secureCookies: false,
            cookies: {}
          })
        }
      ]
    })
      .overrideGuard(TrustedOriginGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AuthRateLimitGuard)
      .useValue({ canActivate: () => true })
      .compile()
    controller = module.get(OAuthController)
  })

  const planted = async (run: () => Promise<unknown>): Promise<unknown> => {
    Object.defineProperty(Object.prototype, 'errorRedirectUrl', {
      value: 'https://attacker.example/',
      configurable: true,
      enumerable: true,
      writable: true
    })
    try {
      return await run().catch((error: unknown) => error)
    } finally {
      Reflect.deleteProperty(Object.prototype, 'errorRedirectUrl')
    }
  }

  // Scenario: the callback and the start of the flow, called while a key is planted. Expected: each is refused as `auth.internal`,
  // the service is never called and the browser is not redirected. Why: the callback answers a failure with a redirect to an
  // address read from the options, and nothing planted may choose it.
  it.each([
    [
      'the callback',
      (): Promise<unknown> =>
        controller.callback('google', { code: 'c', state: 's' } as never, req, res)
    ],
    [
      'the start of the flow',
      (): Promise<unknown> => controller.initiate('google', { tenantId: 't' } as never, req, res)
    ]
  ] as const)('refuses %s', async (_what, run) => {
    const refusal = await planted(run)

    expect(refusal).toBeInstanceOf(AuthException)
    expect((refusal as AuthException).getResponse()).toMatchObject({
      error: { code: AUTH_ERROR_CODES.INTERNAL }
    })
    expect(service.handleCallback).not.toHaveBeenCalled()
    expect(service.initiateOAuth).not.toHaveBeenCalled()
    expect(res.redirect).not.toHaveBeenCalled()
  })
})
