/**
 * OAuthController — the workspace invitation a sign-in accepts, carried in the start request's
 * query string. Kept apart from `oauth.controller.spec.ts`, which is over the size limit.
 */

import { Test } from '@nestjs/testing'
import { plainToInstance } from 'class-transformer'
import { validate } from 'class-validator'
import type { Request, Response } from 'express'

import { OAuthController } from './oauth.controller'
import { OAuthService } from './oauth.service'
import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { OAuthInitiateQueryDto } from '../dto/oauth-initiate-query.dto'
import { AuthRateLimitGuard } from '../guards/auth-rate-limit.guard'
import { TrustedOriginGuard } from '../guards/trusted-origin.guard'
import { TokenDeliveryService } from '../services/token-delivery.service'

const TOKEN = 'ab'.repeat(32)
const oauthService = {
  initiateOAuth: jest.fn().mockResolvedValue(undefined),
  handleCallback: jest.fn()
}

describe('OAuthController workspace invitation', () => {
  let controller: OAuthController

  beforeEach(async () => {
    jest.clearAllMocks()
    const module = await Test.createTestingModule({
      controllers: [OAuthController],
      providers: [
        { provide: OAuthService, useValue: oauthService },
        { provide: TokenDeliveryService, useValue: {} },
        { provide: BYMAX_AUTH_OPTIONS, useValue: {} }
      ]
    })
      .overrideGuard(TrustedOriginGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AuthRateLimitGuard)
      .useValue({ canActivate: () => true })
      .compile()
    controller = module.get(OAuthController)
  })

  it('hands the token in the query to the service as the fifth argument', async () => {
    const req = { headers: {} } as Partial<Request> as Request
    const res = {} as Partial<Response> as Response

    await controller.initiate('google', { workspaceInvitation: TOKEN }, req, res)

    expect(oauthService.initiateOAuth).toHaveBeenCalledWith('google', undefined, req, res, TOKEN)
  })

  describe('the query DTO', () => {
    /** The property names the validator refuses for a query. */
    async function refused(query: object): Promise<string[]> {
      const errors = await validate(plainToInstance(OAuthInitiateQueryDto, query))
      return errors.map((error) => error.property)
    }

    it('accepts no token and a token of exactly 64 characters', async () => {
      expect(await refused({})).toEqual([])
      expect(await refused({ workspaceInvitation: TOKEN })).toEqual([])
    })

    it.each([
      ['63 characters', 'a'.repeat(63)],
      ['65 characters', 'a'.repeat(65)],
      ['an empty string', ''],
      ['a number', 5]
    ])('refuses a token of %s', async (_name, value) => {
      expect(await refused({ workspaceInvitation: value })).toEqual(['workspaceInvitation'])
    })
  })
})
