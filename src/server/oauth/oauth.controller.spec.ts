/**
 * OAuthController — unit tests
 *
 * Verifies that OAuthController correctly delegates to OAuthService and
 * TokenDeliveryService with properly extracted request metadata.
 *
 * The controller is thin: it reads provider from the route param, validates
 * query DTOs, slices ip/userAgent to the documented limits (64/512 chars),
 * and forwards headers. All business logic lives in OAuthService.
 *
 * Mocking strategy: OAuthService and TokenDeliveryService are plain jest mock
 * objects. The controller is instantiated directly (no full NestJS testing
 * module needed) since there are no DI-resolved decorators that affect the
 * method logic. This keeps the tests fast and focused on the controller's
 * transformations.
 *
 * All tests follow the AAA pattern and use jest.resetAllMocks() in beforeEach.
 */

import { Test } from '@nestjs/testing'
import type { Request, Response } from 'express'

import { OAuthController } from './oauth.controller'
import { OAuthService } from './oauth.service'
import { TokenDeliveryService } from '../services/token-delivery.service'

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const MOCK_BEARER_RESPONSE = { accessToken: 'at.jwt' }

const mockOAuthService = {
  initiateOAuth: jest.fn(),
  handleCallback: jest.fn()
}

const mockTokenDelivery = {
  deliverAuthResponse: jest.fn()
}

// ---------------------------------------------------------------------------
// OAuthController
// ---------------------------------------------------------------------------

describe('OAuthController', () => {
  let controller: OAuthController

  beforeEach(async () => {
    jest.resetAllMocks()

    const module = await Test.createTestingModule({
      controllers: [OAuthController],
      providers: [
        { provide: OAuthService, useValue: mockOAuthService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery }
      ]
    }).compile()

    controller = module.get(OAuthController)
  })

  // ---------------------------------------------------------------------------
  // initiate()
  // ---------------------------------------------------------------------------

  describe('initiate()', () => {
    // Verifies the happy path: initiateOAuth is called with the correct provider,
    // tenantId from the query DTO, and the response object.
    it('should call oauthService.initiateOAuth with provider, tenantId, and res', async () => {
      mockOAuthService.initiateOAuth.mockResolvedValue(undefined)
      const mockRes = { redirect: jest.fn() } as unknown as Response
      const query = { tenantId: 'tenant-abc' }

      await controller.initiate('google', query as never, mockRes)

      expect(mockOAuthService.initiateOAuth).toHaveBeenCalledWith('google', 'tenant-abc', mockRes)
    })

    // Verifies that initiate() returns void (undefined) — the redirect is performed
    // inside the service via the response object, not via a return value.
    it('should return undefined (void)', async () => {
      mockOAuthService.initiateOAuth.mockResolvedValue(undefined)
      const mockRes = { redirect: jest.fn() } as unknown as Response
      const query = { tenantId: 'tenant-1' }

      const result = await controller.initiate('google', query as never, mockRes)

      expect(result).toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // callback()
  // ---------------------------------------------------------------------------

  describe('callback()', () => {
    const makeReq = (
      ip = '1.2.3.4',
      userAgent = 'TestBrowser/1.0',
      extraHeaders: Record<string, string> = {}
    ) =>
      ({
        ip,
        headers: { 'user-agent': userAgent, ...extraHeaders },
        cookies: {}
      }) as unknown as Request

    // Verifies the happy path: handleCallback is called with all correct arguments,
    // and the return value of deliverAuthResponse is returned to the caller.
    it('should call handleCallback with correct args and return deliverAuthResponse result', async () => {
      const mockReq = makeReq()
      const mockRes = { cookie: jest.fn() } as unknown as Response
      const query = { code: 'auth-code-xyz', state: 'csrf-state-abc' }

      mockOAuthService.handleCallback.mockResolvedValue({ accessToken: 'at' })
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue(MOCK_BEARER_RESPONSE)

      const result = await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockOAuthService.handleCallback).toHaveBeenCalledWith(
        'google',
        'auth-code-xyz',
        'csrf-state-abc',
        '1.2.3.4',
        'TestBrowser/1.0',
        mockReq.headers
      )
      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        { accessToken: 'at' },
        mockReq
      )
      expect(result).toBe(MOCK_BEARER_RESPONSE)
    })

    // Verifies that a long IP address is truncated to 64 characters before being
    // passed to handleCallback — prevents unbounded string storage in tokens.
    it('should truncate ip to 64 characters', async () => {
      const longIp = 'a'.repeat(90)
      const mockReq = makeReq(longIp)
      const mockRes = {} as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const ipArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[3]
      expect(typeof ipArg).toBe('string')
      expect((ipArg as string).length).toBe(64)
      expect(ipArg).toBe(longIp.slice(0, 64))
    })

    // Verifies that a long User-Agent string is truncated to 512 characters —
    // prevents malformed UA strings from exceeding storage limits.
    it('should truncate userAgent to 512 characters', async () => {
      const longUA = 'B'.repeat(600)
      const mockReq = makeReq('1.2.3.4', longUA)
      const mockRes = {} as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const uaArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[4]
      expect(typeof uaArg).toBe('string')
      expect((uaArg as string).length).toBe(512)
      expect(uaArg).toBe(longUA.slice(0, 512))
    })

    // Verifies that when req.ip is undefined (some reverse-proxy setups), the ip
    // argument falls back to an empty string rather than the literal 'undefined'.
    it('should fall back to empty string when req.ip is undefined', async () => {
      const mockReq = {
        ip: undefined,
        headers: { 'user-agent': 'UA' },
        cookies: {}
      } as unknown as Request
      const mockRes = {} as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const ipArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[3]
      expect(ipArg).toBe('')
    })

    // Verifies that when the user-agent header is absent, the userAgent falls back
    // to an empty string rather than the literal 'undefined'.
    it('should fall back to empty string when user-agent header is absent', async () => {
      const mockReq = {
        ip: '1.2.3.4',
        headers: {},
        cookies: {}
      } as unknown as Request
      const mockRes = {} as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const uaArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[4]
      expect(uaArg).toBe('')
    })

    // Verifies that the full req.headers object is forwarded as the 6th argument to
    // handleCallback so that OAuthService can pass sanitized headers to the hook context.
    it('should forward req.headers as the 6th argument to handleCallback', async () => {
      const headers = { 'user-agent': 'UA', 'x-request-id': 'req-001' }
      const mockReq = { ip: '1.2.3.4', headers, cookies: {} } as unknown as Request
      const mockRes = {} as unknown as Response
      const query = { code: 'code', state: 'state' }

      mockOAuthService.handleCallback.mockResolvedValue({})
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({})

      await controller.callback('google', query as never, mockReq, mockRes)

      const headersArg = (mockOAuthService.handleCallback.mock.calls[0] as unknown[])[5]
      expect(headersArg).toBe(headers)
    })

    // Verifies that TokenDeliveryService.deliverAuthResponse is called with the
    // correct response object (res) as the first argument so cookie delivery works.
    it('should call deliverAuthResponse with (res, result, req) in the correct order', async () => {
      const mockReq = makeReq()
      const mockRes = { cookie: jest.fn() } as unknown as Response
      const query = { code: 'code', state: 'state' }
      const authResult = { accessToken: 'tok', user: {} }

      mockOAuthService.handleCallback.mockResolvedValue(authResult)
      mockTokenDelivery.deliverAuthResponse.mockResolvedValue({ accessToken: 'tok' })

      await controller.callback('google', query as never, mockReq, mockRes)

      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        authResult,
        mockReq
      )
    })
  })
})
