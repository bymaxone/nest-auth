/**
 * @fileoverview Tests for InvitationController.
 *
 * Verifies that the controller delegates correctly to InvitationService and
 * TokenDeliveryService without containing any business logic of its own.
 *
 * All service providers are replaced with Jest mocks. JwtAuthGuard is overridden
 * so tests do not need to instantiate its JWT/Redis dependencies. Controller methods
 * are called directly (bypassing NestJS interceptors, pipes, and middleware), which
 * is the standard NestJS unit-test pattern.
 *
 * Both ?? '' fallbacks for req.ip and req.headers['user-agent'] in the accept()
 * handler are covered by dedicated tests with an incomplete request object.
 */

import { Test, type TestingModule } from '@nestjs/testing'
import type { Request, Response } from 'express'

import type { CreateInvitationDto } from '../dto/create-invitation.dto'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import type { AuthResult } from '../interfaces/auth-result.interface'
import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { InvitationService } from '../services/invitation.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { InvitationController } from './invitation.controller'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const SAFE_USER = {
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
}

const AUTH_RESULT: AuthResult = {
  user: SAFE_USER,
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh'
}

/**
 * Decoded JWT payload representing an authenticated admin user.
 * tenantId comes from the JWT — the controller must never use a tenantId from the request body.
 */
const JWT_PAYLOAD: DashboardJwtPayload = {
  jti: 'test-jti',
  sub: 'inviter-user-1',
  tenantId: 'tenant-from-jwt',
  role: 'admin',
  type: 'dashboard',
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

const mockInvitationService = {
  invite: jest.fn(),
  acceptInvitation: jest.fn()
}

const mockTokenDelivery = {
  deliverAuthResponse: jest.fn()
}

const mockReq = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser/1.0' }
} as unknown as Request

const mockRes = {} as unknown as Response

// ---------------------------------------------------------------------------
// InvitationController — invite() + accept()
// ---------------------------------------------------------------------------

describe('InvitationController', () => {
  let controller: InvitationController

  beforeEach(async () => {
    jest.clearAllMocks()

    const module: TestingModule = await Test.createTestingModule({
      controllers: [InvitationController],
      providers: [
        { provide: InvitationService, useValue: mockInvitationService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery }
      ]
    })
      // Override JwtAuthGuard to avoid instantiating JwtService and related dependencies.
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile()

    controller = module.get(InvitationController)
  })

  // ---------------------------------------------------------------------------
  // invite — POST /invitations
  // ---------------------------------------------------------------------------

  describe('invite', () => {
    const dto: CreateInvitationDto = {
      email: 'new@example.com',
      role: 'member'
    }

    beforeEach(() => {
      mockInvitationService.invite.mockResolvedValue(undefined)
    })

    // Verifies that invite delegates with the correct five arguments:
    // user.sub (inviter ID), dto.email, dto.role, user.tenantId (from JWT), and dto.tenantName (undefined).
    it('should call invitationService.invite with user.sub, dto.email, dto.role, user.tenantId, and undefined tenantName', async () => {
      await controller.invite(dto, JWT_PAYLOAD)

      expect(mockInvitationService.invite).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        dto.email,
        dto.role,
        JWT_PAYLOAD.tenantId,
        undefined
      )
    })

    // Verifies that the optional tenantName is forwarded to the service when present in the DTO.
    it('should pass dto.tenantName to the service when it is provided', async () => {
      const dtoWithName: CreateInvitationDto = { ...dto, tenantName: 'Acme Corp' }
      await controller.invite(dtoWithName, JWT_PAYLOAD)

      expect(mockInvitationService.invite).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        dto.email,
        dto.role,
        JWT_PAYLOAD.tenantId,
        'Acme Corp'
      )
    })

    // Verifies that the tenantId argument is always user.tenantId from the JWT,
    // not any hypothetical field from the DTO body (prevents tenant spoofing).
    it('should use tenantId from the JWT payload, not from any dto field', async () => {
      await controller.invite(dto, JWT_PAYLOAD)

      const [, , , tenantIdArg] = mockInvitationService.invite.mock.calls[0] as string[]
      expect(tenantIdArg).toBe(JWT_PAYLOAD.tenantId)
      expect(tenantIdArg).not.toBe(dto.email)
    })

    // Verifies that the invite endpoint returns undefined, mapping to HTTP 204 No Content.
    it('should return undefined (HTTP 204 No Content)', async () => {
      const result = await controller.invite(dto, JWT_PAYLOAD)
      expect(result).toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // accept — POST /invitations/accept
  // ---------------------------------------------------------------------------

  describe('accept', () => {
    const dto = { token: 'a'.repeat(64), name: 'Jane Doe', password: 'Secure123!' }

    beforeEach(() => {
      mockInvitationService.acceptInvitation.mockResolvedValue(AUTH_RESULT)
      mockTokenDelivery.deliverAuthResponse.mockReturnValue({ user: SAFE_USER })
    })

    // Verifies that acceptInvitation is called with the DTO, extracted ip, userAgent, and headers.
    it('should call invitationService.acceptInvitation with dto, ip, userAgent, and request headers', async () => {
      await controller.accept(dto as never, mockReq, mockRes)

      expect(mockInvitationService.acceptInvitation).toHaveBeenCalledWith(
        dto,
        '1.2.3.4',
        'TestBrowser/1.0',
        mockReq.headers
      )
    })

    // Verifies that deliverAuthResponse is called with the AuthResult from acceptInvitation.
    it('should call tokenDelivery.deliverAuthResponse with res, the service result, and req', async () => {
      await controller.accept(dto as never, mockReq, mockRes)

      expect(mockTokenDelivery.deliverAuthResponse).toHaveBeenCalledWith(
        mockRes,
        AUTH_RESULT,
        mockReq
      )
    })

    // Verifies that the controller returns exactly what deliverAuthResponse returns.
    it('should return the result produced by tokenDelivery.deliverAuthResponse', async () => {
      const expected = { user: SAFE_USER }
      mockTokenDelivery.deliverAuthResponse.mockReturnValue(expected)

      const result = await controller.accept(dto as never, mockReq, mockRes)
      expect(result).toBe(expected)
    })

    // Verifies the req.ip ?? '' fallback: when req.ip is undefined, an empty string is used.
    it('should use empty string for ip when req.ip is undefined', async () => {
      const reqNoIp = {
        ip: undefined,
        headers: { 'user-agent': 'Browser/1.0' }
      } as unknown as Request

      await controller.accept(dto as never, reqNoIp, mockRes)

      const [, ipArg] = mockInvitationService.acceptInvitation.mock.calls[0] as [
        unknown,
        string,
        string,
        unknown
      ]
      expect(ipArg).toBe('')
    })

    // Verifies the user-agent ?? '' fallback: when the user-agent header is absent, an empty string is used.
    it('should use empty string for userAgent when user-agent header is absent', async () => {
      const reqNoAgent = {
        ip: '5.6.7.8',
        headers: {}
      } as unknown as Request

      await controller.accept(dto as never, reqNoAgent, mockRes)

      const [, , agentArg] = mockInvitationService.acceptInvitation.mock.calls[0] as [
        unknown,
        string,
        string,
        unknown
      ]
      expect(agentArg).toBe('')
    })
  })
})
