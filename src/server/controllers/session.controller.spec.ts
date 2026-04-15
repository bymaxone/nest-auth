/**
 * @fileoverview Tests for SessionController, which provides HTTP endpoints for
 * listing and revoking sessions, delegating to SessionService and TokenDeliveryService.
 */

import { GUARDS_METADATA } from '@nestjs/common/constants'
import { Test, type TestingModule } from '@nestjs/testing'
import type { Request } from 'express'

import { sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { JwtAuthGuard } from '../guards/jwt-auth.guard'
import { UserStatusGuard } from '../guards/user-status.guard'
import type { SessionInfo } from '../services/session.service'
import { SessionService } from '../services/session.service'
import { TokenDeliveryService } from '../services/token-delivery.service'
import { SessionController } from './session.controller'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const mockSessionService = {
  listSessions: jest.fn(),
  revokeAllExceptCurrent: jest.fn(),
  revokeSession: jest.fn()
}

const mockTokenDelivery = {
  extractRefreshToken: jest.fn()
}

const JWT_PAYLOAD = {
  jti: 'test-jti',
  sub: 'user-123',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard' as const,
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

// Partial mock — only the fields used by SessionController
const mockReq: Partial<Request> = {
  ip: '1.2.3.4',
  headers: { 'user-agent': 'TestBrowser' },
  cookies: {}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getErrorCode(err: unknown): string {
  if (!(err instanceof AuthException)) throw new Error('Not an AuthException')
  const res = err.getResponse() as { error?: { code?: string } }
  return res.error?.code ?? ''
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('SessionController', () => {
  let controller: SessionController

  beforeEach(async () => {
    jest.clearAllMocks()

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SessionController],
      providers: [
        { provide: SessionService, useValue: mockSessionService },
        { provide: TokenDeliveryService, useValue: mockTokenDelivery }
      ]
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(UserStatusGuard)
      .useValue({ canActivate: () => true })
      .compile()

    controller = module.get(SessionController)
  })

  // ---------------------------------------------------------------------------
  // Guard metadata
  // ---------------------------------------------------------------------------

  // Verifies that both JwtAuthGuard and UserStatusGuard are applied at the controller level so every session endpoint requires authentication.
  it('should apply JwtAuthGuard and UserStatusGuard at the controller level', () => {
    const guards: unknown[] = Reflect.getMetadata(GUARDS_METADATA, SessionController) as unknown[]
    expect(guards).toContain(JwtAuthGuard)
    expect(guards).toContain(UserStatusGuard)
  })

  // ---------------------------------------------------------------------------
  // listSessions
  // ---------------------------------------------------------------------------

  describe('listSessions', () => {
    // Verifies that listSessions passes the full request object to extractRefreshToken to locate the cookie or header.
    it('should call tokenDelivery.extractRefreshToken with the request', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue(null)
      mockSessionService.listSessions.mockResolvedValue([])

      await controller.listSessions(JWT_PAYLOAD, mockReq as Request)

      expect(mockTokenDelivery.extractRefreshToken).toHaveBeenCalledWith(mockReq)
    })

    // Verifies that the raw refresh token is hashed before being forwarded so the plaintext token never leaves the controller.
    it('should forward sha256(rawRefreshToken) as currentHash, not the raw token', async () => {
      const rawToken = 'raw-refresh-token-value'
      const expectedHash = sha256(rawToken)
      mockTokenDelivery.extractRefreshToken.mockReturnValue(rawToken)
      mockSessionService.listSessions.mockResolvedValue([])

      await controller.listSessions(JWT_PAYLOAD, mockReq as Request)

      expect(mockSessionService.listSessions).toHaveBeenCalledWith(JWT_PAYLOAD.sub, expectedHash)
      expect(mockSessionService.listSessions).not.toHaveBeenCalledWith(JWT_PAYLOAD.sub, rawToken)
    })

    // Verifies that undefined is forwarded as currentHash when no refresh token is present in the request.
    it('should forward undefined as currentHash when no refresh token is present', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue(null)
      mockSessionService.listSessions.mockResolvedValue([])

      await controller.listSessions(JWT_PAYLOAD, mockReq as Request)

      expect(mockSessionService.listSessions).toHaveBeenCalledWith(JWT_PAYLOAD.sub, undefined)
    })

    // Verifies that listSessions returns the session list from the service without wrapping or filtering.
    it('should return the result from sessionService.listSessions', async () => {
      const sessions: SessionInfo[] = [
        {
          id: 'a'.repeat(8),
          sessionHash: 'a'.repeat(64),
          device: 'TestBrowser',
          ip: '1.2.3.4',
          isCurrent: true,
          createdAt: new Date('2026-01-01').getTime(),
          lastActivityAt: new Date('2026-01-02').getTime()
        }
      ]
      mockTokenDelivery.extractRefreshToken.mockReturnValue(null)
      mockSessionService.listSessions.mockResolvedValue(sessions)

      const result = await controller.listSessions(JWT_PAYLOAD, mockReq as Request)

      expect(result).toBe(sessions)
    })
  })

  // ---------------------------------------------------------------------------
  // revokeAllSessions
  // ---------------------------------------------------------------------------

  describe('revokeAllSessions', () => {
    // Verifies that revokeAllSessions throws SESSION_NOT_FOUND when extractRefreshToken returns null.
    it('should throw SESSION_NOT_FOUND when no refresh token is present (null)', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue(null)

      let caughtError: unknown
      try {
        await controller.revokeAllSessions(JWT_PAYLOAD, mockReq as Request)
      } catch (err) {
        caughtError = err
      }

      expect(getErrorCode(caughtError)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that revokeAllSessions throws SESSION_NOT_FOUND when extractRefreshToken returns undefined.
    it('should throw SESSION_NOT_FOUND when no refresh token is present (undefined)', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue(undefined)

      let caughtError: unknown
      try {
        await controller.revokeAllSessions(JWT_PAYLOAD, mockReq as Request)
      } catch (err) {
        caughtError = err
      }

      expect(getErrorCode(caughtError)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that revokeAllSessions throws SESSION_NOT_FOUND when extractRefreshToken returns an empty string.
    it('should throw SESSION_NOT_FOUND when no refresh token is present (empty string)', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue('')

      let caughtError: unknown
      try {
        await controller.revokeAllSessions(JWT_PAYLOAD, mockReq as Request)
      } catch (err) {
        caughtError = err
      }

      expect(getErrorCode(caughtError)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })

    // Verifies that the raw refresh token is hashed before being forwarded to revokeAllExceptCurrent.
    it('should forward sha256(rawRefreshToken) to revokeAllExceptCurrent, not the raw token', async () => {
      const rawToken = 'raw-refresh-token-to-revoke'
      const expectedHash = sha256(rawToken)
      mockTokenDelivery.extractRefreshToken.mockReturnValue(rawToken)
      mockSessionService.revokeAllExceptCurrent.mockResolvedValue(undefined)

      await controller.revokeAllSessions(JWT_PAYLOAD, mockReq as Request)

      expect(mockSessionService.revokeAllExceptCurrent).toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        expectedHash
      )
      expect(mockSessionService.revokeAllExceptCurrent).not.toHaveBeenCalledWith(
        JWT_PAYLOAD.sub,
        rawToken
      )
    })

    // Verifies that revokeAllSessions resolves successfully when the service completes without error.
    it('should resolve without throwing on success', async () => {
      mockTokenDelivery.extractRefreshToken.mockReturnValue('some-refresh-token')
      mockSessionService.revokeAllExceptCurrent.mockResolvedValue(undefined)

      await expect(
        controller.revokeAllSessions(JWT_PAYLOAD, mockReq as Request)
      ).resolves.toBeUndefined()
    })

    // Verifies that errors from sessionService.revokeAllExceptCurrent propagate to the caller unchanged.
    it('should propagate errors from sessionService.revokeAllExceptCurrent', async () => {
      const serviceError = new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
      mockTokenDelivery.extractRefreshToken.mockReturnValue('some-refresh-token')
      mockSessionService.revokeAllExceptCurrent.mockRejectedValue(serviceError)

      await expect(controller.revokeAllSessions(JWT_PAYLOAD, mockReq as Request)).rejects.toThrow(
        serviceError
      )
    })
  })

  // ---------------------------------------------------------------------------
  // revokeSession
  // ---------------------------------------------------------------------------

  describe('revokeSession', () => {
    const SESSION_ID = 'b'.repeat(64)

    // Verifies that revokeSession calls the service with the authenticated user's sub and the session ID.
    it('should call sessionService.revokeSession with user.sub and the session id', async () => {
      mockSessionService.revokeSession.mockResolvedValue(undefined)

      await controller.revokeSession(JWT_PAYLOAD, SESSION_ID)

      expect(mockSessionService.revokeSession).toHaveBeenCalledWith(JWT_PAYLOAD.sub, SESSION_ID)
    })

    // Verifies that the controller binds the caller's own sub as the ownership key so users cannot revoke other users' sessions.
    it('should use the authenticated user sub as the ownership key (BOLA prevention)', async () => {
      const differentUserPayload = { ...JWT_PAYLOAD, sub: 'attacker-999' }
      mockSessionService.revokeSession.mockResolvedValue(undefined)

      await controller.revokeSession(differentUserPayload, SESSION_ID)

      expect(mockSessionService.revokeSession).toHaveBeenCalledWith('attacker-999', SESSION_ID)
      expect(mockSessionService.revokeSession).not.toHaveBeenCalledWith('user-123', SESSION_ID)
    })

    // Verifies that SESSION_NOT_FOUND thrown by the service propagates to the caller unchanged.
    it('should propagate SESSION_NOT_FOUND from sessionService.revokeSession', async () => {
      const serviceError = new AuthException(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
      mockSessionService.revokeSession.mockRejectedValue(serviceError)

      let caughtError: unknown
      try {
        await controller.revokeSession(JWT_PAYLOAD, SESSION_ID)
      } catch (err) {
        caughtError = err
      }

      expect(caughtError).toBe(serviceError)
      expect(getErrorCode(caughtError)).toBe(AUTH_ERROR_CODES.SESSION_NOT_FOUND)
    })
  })
})
