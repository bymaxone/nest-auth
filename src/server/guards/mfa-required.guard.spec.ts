import { Reflector } from '@nestjs/core'
import { Test } from '@nestjs/testing'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { SKIP_MFA_KEY } from '../decorators/skip-mfa.decorator'
import { MfaRequiredGuard } from './mfa-required.guard'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const BASE_PAYLOAD = {
  jti: 'test-jti',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard' as const,
  status: 'active',
  mfaEnabled: false,
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

function makeContext(user: Record<string, unknown> | undefined): {
  getHandler: () => jest.Mock
  getClass: () => jest.Mock
  switchToHttp: () => { getRequest: () => Record<string, unknown> }
} {
  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: () => ({ getRequest: () => ({ user }) })
  }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('MfaRequiredGuard', () => {
  let guard: MfaRequiredGuard
  let reflector: Reflector

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [MfaRequiredGuard, { provide: Reflector, useClass: Reflector }]
    }).compile()

    guard = module.get(MfaRequiredGuard)
    reflector = module.get(Reflector)
  })

  // ---------------------------------------------------------------------------
  // @SkipMfa routes
  // ---------------------------------------------------------------------------

  describe('@SkipMfa routes', () => {
    // Verifies that routes decorated with @SkipMfa() bypass MFA enforcement entirely.
    it('should return true without checking MFA when @SkipMfa() is set', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: true, mfaVerified: false })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // Unauthenticated requests
  // ---------------------------------------------------------------------------

  describe('unauthenticated requests', () => {
    // Verifies that requests without request.user (not yet authenticated) pass through.
    // JwtAuthGuard handles authentication enforcement — MfaRequiredGuard only enforces MFA.
    it('should return true when request.user is undefined', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext(undefined)

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // MFA not enabled
  // ---------------------------------------------------------------------------

  describe('mfaEnabled: false', () => {
    // Verifies that users who have not enabled MFA can access any route freely.
    it('should return true when mfaEnabled is false', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: false })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // MFA enabled + verified
  // ---------------------------------------------------------------------------

  describe('mfaEnabled: true, mfaVerified: true', () => {
    // Verifies that a user who completed the MFA challenge (mfaVerified: true) can access protected routes.
    it('should return true when mfaEnabled and mfaVerified are both true', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: true, mfaVerified: true })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // MFA enabled but not verified
  // ---------------------------------------------------------------------------

  describe('mfaEnabled: true, mfaVerified: false', () => {
    // Verifies that a user with MFA enabled who has not yet completed the challenge is rejected.
    it('should throw MFA_REQUIRED when mfaEnabled is true and mfaVerified is false', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: true, mfaVerified: false })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
    })

    // Verifies the specific error code thrown when MFA verification is required.
    it('should throw with AUTH_ERROR_CODES.MFA_REQUIRED code', () => {
      expect.assertions(2)
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: true, mfaVerified: false })

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.MFA_REQUIRED })
        })
      }
    })

    // Verifies that mfaVerified: undefined is treated the same as mfaVerified: false.
    it('should throw MFA_REQUIRED when mfaVerified is undefined (absent in token)', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const payload = { ...BASE_PAYLOAD, mfaEnabled: true }
      // Remove mfaVerified from the payload
      const { mfaVerified: _mv, ...payloadWithoutVerified } = payload
      const ctx = makeContext(payloadWithoutVerified)

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
    })

    // Verifies that mfaVerified: 1 (truthy number, not a strict boolean true) is treated as unverified.
    it('should throw MFA_REQUIRED when mfaVerified is a non-boolean truthy value (e.g. 1)', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: true, mfaVerified: 1 })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // Malformed payload
  // ---------------------------------------------------------------------------

  describe('malformed payload', () => {
    // Verifies that a token missing the mfaEnabled field entirely throws TOKEN_INVALID.
    it('should throw TOKEN_INVALID when mfaEnabled is absent from the token payload', () => {
      expect.assertions(2)
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const { mfaEnabled: _me, ...payloadWithoutMfaEnabled } = BASE_PAYLOAD
      const ctx = makeContext(payloadWithoutMfaEnabled)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
        })
      }
    })

    // Verifies that a non-boolean mfaEnabled value (e.g. a string) triggers TOKEN_INVALID.
    it('should throw TOKEN_INVALID when mfaEnabled is a string', () => {
      expect.assertions(2)
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: 'true' })

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.TOKEN_INVALID })
        })
      }
    })

    // Verifies that mfaEnabled: null triggers TOKEN_INVALID (not a pass-through).
    it('should throw TOKEN_INVALID when mfaEnabled is null', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: null })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
    })

    // Verifies that mfaEnabled: 0 triggers TOKEN_INVALID (falsy non-boolean is still invalid).
    it('should throw TOKEN_INVALID when mfaEnabled is 0', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: 0 })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
    })

    // Verifies that mfaEnabled: {} triggers TOKEN_INVALID (truthy object is still invalid type).
    it('should throw TOKEN_INVALID when mfaEnabled is an object', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext({ ...BASE_PAYLOAD, mfaEnabled: {} })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // Reflector key
  // ---------------------------------------------------------------------------

  describe('reflector key', () => {
    // Verifies that the guard reads metadata using the SKIP_MFA_KEY Symbol.
    it('should call reflector.getAllAndOverride with SKIP_MFA_KEY', () => {
      const getAllAndOverrideSpy = jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false)
      const ctx = makeContext(BASE_PAYLOAD)

      guard.canActivate(ctx as never)

      expect(getAllAndOverrideSpy).toHaveBeenCalledWith(SKIP_MFA_KEY, [
        ctx.getHandler(),
        ctx.getClass()
      ])
    })
  })
})
