import { HttpStatus } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { SelfOrAdminGuard } from './self-or-admin.guard'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const hierarchy = {
  admin: ['member', 'viewer'],
  member: ['viewer'],
  viewer: []
}

const mockOptions = {
  roles: { hierarchy }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUser(overrides: Partial<{
  sub: string
  role: string
  jti: string
  tenantId: string
  type: 'dashboard'
  status: string
  mfaEnabled: boolean
  mfaVerified: boolean
  iat: number
  exp: number
}> = {}) {
  return {
    jti: 'some-jti',
    sub: 'user-1',
    tenantId: 'tenant-1',
    role: 'member',
    type: 'dashboard' as const,
    status: 'active',
    mfaEnabled: false,
    mfaVerified: false,
    iat: 1_000_000,
    exp: 9_999_999_999,
    ...overrides
  }
}

function makeContext(
  user: ReturnType<typeof makeUser> | undefined,
  params: Record<string, string | string[]>
): {
  getHandler: () => jest.Mock
  getClass: () => jest.Mock
  switchToHttp: () => { getRequest: () => Record<string, unknown> }
} {
  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: () => ({
      getRequest: () => ({
        user,
        params
      })
    })
  }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('SelfOrAdminGuard', () => {
  let guard: SelfOrAdminGuard

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        SelfOrAdminGuard,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }
      ]
    }).compile()

    guard = module.get(SelfOrAdminGuard)
  })

  // ----------------- Missing user -----------------

  describe('missing user', () => {
    // Verifies that the guard throws TOKEN_INVALID/UNAUTHORIZED when req.user is undefined (JwtAuthGuard skipped).
    it('should throw TOKEN_INVALID when req.user is undefined (defensive)', () => {
      const ctx = makeContext(undefined, { userId: 'user-1' })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getStatus()).toBe(HttpStatus.UNAUTHORIZED)
        const body = (e as AuthException).getResponse() as { error: { code: string } }
        expect(body.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
      }
    })
  })

  // ----------------- Missing route param -----------------

  describe('missing route param', () => {
    // Verifies that the guard throws INSUFFICIENT_ROLE/FORBIDDEN when neither userId nor id is present in params.
    it('should throw INSUFFICIENT_ROLE when neither userId nor id param is present', () => {
      const ctx = makeContext(makeUser(), {})

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
        const body = (e as AuthException).getResponse() as { error: { code: string } }
        expect(body.error.code).toBe(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
      }
    })
  })

  // ----------------- Array param -----------------

  describe('array param value', () => {
    // Verifies that the guard throws INSUFFICIENT_ROLE/FORBIDDEN when the resolved param is an array instead of a plain string.
    it('should throw INSUFFICIENT_ROLE when the param value is an array', () => {
      const ctx = makeContext(makeUser(), { userId: ['user-1', 'user-2'] })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
        const body = (e as AuthException).getResponse() as { error: { code: string } }
        expect(body.error.code).toBe(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
      }
    })

    // Verifies that the id fallback param is also rejected when it arrives as an array.
    it('should throw INSUFFICIENT_ROLE when the id fallback param value is an array', () => {
      const ctx = makeContext(makeUser(), { id: ['hash-a', 'hash-b'] })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
        const body = (e as AuthException).getResponse() as { error: { code: string } }
        expect(body.error.code).toBe(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
      }
    })
  })

  // ----------------- SHA-256 format gate -----------------

  describe('SHA-256 format gate', () => {
    // Verifies that a 64-char param containing uppercase hex letters is rejected with TOKEN_INVALID/BAD_REQUEST.
    it('should reject a 64-char hex param with uppercase letters (not strict lowercase SHA-256)', () => {
      // 64 chars, hex-looking but uppercase — fails STRICT_SHA256_RE
      const upperHex = 'A'.repeat(64)
      const ctx = makeContext(makeUser({ sub: upperHex }), { id: upperHex })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getStatus()).toBe(HttpStatus.BAD_REQUEST)
        const body = (e as AuthException).getResponse() as { error: { code: string } }
        expect(body.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
      }
    })

    // Verifies that a 64-char string that is NOT all-hex (contains non-hex chars) does NOT trigger the SHA-256 gate.
    it('should accept self-access for a 64-char string that is NOT all-hex (e.g. mixed alphanumeric)', () => {
      // 64 chars but contains 'g' which is not a hex digit — isHexLooking returns false
      const nonHex64 = 'g' + 'a'.repeat(63)
      const ctx = makeContext(makeUser({ sub: nonHex64 }), { userId: nonHex64 })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // Verifies that a 63-char all-hex string does NOT trigger the SHA-256 gate (length must be exactly 64).
    it('should NOT trigger the SHA-256 gate for a 63-char hex string (length must be exactly 64)', () => {
      // 63 lowercase hex chars — isHexLooking returns false because length !== 64
      const hex63 = 'a'.repeat(63)
      const ctx = makeContext(makeUser({ sub: hex63 }), { userId: hex63 })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // Verifies that a valid lowercase SHA-256 hash equal to req.user.sub is accepted (self-access).
    it('should accept a valid lowercase SHA-256 session hash when it equals req.user.sub', () => {
      // 64 strictly lowercase hex chars — passes STRICT_SHA256_RE, sub matches
      const validHash = 'a'.repeat(64)
      const ctx = makeContext(makeUser({ sub: validHash }), { id: validHash })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })

  // ----------------- Self-access -----------------

  describe('self-access', () => {
    // Verifies that a request where req.user.sub matches the userId param returns true.
    it('should accept self access via req.params.userId', () => {
      const ctx = makeContext(makeUser({ sub: 'user-42', role: 'member' }), { userId: 'user-42' })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // Verifies that the guard falls back to the id param when userId is absent and sub matches.
    it('should accept self access via req.params.id (fallback)', () => {
      const ctx = makeContext(makeUser({ sub: 'user-99', role: 'member' }), { id: 'user-99' })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // Verifies that self-access is granted for a non-hex looking ID (e.g. a UUID with dashes).
    it('should accept self-access for a non-hex looking ID (e.g. UUID)', () => {
      const uuid = '550e8400-e29b-41d4-a716-446655440000'
      const ctx = makeContext(makeUser({ sub: uuid, role: 'viewer' }), { userId: uuid })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // Verifies that userId takes precedence over id when both params are present.
    it('should prefer userId over id when both params are present', () => {
      // sub matches userId but not id
      const ctx = makeContext(makeUser({ sub: 'user-primary' }), {
        userId: 'user-primary',
        id: 'other-hash'
      })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })

  // ----------------- Admin override -----------------

  describe('admin override', () => {
    // Verifies that a user with the admin role can access another user's resource even when sub does not match.
    it('should accept admin override even when sub does not match', () => {
      const ctx = makeContext(makeUser({ sub: 'admin-user', role: 'admin' }), { userId: 'other-user' })

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // Verifies that a non-admin, non-matching user throws INSUFFICIENT_ROLE/FORBIDDEN.
    it('should throw INSUFFICIENT_ROLE when neither self nor admin', () => {
      const ctx = makeContext(makeUser({ sub: 'user-1', role: 'member' }), { userId: 'user-2' })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
        const body = (e as AuthException).getResponse() as { error: { code: string } }
        expect(body.error.code).toBe(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
      }
    })

    // Verifies that a viewer role (below admin) cannot access another user's resource.
    it('should throw INSUFFICIENT_ROLE for a viewer accessing another user', () => {
      const ctx = makeContext(makeUser({ sub: 'viewer-1', role: 'viewer' }), { userId: 'user-2' })

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)

      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
      }
    })
  })
})
