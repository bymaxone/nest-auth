/**
 * PlatformRolesGuard — unit tests
 *
 * Tests the role-based access control guard for platform admin routes.
 * The guard:
 *  - Returns true when no @PlatformRoles metadata is set (no restriction)
 *  - Returns true when @PlatformRoles([]) is an empty array
 *  - Throws TOKEN_INVALID when request.user is missing or not a platform token
 *  - Throws INSUFFICIENT_ROLE (403) when platformHierarchy is not configured
 *  - Throws INSUFFICIENT_ROLE (403) when the user's role does not satisfy requirements
 *  - Returns true on exact role match or hierarchical role inheritance
 *
 * Mocking strategy: Reflector is instantiated via useClass so jest.spyOn works.
 * The BYMAX_AUTH_OPTIONS token is provided as a plain mock object. No real Redis
 * or JWT dependencies are needed — this guard only reads request.user.
 */

import { HttpStatus } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { PLATFORM_ROLES_KEY } from '../decorators/platform-roles.decorator'
import { PlatformRolesGuard } from './platform-roles.guard'

// ---------------------------------------------------------------------------
// Test doubles — platform role hierarchy
// ---------------------------------------------------------------------------

// Denormalized hierarchy: super_admin inherits admin and support; admin inherits support.
const TEST_HIERARCHY = {
  super_admin: ['admin', 'support'],
  admin: ['support'],
  support: []
}

const mockOptionsWithHierarchy = {
  roles: { platformHierarchy: TEST_HIERARCHY }
}

const mockOptionsWithoutHierarchy = {
  roles: { platformHierarchy: undefined }
}

// ---------------------------------------------------------------------------
// Helper — builds a minimal ExecutionContext with a user on the request
// ---------------------------------------------------------------------------

function makeContext(
  userType: string | undefined,
  userRole: string | undefined
): {
  getHandler: () => jest.Mock
  getClass: () => jest.Mock
  switchToHttp: () => { getRequest: () => Record<string, unknown> }
} {
  const user =
    userType !== undefined && userRole !== undefined
      ? { type: userType, role: userRole }
      : userType !== undefined
        ? { type: userType, role: undefined }
        : undefined

  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: () => ({
      getRequest: () => ({ user })
    })
  }
}

// ---------------------------------------------------------------------------
// Suite — PlatformRolesGuard
// ---------------------------------------------------------------------------

describe('PlatformRolesGuard', () => {
  let guard: PlatformRolesGuard
  let reflector: Reflector

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        PlatformRolesGuard,
        { provide: Reflector, useClass: Reflector },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptionsWithHierarchy }
      ]
    }).compile()

    guard = module.get(PlatformRolesGuard)
    reflector = module.get(Reflector)
  })

  // ---------------------------------------------------------------------------
  // No metadata (open route)
  // ---------------------------------------------------------------------------

  describe('no role metadata', () => {
    // When no @PlatformRoles metadata is set on the handler or controller,
    // all authenticated platform admins may proceed — no role restriction applies.
    it('should return true when requiredRoles metadata is undefined', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined)
      const ctx = makeContext('platform', 'support')

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // An explicitly empty @PlatformRoles([]) decoration is equivalent to no restriction;
    // the guard must return true without checking the user role.
    it('should return true when requiredRoles metadata is an empty array', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([])
      const ctx = makeContext('platform', 'support')

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // Unauthenticated / wrong token type
  // ---------------------------------------------------------------------------

  describe('user validation', () => {
    // If JwtPlatformGuard did not run (or was bypassed), request.user may be undefined.
    // The roles guard must detect this and throw TOKEN_INVALID, not a 403.
    it('should throw TOKEN_INVALID when request.user is undefined', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
      const ctx = makeContext(undefined, undefined)

      expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
    })

    // Confirms the specific error code when user is missing.
    it('should set error code TOKEN_INVALID when request.user is undefined', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
      const ctx = makeContext(undefined, undefined)

      let caughtError: AuthException | undefined
      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // A dashboard user who somehow reaches this guard must be rejected with TOKEN_INVALID.
    // This prevents a tenant user from accessing platform admin endpoints even if they
    // have the right role string.
    it('should throw TOKEN_INVALID when user.type is "dashboard" (non-platform token)', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
      const ctx = makeContext('dashboard', 'admin')

      let caughtError: AuthException | undefined
      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })
  })

  // ---------------------------------------------------------------------------
  // Missing hierarchy configuration
  // ---------------------------------------------------------------------------

  describe('missing hierarchy configuration', () => {
    // If platformHierarchy is not configured in module options, the guard cannot
    // evaluate roles and must deny access (fail-secure) with INSUFFICIENT_ROLE + 403.
    it('should throw INSUFFICIENT_ROLE (403) when platformHierarchy is not configured', async () => {
      const moduleWithoutHierarchy = await Test.createTestingModule({
        providers: [
          PlatformRolesGuard,
          { provide: Reflector, useClass: Reflector },
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptionsWithoutHierarchy }
        ]
      }).compile()

      const guardNoHierarchy = moduleWithoutHierarchy.get(PlatformRolesGuard)
      const localReflector = moduleWithoutHierarchy.get(Reflector)

      jest.spyOn(localReflector, 'getAllAndOverride').mockReturnValue(['admin'])
      const ctx = makeContext('platform', 'admin')

      let caughtError: AuthException | undefined
      try {
        guardNoHierarchy.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
      expect(caughtError!.getStatus()).toBe(HttpStatus.FORBIDDEN)
    })
  })

  // ---------------------------------------------------------------------------
  // Role insufficiency
  // ---------------------------------------------------------------------------

  describe('insufficient role', () => {
    // A user with 'support' role must not access an 'admin'-only route.
    // The guard throws INSUFFICIENT_ROLE with HTTP 403.
    it('should throw INSUFFICIENT_ROLE (403) when the user role is too low', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
      const ctx = makeContext('platform', 'support')

      let caughtError: AuthException | undefined
      try {
        guard.canActivate(ctx as never)
      } catch (e) {
        caughtError = e instanceof AuthException ? e : undefined
      }
      expect(caughtError).toBeInstanceOf(AuthException)
      const response = caughtError!.getResponse() as { error: { code: string } }
      expect(response.error.code).toBe(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
      expect(caughtError!.getStatus()).toBe(HttpStatus.FORBIDDEN)
    })

    // Confirms the metadata key used for reflector lookup is exactly PLATFORM_ROLES_KEY
    // (the same Symbol imported from the decorator module).
    it('should use PLATFORM_ROLES_KEY (Symbol) to read metadata from the reflector', () => {
      const spy = jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['support'])
      const ctx = makeContext('platform', 'support')

      guard.canActivate(ctx as never)

      expect(spy).toHaveBeenCalledWith(PLATFORM_ROLES_KEY, expect.any(Array))
    })
  })

  // ---------------------------------------------------------------------------
  // Happy path — access granted
  // ---------------------------------------------------------------------------

  describe('access granted', () => {
    // Exact role match: the user has the 'admin' role and 'admin' is required.
    it('should return true on exact role match', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
      const ctx = makeContext('platform', 'admin')

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // Hierarchical match: super_admin inherits admin (listed in TEST_HIERARCHY),
    // so a super_admin must be allowed to access an 'admin'-required route.
    it('should return true when user role inherits the required role (super_admin → admin)', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
      const ctx = makeContext('platform', 'super_admin')

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // super_admin also transitively covers 'support' routes.
    it('should return true when user role inherits support (super_admin → support)', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['support'])
      const ctx = makeContext('platform', 'super_admin')

      expect(guard.canActivate(ctx as never)).toBe(true)
    })

    // When multiple roles are allowed and the user satisfies one of them, access is granted.
    it('should return true when the user satisfies any of multiple required roles', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['super_admin', 'admin'])
      const ctx = makeContext('platform', 'admin')

      expect(guard.canActivate(ctx as never)).toBe(true)
    })
  })
})
