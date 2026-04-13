import { HttpStatus } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-one-nest-auth.constants'
import { AuthException } from '../errors/auth-exception'
import { RolesGuard } from './roles.guard'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeContext(
  userRole: string | undefined,
  requiredRoles: string[] | undefined
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
        user: userRole ? { role: userRole } : undefined
      })
    })
  }
}

const mockOptions = {
  roles: {
    hierarchy: {
      owner: ['admin', 'member', 'viewer'],
      admin: ['member', 'viewer'],
      member: ['viewer'],
      viewer: []
    }
  }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('RolesGuard', () => {
  let guard: RolesGuard
  let reflector: Reflector

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [RolesGuard, Reflector, { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }]
    }).compile()

    guard = module.get(RolesGuard)
    reflector = module.get(Reflector)
  })

  // Verifies that routes with no @Roles metadata are accessible to any authenticated user.
  it('should return true when no roles metadata is set', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined)
    const ctx = makeContext('member', undefined)
    expect(guard.canActivate(ctx as never)).toBe(true)
  })

  // Verifies that an empty @Roles([]) array is treated as no restriction, allowing all roles.
  it('should return true when roles metadata is an empty array', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue([])
    const ctx = makeContext('member', [])
    expect(guard.canActivate(ctx as never)).toBe(true)
  })

  // Verifies that an exact role match between user and required role grants access.
  it('should allow access on exact role match', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
    const ctx = makeContext('admin', ['admin'])
    expect(guard.canActivate(ctx as never)).toBe(true)
  })

  // Verifies that a higher-ranking role inherits access to routes requiring a lower role (hierarchy).
  it('should allow access via hierarchical role (owner can access admin routes)', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
    const ctx = makeContext('owner', ['admin'])
    expect(guard.canActivate(ctx as never)).toBe(true)
  })

  // Verifies that a role below the required level throws an AuthException instead of returning false.
  it('should deny access when role is insufficient', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
    const ctx = makeContext('viewer', ['admin'])
    expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
  })

  // Verifies that the thrown AuthException has HTTP status 403 FORBIDDEN on role denial.
  it('should throw FORBIDDEN (403) on insufficient role', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
    const ctx = makeContext('viewer', ['admin'])
    try {
      guard.canActivate(ctx as never)
    } catch (e) {
      expect(e).toBeInstanceOf(AuthException)
      expect((e as AuthException).getStatus()).toBe(HttpStatus.FORBIDDEN)
    }
  })

  // Verifies that a request with no authenticated user (request.user undefined) throws an AuthException.
  it('should throw when user has no role set', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin'])
    const ctx = makeContext(undefined, ['admin'])
    expect(() => guard.canActivate(ctx as never)).toThrow(AuthException)
  })

  // Verifies that the guard passes when the user's role satisfies any of multiple required roles.
  it('should allow when user satisfies any of multiple required roles', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin', 'owner'])
    const ctx = makeContext('admin', ['admin', 'owner'])
    expect(guard.canActivate(ctx as never)).toBe(true)
  })
})
