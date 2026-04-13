import { ExecutionContext } from '@nestjs/common'

const { ROUTE_ARGS_METADATA } = require('@nestjs/common/constants') as {
  ROUTE_ARGS_METADATA: string
}

import type { DashboardJwtPayload } from '../interfaces/jwt-payload.interface'
import { CurrentUser } from './current-user.decorator'

// ---------------------------------------------------------------------------
// Extract factory function from the param decorator
// ---------------------------------------------------------------------------

/**
 * NestJS createParamDecorator stores the factory in ROUTE_ARGS_METADATA.
 * This helper applies the decorator to a test method to retrieve the factory.
 */
function getFactory(
  decorator: ParameterDecorator
): (data: unknown, ctx: ExecutionContext) => unknown {
  class TestController {
    testMethod(@decorator value: unknown) {
      return value
    }
  }
  const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, TestController, 'testMethod') as Record<
    string,
    { factory: (data: unknown, ctx: ExecutionContext) => unknown }
  >
  const key = Object.keys(args)[0]!
  return args[key]!.factory
}

// ---------------------------------------------------------------------------
// Mock context helpers
// ---------------------------------------------------------------------------

const MOCK_PAYLOAD: DashboardJwtPayload = {
  jti: 'test-jti',
  sub: 'user-1',
  tenantId: 'tenant-1',
  role: 'member',
  type: 'dashboard',
  status: 'active',
  mfaVerified: false,
  iat: 1_000_000,
  exp: 9_999_999_999
}

function mockCtx(user: DashboardJwtPayload | undefined): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ user })
    })
  } as unknown as ExecutionContext
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('CurrentUser decorator', () => {
  const noPropertyFactory = getFactory(CurrentUser())
  const subFactory = getFactory(CurrentUser('sub'))
  const tenantFactory = getFactory(CurrentUser('tenantId'))

  // Verifies that @CurrentUser() without arguments returns the full JWT payload from request.user.
  it('should return the full user payload when no property is specified', () => {
    const result = noPropertyFactory(undefined, mockCtx(MOCK_PAYLOAD))
    expect(result).toEqual(MOCK_PAYLOAD)
  })

  // Verifies that @CurrentUser('sub') extracts only the sub property from the JWT payload.
  it('should return the sub property when CurrentUser("sub") is used', () => {
    expect(subFactory('sub', mockCtx(MOCK_PAYLOAD))).toBe('user-1')
  })

  // Verifies that @CurrentUser('tenantId') extracts only the tenantId property from the JWT payload.
  it('should return the tenantId property when CurrentUser("tenantId") is used', () => {
    expect(tenantFactory('tenantId', mockCtx(MOCK_PAYLOAD))).toBe('tenant-1')
  })

  // Verifies that the decorator returns undefined when request.user is absent (unauthenticated route).
  it('should return undefined when user is not present on the request', () => {
    expect(noPropertyFactory(undefined, mockCtx(undefined))).toBeUndefined()
  })

  // Verifies that accessing a specific property when user is absent also returns undefined safely.
  it('should return undefined for a property when user is absent', () => {
    expect(subFactory('sub', mockCtx(undefined))).toBeUndefined()
  })
})
