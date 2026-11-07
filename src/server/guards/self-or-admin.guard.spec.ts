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

function makeUser(
  overrides: Partial<{
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
  }> = {}
) {
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
      providers: [SelfOrAdminGuard, { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions }]
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
    // Verifies that a 64-char param containing uppercase hex letters is rejected with
    // TOKEN_INVALID at 401 — the status the code carries everywhere else. This site used to
    // answer 400 for the same code, which is one of the five self-disagreements the status
    // table removed: a caller could tell this rejection from every other TOKEN_INVALID by the
    // status line alone.
    it('should reject a 64-char hex param with uppercase letters (not strict lowercase SHA-256)', () => {
      // 64 chars, hex-looking but uppercase — fails STRICT_SHA256_RE
      const upperHex = 'A'.repeat(64)
      const ctx = makeContext(makeUser({ sub: upperHex }), { id: upperHex })

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
      const ctx = makeContext(makeUser({ sub: 'admin-user', role: 'admin' }), {
        userId: 'other-user'
      })

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

  // ----------------- The id is one segment -----------------

  describe('the id parameter', () => {
    /** The error code a refused request carries, or `undefined` when the guard admitted it. */
    function codeFor(
      user: ReturnType<typeof makeUser>,
      params: Record<string, string | string[]>
    ): string | undefined {
      try {
        guard.canActivate(makeContext(user, params) as never)
        return undefined
      } catch (e) {
        const body = (e as AuthException).getResponse() as { error: { code: string } }
        return body.error.code
      }
    }

    // Scenario: the id is not one non-empty path segment: empty, or a decoded `%2F` that carries a
    // slash. Expected: refused for an admin and for the owner alike. Why: the id names one
    // resource, and a value that spans segments names a different one or none; the handler would
    // receive a path the route never matched.
    it.each([
      ['empty', ''],
      ['carrying a slash', 'user-1/../user-2'],
      ['a lone slash', '/']
    ])('should refuse an id that is %s, even for an admin', (_label, id) => {
      expect(codeFor(makeUser({ sub: 'admin-1', role: 'admin' }), { userId: id })).toBe(
        AUTH_ERROR_CODES.INSUFFICIENT_ROLE
      )
    })

    it('should refuse an owner whose own id carries a slash', () => {
      expect(codeFor(makeUser({ sub: 'a/b' }), { userId: 'a/b' })).toBe(
        AUTH_ERROR_CODES.INSUFFICIENT_ROLE
      )
    })

    // The segment rule comes before the session-hash rule, as the tenant rule does.
    it('should refuse the id before it looks at a hash-shaped value', () => {
      expect(
        codeFor(makeUser({ sub: 'admin-1', role: 'admin' }), {
          id: `${'A'.repeat(32)}/${'b'.repeat(31)}`
        })
      ).toBe(AUTH_ERROR_CODES.INSUFFICIENT_ROLE)
    })

    it('should still admit a plain id for its owner and for an admin', () => {
      expect(codeFor(makeUser({ sub: 'user-1' }), { userId: 'user-1' })).toBeUndefined()
      expect(
        codeFor(makeUser({ sub: 'admin-1', role: 'admin' }), { userId: 'user-9' })
      ).toBeUndefined()
    })
  })

  // ----------------- Tenant capture -----------------

  describe('a route that captures the tenant', () => {
    /** The error a refused request carries, or `undefined` when the guard admitted it. */
    function refusal(
      user: ReturnType<typeof makeUser>,
      params: Record<string, string | string[]>
    ): { status: number; code: string } | undefined {
      try {
        guard.canActivate(makeContext(user, params) as never)
        return undefined
      } catch (e) {
        const error = e as AuthException
        const body = error.getResponse() as { error: { code: string } }
        return { status: error.getStatus(), code: body.error.code }
      }
    }

    const REFUSED = { status: HttpStatus.FORBIDDEN, code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE }

    // Scenario: a member of tenant-1 asks for their own id on a route that names tenant-2.
    // Expected: refused with INSUFFICIENT_ROLE. Why: the id alone proves nothing across tenants,
    // since ids are only unique within one; the route says which tenant the resource is in.
    it('should refuse a user whose own id is requested under another tenant', () => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
          tenantId: 'tenant-2',
          userId: 'user-1'
        })
      ).toEqual(REFUSED)
    })

    // Scenario: an admin of tenant-1 asks for a user of tenant-2. Expected: refused. Why: the admin
    // role is held inside one tenant and carries no authority over another.
    it('should refuse an admin acting on another tenant', () => {
      expect(
        refusal(makeUser({ sub: 'admin-1', role: 'admin', tenantId: 'tenant-1' }), {
          tenantId: 'tenant-2',
          userId: 'user-9'
        })
      ).toEqual(REFUSED)
    })

    // Each of the three capture names the guard recognizes is held to the token's tenant.
    it.each(['tenantId', 'tenant_id', 'tenant'])(
      'should refuse a mismatching %s capture',
      (name) => {
        expect(
          refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
            [name]: 'tenant-2',
            userId: 'user-1'
          })
        ).toEqual(REFUSED)
      }
    )

    // The same capture equal to the token's tenant leaves the decision to the self-or-admin rule.
    it.each(['tenantId', 'tenant_id', 'tenant'])(
      'should admit a matching %s capture for the owner',
      (name) => {
        expect(
          refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
            [name]: 'tenant-1',
            userId: 'user-1'
          })
        ).toBeUndefined()
      }
    )

    it('should admit an admin of the same tenant on another user', () => {
      expect(
        refusal(makeUser({ sub: 'admin-1', role: 'admin', tenantId: 'tenant-1' }), {
          tenantId: 'tenant-1',
          userId: 'user-9'
        })
      ).toBeUndefined()
    })

    it('should still refuse a member of the same tenant on another user', () => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
          tenantId: 'tenant-1',
          userId: 'user-2'
        })
      ).toEqual(REFUSED)
    })

    // Scenario: two capture names are present and disagree. Expected: refused, even though one of
    // them equals the token's tenant. Why: the route is ambiguous about which tenant it means.
    it('should refuse captures that disagree, even when one matches', () => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
          tenantId: 'tenant-1',
          tenant: 'tenant-2',
          userId: 'user-1'
        })
      ).toEqual(REFUSED)
    })

    it('should admit captures that agree on the token tenant', () => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
          tenantId: 'tenant-1',
          tenant_id: 'tenant-1',
          userId: 'user-1'
        })
      ).toBeUndefined()
    })

    // A capture that is empty, or is an array, names no tenant the token can equal.
    it.each([
      ['an empty string', ''],
      ['an array', ['tenant-1']],
      ['an empty array', []]
    ])('should refuse a capture that is %s', (_label, value) => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
          tenantId: value as string | string[],
          userId: 'user-1'
        })
      ).toEqual(REFUSED)
    })

    // A token with no tenant cannot equal any capture.
    it('should refuse a token with no tenant when the route names one', () => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: '' }), {
          tenantId: 'tenant-1',
          userId: 'user-1'
        })
      ).toEqual(REFUSED)
    })

    // An empty tenant on the token equals an empty capture, and neither names a tenant.
    it('should refuse an empty capture when the token tenant is empty too', () => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: '' }), { tenantId: '', userId: 'user-1' })
      ).toEqual(REFUSED)
    })

    // A wildcard capture that carries the tenant arrives as the array of the segments it matched
    // (Express 5 `*tenant`), whatever its length, so it is refused even for an admin.
    it.each([
      ['one segment', ['tenant-1']],
      ['two segments', ['tenant-1', 'x']],
      ['a star', ['*']]
    ])('should refuse a wildcard tenant capture of %s even for an admin', (_label, value) => {
      expect(
        refusal(makeUser({ sub: 'admin-1', role: 'admin', tenantId: 'tenant-1' }), {
          tenant: value,
          userId: 'user-9'
        })
      ).toEqual(REFUSED)
    })

    // A literal star is only the value of a named capture: it is not the token's tenant, so it is
    // refused for a member and for an admin alike.
    it('should refuse a literal star as the tenant, even for an admin', () => {
      expect(
        refusal(makeUser({ sub: 'admin-1', role: 'admin', tenantId: 'tenant-1' }), {
          tenantId: '*',
          userId: 'user-9'
        })
      ).toEqual(REFUSED)
    })

    // Scenario: a cross-tenant request that would also fail another check. Expected: the tenant
    // refusal comes first, so INSUFFICIENT_ROLE and not TOKEN_INVALID. Why: a cross-tenant request
    // must not learn anything from a later check, and must never reach the role decision.
    it('should refuse on the tenant before it looks at the id', () => {
      const upperHash = 'A'.repeat(64)
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), {
          tenantId: 'tenant-2',
          id: upperHash
        })
      ).toEqual(REFUSED)
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), { tenantId: 'tenant-2' })
      ).toEqual(REFUSED)
    })

    // Routes that capture no tenant are decided exactly as before: by identity and role.
    it('should leave a route without a tenant capture to the self-or-admin rule', () => {
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), { userId: 'user-1' })
      ).toBeUndefined()
      expect(
        refusal(makeUser({ sub: 'admin-1', role: 'admin', tenantId: 'tenant-1' }), {
          userId: 'user-9'
        })
      ).toBeUndefined()
      expect(
        refusal(makeUser({ sub: 'user-1', tenantId: 'tenant-1' }), { userId: 'user-2' })
      ).toEqual(REFUSED)
    })
  })
})
