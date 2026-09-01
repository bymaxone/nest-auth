/**
 * @fileoverview Tests for UserStatusGuard, the HTTP adapter over AccountStatusService.
 *
 * The lifecycle decision itself — the cache shape, the miss path, the order of the two refusals —
 * is covered by `account-status.service.spec.ts`. What is left here, and what these tests pin, is
 * the adapter: which account the guard names from the request, that an unauthenticated request is
 * passed through without asking at all, and that a refusal propagates rather than being converted
 * into a `false`.
 */

import { Test } from '@nestjs/testing'

import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AccountStatusService } from '../services/account-status.service'
import { UserStatusGuard } from './user-status.guard'

const mockAccountStatus = {
  assertDashboardAccountUsable: jest.fn()
}

/** Builds an execution context whose request carries the given principal, or none. */
function makeContext(user: { sub: string; tenantId?: string } | undefined) {
  // Every authenticated principal carries a tenant; default one so the delegated ref is
  // tenant-scoped exactly as it is in production.
  const withTenant = user === undefined ? undefined : { tenantId: 'tenant-1', ...user }
  return {
    switchToHttp: () => ({
      getRequest: () => ({ user: withTenant })
    })
  }
}

describe('UserStatusGuard', () => {
  let guard: UserStatusGuard

  beforeEach(async () => {
    jest.clearAllMocks()
    const module = await Test.createTestingModule({
      providers: [UserStatusGuard, { provide: AccountStatusService, useValue: mockAccountStatus }]
    }).compile()
    guard = module.get(UserStatusGuard)
  })

  // A request with no principal (a @Public() route) passes through without consulting the gate at
  // all — asking would cost a Redis read for a route that has no account to ask about.
  it('passes through a request with no authenticated user, without delegating', async () => {
    await expect(guard.canActivate(makeContext(undefined) as never)).resolves.toBe(true)
    expect(mockAccountStatus.assertDashboardAccountUsable).not.toHaveBeenCalled()
  })

  // The account the guard names must carry BOTH claims. A repository id is unique only within a
  // tenant, so delegating a bare id would let the gate answer for a colliding id elsewhere.
  it('delegates the JWT subject and tenant, and allows the request when the gate resolves', async () => {
    mockAccountStatus.assertDashboardAccountUsable.mockResolvedValue(undefined)

    await expect(guard.canActivate(makeContext({ sub: 'user-1' }) as never)).resolves.toBe(true)

    expect(mockAccountStatus.assertDashboardAccountUsable).toHaveBeenCalledWith({
      userId: 'user-1',
      tenantId: 'tenant-1'
    })
  })

  // The tenant is read from the token, not defaulted: a principal in another tenant must produce a
  // lookup in that tenant.
  it('forwards a non-default tenant verbatim', async () => {
    mockAccountStatus.assertDashboardAccountUsable.mockResolvedValue(undefined)

    await guard.canActivate(makeContext({ sub: 'u2', tenantId: 'acme' }) as never)

    expect(mockAccountStatus.assertDashboardAccountUsable).toHaveBeenCalledWith({
      userId: 'u2',
      tenantId: 'acme'
    })
  })

  // A refusal must PROPAGATE with its own code. Swallowing it into a plain `false` would answer
  // 403 Forbidden with no code, losing the distinction a client renders — banned, suspended,
  // unverified all collapse to the same opaque denial.
  it('propagates the gate exception rather than answering false', async () => {
    mockAccountStatus.assertDashboardAccountUsable.mockRejectedValue(
      new AuthException(AUTH_ERROR_CODES.ACCOUNT_BANNED)
    )

    const thrown = await guard
      .canActivate(makeContext({ sub: 'user-1' }) as never)
      .catch((e: unknown) => e)

    expect(thrown).toBeInstanceOf(AuthException)
    const body = (thrown as AuthException).getResponse() as { error: { code: string } }
    expect(body.error.code).toBe(AUTH_ERROR_CODES.ACCOUNT_BANNED)
  })
})
