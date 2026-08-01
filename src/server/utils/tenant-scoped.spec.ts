/**
 * Unit tests for `tenantScoped`.
 *
 * `IUserRepository.findByEmail` takes a `tenantId` and its contract says to scope by it, but
 * the repository is the host's and an interface can only ask. Under a host that ignores the
 * argument, every distinct `tenantId` in a request body resolves the same account while
 * deriving a different HMAC-keyed identifier — turning the brute-force lockout and the resend
 * cooldown into per-value budgets an attacker refills by rotating a field they control.
 */

import { tenantScoped } from './tenant-scoped'

describe('tenantScoped', () => {
  const user = { id: 'u1', tenantId: 'tenant-a' }

  // The ordinary case: a repository that scoped correctly.
  it('returns the user when the tenant matches', () => {
    expect(tenantScoped(user, 'tenant-a')).toBe(user)
  })

  // The defect this exists for: an account from another tenant collapses to the path the
  // callers already have for "no such account" — same generic error, same dummy-KDF timing,
  // same silent Ok. Nothing new is disclosed and the lockout stops being refillable.
  it('returns null when the repository answered outside the requested tenant', () => {
    expect(tenantScoped(user, 'tenant-b')).toBeNull()
  })

  // A genuinely absent account passes straight through.
  it('returns null for an absent user', () => {
    expect(tenantScoped(null, 'tenant-a')).toBeNull()
  })

  // The comparison is exact: a tenant id is an opaque identifier, and near-matches are
  // different tenants.
  it.each([['TENANT-A'], ['tenant-a '], [''], ['tenant-ab']])(
    'treats %p as a different tenant',
    (requested) => {
      expect(tenantScoped(user, requested)).toBeNull()
    }
  )
})
