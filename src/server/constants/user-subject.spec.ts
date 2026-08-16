import { userSubject } from './user-subject'

/**
 * The subject every MFA store key and MFA failure counter is derived from. Its exact shape is a
 * byte-for-byte agreement with rust-auth — the conformance contract pins it — so these tests pin
 * the format and, above all, the plane-driven rule that keeps the platform preimage tenant-free.
 */
describe('userSubject', () => {
  // The dashboard subject carries the tenant so that two tenants' user `1` — which a host that
  // numbers users per tenant will produce — derive different keys.
  it('scopes a dashboard subject by tenant and user', () => {
    expect(userSubject('dashboard', 'user-1', 'tenant-1')).toBe('dashboard:tenant-1:user-1')
  })

  // The platform subject carries no tenant segment: platform admins are cross-tenant and have none.
  it('derives a platform subject from the user alone', () => {
    expect(userSubject('platform', 'admin-1', undefined)).toBe('platform:admin-1')
  })

  // Driven by the plane, NOT by whether a tenant was supplied — so a caller that passes a tenant on
  // the platform plane cannot move the preimage off `platform:{userId}`. This is the property that
  // keeps a platform admin's keys from being relocated by a stray argument.
  it('ignores a tenant supplied on the platform plane', () => {
    expect(userSubject('platform', 'admin-1', 'tenant-1')).toBe('platform:admin-1')
    expect(userSubject('platform', 'admin-1', 'tenant-1')).toBe(
      userSubject('platform', 'admin-1', undefined)
    )
  })

  // The whole point: user `1` in one tenant and user `1` in another must not share a subject.
  it('gives two tenants distinct subjects for the same user id', () => {
    expect(userSubject('dashboard', 'user-1', 'tenant-a')).not.toBe(
      userSubject('dashboard', 'user-1', 'tenant-b')
    )
  })

  // A dashboard subject and a platform subject for the same id never collide — the planes are
  // distinguished even before the tenant is considered.
  it('never collides a dashboard subject with a platform subject', () => {
    expect(userSubject('dashboard', 'shared-id', 'tenant-1')).not.toBe(
      userSubject('platform', 'shared-id', undefined)
    )
  })
})
