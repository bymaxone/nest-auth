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
    expect(userSubject('dashboard', 'user-1', 'tenant-1')).toBe('dashboard:8:tenant-1:user-1')
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
  // The platform plane is unaffected: its subject carries no tenant segment, so an absent tenant
  // there is the correct shape. Guarding both planes with one rule would refuse every platform
  // key in the library.
  it('still builds a platform subject with no tenant', () => {
    expect(userSubject('platform', 'admin-1', undefined)).toBe('platform:admin-1')
  })
  // Injectivity, which is the property the whole keyspace rests on: two different (tenant, user)
  // pairs must never derive the same key. A bare `:` between the two components did not have it.
  // `tenant-id-charset.spec.ts` deliberately admits `acme.eu-west-1:prod`, and `assertSubject`
  // documents composite `tenant:user` subjects, so both halves can legitimately contain the
  // delimiter — and then `('acme:prod','u1')` and `('acme','prod:u1')` produced the same preimage,
  // the same HMAC, and therefore ONE session index, ONE token epoch, one set of MFA store keys
  // and one recovery-code claim shared by two unrelated tenants.
  it('derives different subjects when the delimiter appears inside a component', () => {
    const a = userSubject('dashboard', 'u1', 'acme:prod')
    const b = userSubject('dashboard', 'prod:u1', 'acme')

    expect(a).not.toBe(b)
    // Spelled out, so a future encoding change has to face what it breaks rather than just
    // keeping "they differ" true by accident.
    expect(a).toBe('dashboard:9:acme:prod:u1')
    expect(b).toBe('dashboard:4:acme:prod:u1')
  })

  // The prefix counts UTF-8 BYTES, not `String.length`. JavaScript counts UTF-16 code units and
  // Rust counts bytes, and this preimage is byte-shared with `@bymax-one/rust-auth`: `'açaí'` is
  // 4 by one measure and 6 by the other, so `.length` would agree for ASCII and derive a
  // different key on the first accented tenant id — the exact split this contract exists to stop.
  it('counts the tenant in UTF-8 bytes, not UTF-16 code units', () => {
    expect(userSubject('dashboard', 'u1', 'açaí')).toBe('dashboard:6:açaí:u1')
  })

  // The platform arm carries ONE component after the plane, so it has nothing to disambiguate and
  // keeps its shape. Prefixing it would change a keyspace for no gain and break the pairing.
  it('leaves the platform subject unprefixed', () => {
    expect(userSubject('platform', 'admin-1', undefined)).toBe('platform:admin-1')
  })
})
