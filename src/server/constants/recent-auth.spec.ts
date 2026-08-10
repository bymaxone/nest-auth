import { RECENT_AUTH_TTL_SECONDS, recentAuthKey } from './recent-auth'

/**
 * The recent-authentication marker is what lets the library ask "did this caller authenticate
 * *just now*", as opposed to "does it hold a token minted at some point". It is the whole proof
 * behind enrolling MFA on an account with no local password, so the shape of its key is a
 * security property rather than a formatting choice.
 */
describe('recentAuthKey', () => {
  const HMAC_KEY = 'a-test-hmac-key-of-sufficient-length'

  // The keyspace is shared with rust-auth and readable by anyone with access to the store. A
  // bare id there is an account identifier in the clear, which is why every user-derived key in
  // this library is keyed rather than plain.
  it('never puts the account id in the key', () => {
    const key = recentAuthKey('dashboard', 'user-1', HMAC_KEY, 'tenant-1')

    expect(key).toMatch(/^ra:[0-9a-f]{64}$/)
    expect(key).not.toContain('user-1')
  })

  // A dashboard user and a platform admin come from different consumer repositories and may
  // carry the same id. Without the plane in the preimage one could satisfy the other's
  // freshness check — the same collision the `lf:` lockout identifier was fixed for.
  it('binds the marker to its authentication plane', () => {
    const dashboard = recentAuthKey('dashboard', 'shared-id', HMAC_KEY, 'tenant-1')
    const platform = recentAuthKey('platform', 'shared-id', HMAC_KEY, undefined)

    expect(dashboard).not.toBe(platform)
  })

  // The library may not assume ids are unique across tenants — a host that numbers users per
  // tenant gives every tenant a user `1`. Without the tenant in the preimage, one tenant's user
  // would satisfy another tenant's freshness check.
  it('binds a dashboard marker to its tenant', () => {
    const tenantA = recentAuthKey('dashboard', 'user-1', HMAC_KEY, 'tenant-a')
    const tenantB = recentAuthKey('dashboard', 'user-1', HMAC_KEY, 'tenant-b')

    expect(tenantA).not.toBe(tenantB)
  })

  // The platform plane has no tenant, and the derivation is driven by the plane rather than by
  // whether a tenant was supplied — so a tenant passed on the platform plane cannot move the key.
  it('ignores a tenant supplied on the platform plane', () => {
    const withTenant = recentAuthKey('platform', 'admin-1', HMAC_KEY, 'tenant-1')
    const withoutTenant = recentAuthKey('platform', 'admin-1', HMAC_KEY, undefined)

    expect(withTenant).toBe(withoutTenant)
  })

  // Keyed, not hashed: an id carries far too little entropy for a plain digest to hide it, so a
  // key change must change every derived key.
  it('derives from the HMAC key, so a rotation invalidates the keyspace', () => {
    const first = recentAuthKey('dashboard', 'user-1', HMAC_KEY, 'tenant-1')
    const second = recentAuthKey(
      'dashboard',
      'user-1',
      'a-different-key-of-sufficient-length',
      'tenant-1'
    )

    expect(first).not.toBe(second)
  })

  it('is deterministic for the same inputs', () => {
    expect(recentAuthKey('dashboard', 'user-1', HMAC_KEY, 'tenant-1')).toBe(
      recentAuthKey('dashboard', 'user-1', HMAC_KEY, 'tenant-1')
    )
  })

  // Long enough that a user who signs in and then opens their security settings is not sent
  // back through the door; short enough that a session lifted hours later cannot spend it.
  // Pinned because widening it silently widens the window a stolen token has.
  it('treats an authentication as recent for five minutes', () => {
    expect(RECENT_AUTH_TTL_SECONDS).toBe(300)
  })
})
