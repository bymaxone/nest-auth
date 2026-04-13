import { hasRole } from './roles.util'

// ---------------------------------------------------------------------------
// Denormalized hierarchy fixture — OWNER > ADMIN > MEMBER > VIEWER
// ---------------------------------------------------------------------------

const hierarchy: Record<string, string[]> = {
  OWNER: ['ADMIN', 'MEMBER', 'VIEWER'],
  ADMIN: ['MEMBER', 'VIEWER'],
  MEMBER: ['VIEWER'],
  VIEWER: []
}

describe('hasRole', () => {
  // Verifies that an exact match between userRole and requiredRole grants access without traversing the hierarchy.
  it('should return true on exact role match', () => {
    expect(hasRole('ADMIN', 'ADMIN', hierarchy)).toBe(true)
    expect(hasRole('VIEWER', 'VIEWER', hierarchy)).toBe(true)
    expect(hasRole('OWNER', 'OWNER', hierarchy)).toBe(true)
  })

  // Verifies that a higher-ranking role can access routes requiring any lower-ranking role it inherits.
  it('should return true when userRole inherits the required role', () => {
    expect(hasRole('OWNER', 'ADMIN', hierarchy)).toBe(true)
    expect(hasRole('OWNER', 'MEMBER', hierarchy)).toBe(true)
    expect(hasRole('OWNER', 'VIEWER', hierarchy)).toBe(true)
    expect(hasRole('ADMIN', 'MEMBER', hierarchy)).toBe(true)
    expect(hasRole('ADMIN', 'VIEWER', hierarchy)).toBe(true)
    expect(hasRole('MEMBER', 'VIEWER', hierarchy)).toBe(true)
  })

  // Verifies that a lower-ranking role cannot access routes that require a higher role.
  it('should return false when userRole does not inherit the required role', () => {
    expect(hasRole('VIEWER', 'MEMBER', hierarchy)).toBe(false)
    expect(hasRole('MEMBER', 'ADMIN', hierarchy)).toBe(false)
    expect(hasRole('ADMIN', 'OWNER', hierarchy)).toBe(false)
  })

  // Verifies that a role not present in the hierarchy map at all returns false.
  it('should return false when userRole is not in the hierarchy', () => {
    expect(hasRole('UNKNOWN_ROLE', 'MEMBER', hierarchy)).toBe(false)
  })

  // Verifies that when the requiredRole is not in the user's inherited list, access is denied.
  it('should return false when requiredRole is not in the inherited list', () => {
    expect(hasRole('VIEWER', 'SUPER_ADMIN', hierarchy)).toBe(false)
  })

  // Verifies that an empty hierarchy returns false for any non-exact role combination, but true for an exact match.
  it('should handle an empty hierarchy gracefully', () => {
    // Role not found in empty hierarchy → false
    expect(hasRole('ADMIN', 'MEMBER', {})).toBe(false)
    // Exact match bypasses hierarchy lookup → true
    expect(hasRole('ADMIN', 'ADMIN', {})).toBe(true)
  })

  // Verifies that a leaf role with an empty inherited list returns true only for an exact match.
  it('should handle a role with an empty inherited list', () => {
    // VIEWER has no inherited roles
    expect(hasRole('VIEWER', 'VIEWER', hierarchy)).toBe(true)
    expect(hasRole('VIEWER', 'ADMIN', hierarchy)).toBe(false)
  })
})
