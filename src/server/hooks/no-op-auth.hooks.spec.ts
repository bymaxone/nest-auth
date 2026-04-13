import { Test } from '@nestjs/testing'

import type { HookContext, IAuthHooks } from '../interfaces/auth-hooks.interface'
import type { OAuthProfile } from '../interfaces/oauth-provider.interface'
import type { SafeAuthUser } from '../interfaces/user-repository.interface'
import { NoOpAuthHooks } from './no-op-auth.hooks'

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const CONTEXT: HookContext = {
  ip: '127.0.0.1',
  userAgent: 'TestAgent',
  sanitizedHeaders: {}
}

const PROFILE: OAuthProfile = {
  provider: 'google',
  providerId: 'google-uid-123',
  email: 'user@example.com',
  name: 'Test User'
}

const EXISTING_USER: SafeAuthUser = {
  id: 'user-1',
  email: 'user@example.com',
  name: 'Test User',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('NoOpAuthHooks', () => {
  let hooks: NoOpAuthHooks

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [NoOpAuthHooks]
    }).compile()

    hooks = module.get(NoOpAuthHooks)
  })

  // ---------------------------------------------------------------------------
  // beforeRegister
  // ---------------------------------------------------------------------------

  describe('beforeRegister', () => {
    // Verifies that the no-op implementation always allows registration by returning { allowed: true }.
    it('should always return { allowed: true }', () => {
      const result = hooks.beforeRegister(
        { email: 'user@example.com', name: 'Test', tenantId: 'tenant-1' },
        CONTEXT
      )
      expect(result).toEqual({ allowed: true })
    })

    // Verifies that the no-op hook does not reject any registration regardless of the input data.
    it('should return { allowed: true } regardless of input', () => {
      const result = hooks.beforeRegister(
        { email: 'blocked@blacklist.com', name: 'Attacker', tenantId: 'tenant-x' },
        CONTEXT
      )
      expect(result.allowed).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // onOAuthLogin
  // ---------------------------------------------------------------------------

  describe('onOAuthLogin', () => {
    // Verifies that when no existing user is found, the no-op hook returns { action: 'create' }.
    it('should return { action: "create" } when no existing user is found', () => {
      const result = hooks.onOAuthLogin(PROFILE, null, CONTEXT)
      expect(result).toEqual({ action: 'create' })
    })

    // Verifies that when the existing user email matches the profile email, the hook returns { action: 'link' }.
    it('should return { action: "link" } when existing user email matches profile email', () => {
      const result = hooks.onOAuthLogin(PROFILE, EXISTING_USER, CONTEXT)
      expect(result).toEqual({ action: 'link' })
    })

    // Verifies that when the existing user email does not match the profile email, the hook returns { action: 'reject' }.
    it('should return { action: "reject" } when existing user email does not match profile email', () => {
      const mismatchedUser: SafeAuthUser = { ...EXISTING_USER, email: 'other@example.com' }
      const result = hooks.onOAuthLogin(PROFILE, mismatchedUser, CONTEXT)
      expect(result.action).toBe('reject')
      expect(result.reason).toBeDefined()
    })
  })

  // ---------------------------------------------------------------------------
  // Optional hooks — NoOpAuthHooks only implements beforeRegister and onOAuthLogin;
  // all other hooks are undefined (not present on the class).
  // ---------------------------------------------------------------------------

  describe('optional hooks', () => {
    // Verifies that afterRegister is not implemented on NoOpAuthHooks (no-op by omission).
    it('should not implement afterRegister (no-op by omission)', () => {
      const hooksAsInterface = hooks as IAuthHooks
      expect(hooksAsInterface.afterRegister).toBeUndefined()
    })

    // Verifies that afterLogin is not implemented on NoOpAuthHooks (no-op by omission).
    it('should not implement afterLogin (no-op by omission)', () => {
      const hooksAsInterface = hooks as IAuthHooks
      expect(hooksAsInterface.afterLogin).toBeUndefined()
    })

    // Verifies that afterLogout is not implemented on NoOpAuthHooks (no-op by omission).
    it('should not implement afterLogout (no-op by omission)', () => {
      const hooksAsInterface = hooks as IAuthHooks
      expect(hooksAsInterface.afterLogout).toBeUndefined()
    })
  })
})
