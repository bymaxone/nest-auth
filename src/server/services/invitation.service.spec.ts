/**
 * @fileoverview Tests for InvitationService.
 *
 * Verifies the complete invitation lifecycle:
 *   - invite()           — authorization checks, token generation, Redis storage, email dispatch
 *   - acceptInvitation() — atomic token consumption, type guarding, user creation, hook callback
 *
 * All external dependencies (Redis, email provider, user repository, password service,
 * token manager) are replaced with Jest mocks so no real I/O occurs.
 *
 * sha256 is imported directly (not mocked) to compute expected Redis keys for
 * acceptInvitation() key-format assertions. It is a pure deterministic function
 * with no observable side effects in these tests.
 *
 * isStoredInvitation() is a private module-level function. Its branches are exercised
 * indirectly through the acceptInvitation() tests that feed various Redis payloads.
 */

import { ForbiddenException } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-one-nest-auth.constants'
import { sha256 } from '../crypto/secure-token'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { InvitationService } from './invitation.service'
import { PasswordService } from './password.service'
import { SessionService } from './session.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/**
 * Full inviter record with admin role — sufficient to invite a member.
 * Role 'admin' inherits 'member' in the mockOptions hierarchy.
 */
const INVITER = {
  id: 'inviter-1',
  email: 'admin@example.com',
  name: 'Admin User',
  passwordHash: 'scrypt:salt:hash',
  role: 'admin',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

/**
 * Created user record returned by userRepo.create after accepting an invitation.
 * Includes mfaSecret and mfaRecoveryCodes to verify they are stripped by destructuring
 * before being passed to the afterInvitationAccepted hook.
 */
const AUTH_USER = {
  id: 'new-user-1',
  email: 'invited@example.com',
  name: 'Invited User',
  passwordHash: 'scrypt:salt:newhash',
  role: 'member',
  status: 'active',
  tenantId: 'tenant-1',
  emailVerified: true,
  mfaEnabled: false,
  mfaSecret: 'totp-secret',
  mfaRecoveryCodes: ['code1', 'code2'],
  lastLoginAt: null,
  createdAt: new Date('2026-01-01')
}

const AUTH_RESULT = {
  user: {
    id: 'new-user-1',
    email: 'invited@example.com',
    name: 'Invited User',
    role: 'member',
    status: 'active',
    tenantId: 'tenant-1',
    emailVerified: true,
    mfaEnabled: false,
    lastLoginAt: null,
    createdAt: new Date('2026-01-01')
  },
  accessToken: 'access.jwt',
  rawRefreshToken: 'raw-refresh'
}

/**
 * A valid stored invitation object as would be found in Redis (pre-serialized).
 * All fields are strings, satisfying the isStoredInvitation type guard.
 */
const VALID_STORED_INVITATION = {
  email: 'invited@example.com',
  role: 'member',
  tenantId: 'tenant-1',
  inviterUserId: 'inviter-1',
  createdAt: '2026-01-01T00:00:00.000Z'
}

/**
 * A 64-character hex token matching the expected output of generateSecureToken(32).
 * Used as dto.token in all acceptInvitation() tests.
 */
const VALID_TOKEN = 'a'.repeat(64)

const mockUserRepo = {
  findById: jest.fn(),
  findByEmail: jest.fn(),
  create: jest.fn()
}

const mockEmailProvider = {
  sendInvitation: jest.fn()
}

const mockHooks = {
  afterInvitationAccepted: jest.fn()
}

const mockRedis = {
  set: jest.fn(),
  getdel: jest.fn()
}

const mockPasswordService = {
  hash: jest.fn()
}

const mockTokenManager = {
  issueTokens: jest.fn()
}

const mockSessionService = {
  createSession: jest.fn()
}

/**
 * Denormalized role hierarchy for all tests.
 * admin inherits member (can invite members).
 * member has no inherited roles (cannot invite anyone above themselves).
 */
const mockOptions = {
  roles: {
    hierarchy: {
      admin: ['member'],
      member: [] as string[]
    }
  },
  invitations: {
    tokenTtlSeconds: 86_400
  },
  sessions: {
    enabled: false
  }
}

// Shared request metadata for acceptInvitation() tests
const TEST_IP = '1.2.3.4'
const TEST_AGENT = 'TestBrowser/1.0'
// Includes 'authorization' to verify sanitizeHeaders strips it before the hook call.
const TEST_HEADERS: Record<string, string | string[] | undefined> = {
  'content-type': 'application/json',
  authorization: 'Bearer secret'
}

// ---------------------------------------------------------------------------
// InvitationService — invite() + acceptInvitation()
// ---------------------------------------------------------------------------

describe('InvitationService', () => {
  let service: InvitationService

  beforeEach(async () => {
    jest.clearAllMocks()

    const module = await Test.createTestingModule({
      providers: [
        InvitationService,
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
        { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
        { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
        { provide: PasswordService, useValue: mockPasswordService },
        { provide: SessionService, useValue: mockSessionService },
        { provide: TokenManagerService, useValue: mockTokenManager },
        { provide: AuthRedisService, useValue: mockRedis }
      ]
    }).compile()

    service = module.get(InvitationService)
  })

  // ---------------------------------------------------------------------------
  // invite()
  // ---------------------------------------------------------------------------

  describe('invite', () => {
    beforeEach(() => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      mockRedis.set.mockResolvedValue('OK')
      mockEmailProvider.sendInvitation.mockResolvedValue(undefined)
    })

    // Verifies the happy path: a valid admin inviting a member stores the token and sends the email.
    it('should store token in Redis and send invitation email on success', async () => {
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendInvitation).toHaveBeenCalledTimes(1)
    })

    // Verifies that the Redis key uses the inv:{sha256} prefix with a 64-char hex hash.
    it('should store the invitation under a key matching /^inv:[0-9a-f]{64}$/', async () => {
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      const [key] = mockRedis.set.mock.calls[0] as [string, string, number]
      expect(key).toMatch(/^inv:[0-9a-f]{64}$/)
    })

    // Verifies that the TTL is taken from the configured invitations.tokenTtlSeconds option.
    it('should store the invitation with the configured tokenTtlSeconds as TTL', async () => {
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      const [, , ttl] = mockRedis.set.mock.calls[0] as [string, string, number]
      expect(ttl).toBe(mockOptions.invitations.tokenTtlSeconds)
    })

    // Verifies that all required invitation fields (email, role, tenantId, inviterUserId, createdAt) are persisted.
    it('should store correct invitation data as JSON with all required fields', async () => {
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      const [, raw] = mockRedis.set.mock.calls[0] as [string, string, number]
      const stored = JSON.parse(raw) as Record<string, unknown>
      expect(stored['email']).toBe('invited@example.com')
      expect(stored['role']).toBe('member')
      expect(stored['tenantId']).toBe('tenant-1')
      expect(stored['inviterUserId']).toBe('inviter-1')
      expect(typeof stored['createdAt']).toBe('string')
    })

    // Verifies that the email address is normalized (lowercased and trimmed) at the service boundary.
    it('should normalize email to lowercase and trim whitespace before storing', async () => {
      await service.invite('inviter-1', '  UPPER@EXAMPLE.COM  ', 'member', 'tenant-1')

      const [, raw] = mockRedis.set.mock.calls[0] as [string, string, number]
      const stored = JSON.parse(raw) as { email: string }
      expect(stored.email).toBe('upper@example.com')
    })

    // Verifies that the normalized email (not the raw input) is used in the sendInvitation call.
    it('should send invitation email to the normalized email address', async () => {
      await service.invite('inviter-1', '  UPPER@EXAMPLE.COM  ', 'member', 'tenant-1')

      const [toEmail] = mockEmailProvider.sendInvitation.mock.calls[0] as [string]
      expect(toEmail).toBe('upper@example.com')
    })

    // Verifies that InviteData includes the inviter's name, the provided tenantName, and a 64-char token.
    it('should send InviteData with inviterName, tenantName, 64-char inviteToken, and a future expiresAt', async () => {
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1', 'Acme Corp')

      type InvitePayload = {
        inviterName: string
        tenantName: string
        inviteToken: string
        expiresAt: Date
      }
      const [, inviteData] = mockEmailProvider.sendInvitation.mock.calls[0] as [
        string,
        InvitePayload
      ]
      expect(inviteData.inviterName).toBe(INVITER.name)
      expect(inviteData.tenantName).toBe('Acme Corp')
      expect(inviteData.inviteToken).toHaveLength(64)
      expect(inviteData.expiresAt).toBeInstanceOf(Date)
      expect(inviteData.expiresAt.getTime()).toBeGreaterThan(Date.now())
    })

    // Verifies the tenantName ?? tenantId fallback: when tenantName is omitted, the tenantId is used in the email.
    it('should fall back to tenantId as display name when tenantName is not provided', async () => {
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      const [, inviteData] = mockEmailProvider.sendInvitation.mock.calls[0] as [
        string,
        { tenantName: string }
      ]
      expect(inviteData.tenantName).toBe('tenant-1')
    })

    // Verifies that a role not present in the hierarchy causes ForbiddenException before any DB lookup.
    it('should throw ForbiddenException with INSUFFICIENT_ROLE for an unknown role', async () => {
      await expect(
        service.invite('inviter-1', 'invited@example.com', 'unknown-role', 'tenant-1')
      ).rejects.toThrow(ForbiddenException)

      expect(mockUserRepo.findById).not.toHaveBeenCalled()
    })

    // Verifies that a deleted inviter account (JWT references non-existent user) throws TOKEN_INVALID.
    it('should throw AuthException when the inviter user record is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toThrow(AuthException)
    })

    // Verifies the specific error code used when the inviter does not exist.
    it('should use TOKEN_INVALID error code when the inviter user is not found', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      let caught: unknown
      try {
        await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      } catch (err) {
        caught = err
      }

      const resp = (caught as AuthException).getResponse() as { error?: { code?: string } }
      expect(resp.error?.code).toBe(AUTH_ERROR_CODES.TOKEN_INVALID)
    })

    // Verifies that an inviter whose role is below the requested role (member inviting admin) is rejected.
    it('should throw ForbiddenException with INSUFFICIENT_ROLE when inviter role is insufficient', async () => {
      // A member inviter cannot invite an admin (member has no inherited roles).
      const memberInviter = { ...INVITER, role: 'member' }
      mockUserRepo.findById.mockResolvedValue(memberInviter)

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'admin', 'tenant-1')
      ).rejects.toThrow(ForbiddenException)
    })
  })

  // ---------------------------------------------------------------------------
  // acceptInvitation()
  // ---------------------------------------------------------------------------

  describe('acceptInvitation', () => {
    beforeEach(() => {
      mockRedis.getdel.mockResolvedValue(JSON.stringify(VALID_STORED_INVITATION))
      mockUserRepo.findByEmail.mockResolvedValue(null)
      mockPasswordService.hash.mockResolvedValue('scrypt:salt:newhash')
      mockUserRepo.create.mockResolvedValue(AUTH_USER)
      mockTokenManager.issueTokens.mockResolvedValue(AUTH_RESULT)
      mockHooks.afterInvitationAccepted.mockResolvedValue(undefined)
    })

    // Verifies the full happy path: token consumed, user created, tokens issued, hook fired, result returned.
    it('should create user, issue tokens, call hook, and return AuthResult on success', async () => {
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      const result = await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      expect(result).toBe(AUTH_RESULT)
      expect(mockUserRepo.create).toHaveBeenCalledTimes(1)
      expect(mockTokenManager.issueTokens).toHaveBeenCalledTimes(1)
      expect(mockHooks.afterInvitationAccepted).toHaveBeenCalledTimes(1)
    })

    // Verifies that getdel is called with the exactly derived inv:{sha256(dto.token)} key.
    it('should call redis.getdel with inv:{sha256(dto.token)}', async () => {
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }
      await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      const expectedKey = `inv:${sha256(VALID_TOKEN)}`
      expect(mockRedis.getdel).toHaveBeenCalledWith(expectedKey)
    })

    // Verifies that a null from getdel (token not found / already consumed) is rejected immediately.
    it('should throw AuthException(INVALID_INVITATION_TOKEN) when Redis has no matching key', async () => {
      mockRedis.getdel.mockResolvedValue(null)
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
    })

    // Verifies the specific error code when the token lookup returns nothing.
    it('should use INVALID_INVITATION_TOKEN code when token is not in Redis', async () => {
      mockRedis.getdel.mockResolvedValue(null)

      let caught: unknown
      try {
        await service.acceptInvitation(
          { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' },
          TEST_IP,
          TEST_AGENT,
          TEST_HEADERS
        )
      } catch (err) {
        caught = err
      }

      const resp = (caught as AuthException).getResponse() as { error?: { code?: string } }
      expect(resp.error?.code).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
    })

    // Verifies that a syntactically invalid JSON value stored in Redis triggers the catch branch.
    it('should throw AuthException(INVALID_INVITATION_TOKEN) when stored value is malformed JSON', async () => {
      mockRedis.getdel.mockResolvedValue('{not-valid-json}')
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
    })

    // Verifies the isStoredInvitation null-check branch: JSON.parse('null') returns null,
    // which fails the typeof value !== 'object' || value === null guard and throws.
    it('should throw AuthException(INVALID_INVITATION_TOKEN) when stored JSON is null', async () => {
      mockRedis.getdel.mockResolvedValue('null')
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
    })

    // Verifies the isStoredInvitation non-object branch: a JSON string primitive
    // (typeof === 'string', not 'object') fails the guard immediately.
    it('should throw AuthException(INVALID_INVITATION_TOKEN) when stored JSON is a primitive string', async () => {
      // JSON.parse('"some-string"') = "some-string" — typeof 'string' !== 'object' is true
      mockRedis.getdel.mockResolvedValue('"some-string"')
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
    })

    // Verifies the isStoredInvitation field-type branch: an object with a non-string email fails the guard.
    it('should throw AuthException(INVALID_INVITATION_TOKEN) when stored JSON has wrong field types', async () => {
      // email is a number — fails typeof v['email'] === 'string' check in isStoredInvitation
      const badPayload = {
        email: 123,
        role: 'member',
        tenantId: 'tenant-1',
        inviterUserId: 'u',
        createdAt: '2026-01-01'
      }
      mockRedis.getdel.mockResolvedValue(JSON.stringify(badPayload))
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
    })

    // Verifies the Redis-tamper guard: a stored role not in the configured hierarchy is rejected.
    it('should throw AuthException(INVALID_INVITATION_TOKEN) when stored role is not in hierarchy', async () => {
      const tampered = { ...VALID_STORED_INVITATION, role: 'superadmin' }
      mockRedis.getdel.mockResolvedValue(JSON.stringify(tampered))
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
    })

    // Verifies that a duplicate email in the same tenant is rejected before creating the user.
    it('should throw AuthException(EMAIL_ALREADY_EXISTS) when email is already registered in the tenant', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(AUTH_USER)
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
    })

    // Verifies the specific error code for the duplicate-email rejection.
    it('should use EMAIL_ALREADY_EXISTS code when email is already registered', async () => {
      mockUserRepo.findByEmail.mockResolvedValue(AUTH_USER)

      let caught: unknown
      try {
        await service.acceptInvitation(
          { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' },
          TEST_IP,
          TEST_AGENT,
          TEST_HEADERS
        )
      } catch (err) {
        caught = err
      }

      const resp = (caught as AuthException).getResponse() as { error?: { code?: string } }
      expect(resp.error?.code).toBe(AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS)
    })

    // Verifies that invitation acceptance sets emailVerified: true, since the invitation implies email ownership.
    it('should create the user with emailVerified: true', async () => {
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      expect(mockUserRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ emailVerified: true })
      )
    })

    // Verifies that the hook receives safeUser without credential fields (passwordHash, mfaSecret, mfaRecoveryCodes).
    it('should call hook with safeUser that excludes passwordHash, mfaSecret, and mfaRecoveryCodes', async () => {
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      const [userArg] = mockHooks.afterInvitationAccepted.mock.calls[0] as [Record<string, unknown>]
      expect(userArg).not.toHaveProperty('passwordHash')
      expect(userArg).not.toHaveProperty('mfaSecret')
      expect(userArg).not.toHaveProperty('mfaRecoveryCodes')
      expect(userArg['id']).toBe(AUTH_USER.id)
      expect(userArg['email']).toBe(AUTH_USER.email)
    })

    // Verifies that the hook context contains the correct ip, userAgent, and sanitized headers.
    // The authorization header must be stripped by sanitizeHeaders before reaching the hook.
    it('should call hook with correct ip, userAgent, and headers sanitized (authorization stripped)', async () => {
      const headers = { 'content-type': 'application/json', authorization: 'Bearer secret' }
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, headers)

      type HookContext = {
        ip: string
        userAgent: string
        sanitizedHeaders: Record<string, unknown>
      }
      const [, context] = mockHooks.afterInvitationAccepted.mock.calls[0] as [unknown, HookContext]
      expect(context.ip).toBe(TEST_IP)
      expect(context.userAgent).toBe(TEST_AGENT)
      // sanitizeHeaders must remove the authorization header
      expect(context.sanitizedHeaders).not.toHaveProperty('authorization')
      expect(context.sanitizedHeaders['content-type']).toBe('application/json')
    })

    // Verifies the sessions.enabled=true branch: createSession must be called with the correct
    // userId and rawRefreshToken so the accepted invitation account is visible in session management.
    it('should call sessionService.createSession when sessions.enabled is true', async () => {
      const sessionsEnabledOptions = { ...mockOptions, sessions: { enabled: true } }
      const sessionsModule = await Test.createTestingModule({
        providers: [
          InvitationService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: sessionsEnabledOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: mockHooks },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: AuthRedisService, useValue: mockRedis }
        ]
      }).compile()

      const svcWithSessions = sessionsModule.get(InvitationService)
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      await svcWithSessions.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      expect(mockSessionService.createSession).toHaveBeenCalledTimes(1)
      expect(mockSessionService.createSession).toHaveBeenCalledWith(
        AUTH_USER.id,
        AUTH_RESULT.rawRefreshToken,
        TEST_IP,
        TEST_AGENT
      )
    })

    // Verifies that the service completes without error when afterInvitationAccepted is not defined on hooks.
    it('should complete normally when the afterInvitationAccepted hook is not defined', async () => {
      // Re-build service with an empty hooks object (no afterInvitationAccepted method).
      const noHookModule = await Test.createTestingModule({
        providers: [
          InvitationService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: {} },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: AuthRedisService, useValue: mockRedis }
        ]
      }).compile()

      const svcNoHook = noHookModule.get(InvitationService)
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }

      await expect(
        svcNoHook.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).resolves.toBe(AUTH_RESULT)
    })
  })
})
