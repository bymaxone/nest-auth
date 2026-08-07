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

import { Logger } from '@nestjs/common'
import { Test } from '@nestjs/testing'

import {
  BYMAX_AUTH_EMAIL_PROVIDER,
  BYMAX_AUTH_HOOKS,
  BYMAX_AUTH_OPTIONS,
  BYMAX_AUTH_USER_REPOSITORY
} from '../bymax-auth.constants'
import { hmacSha256, sha256 } from '../crypto/secure-token'
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
  get: jest.fn(),
  del: jest.fn(),
  getdel: jest.fn(),
  // The invitee index is claimed by compare-and-swap, so the script answers 1 for "claimed".
  // The default is the ordinary case: nothing pending, and this caller wins the claim.
  eval: jest.fn().mockResolvedValue(1)
}

const mockPasswordService = {
  hash: jest.fn(),
  assertNotCompromised: jest.fn().mockResolvedValue(undefined),
  assertAcceptable: jest.fn().mockResolvedValue(undefined),
  assertLongEnough: jest.fn()
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
/** The server secret the invitee index is keyed under — the address is HMAC'd, never bare. */
const HMAC_KEY = 'invitation-spec-hmac-key'

const mockOptions = {
  hmacKey: HMAC_KEY,
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
  },
  blockedStatuses: ['BANNED', 'INACTIVE', 'SUSPENDED']
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

      // One `set` — the invitation record. The invitee index is claimed through the atomic
      // read-and-set, so it is not a second `set`.
      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendInvitation).toHaveBeenCalledTimes(1)
    })

    // Scenario: an admin of tenant-1 invites into tenant-2. Expected: refused, and nothing is
    // stored or sent. Why: the only other authorization here is the role-hierarchy check,
    // which says *what* role the inviter holds and nothing about *where* they hold it — so an
    // ADMIN of one tenant could mint an invitation that provisions an ADMIN account inside a
    // tenant they have no relationship with. The shipped controller sources `tenantId` from
    // the caller's own claims, which hides it, but this is a library whose service layer
    // consumers call directly.
    it('should refuse to invite into a tenant the inviter does not belong to', async () => {
      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-2')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE } }
      })

      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
    })

    // Scenario: the same refusal for an inviter whose role would otherwise permit it. Expected:
    // still refused. Why: the tenant check must not be reachable-around by holding a high
    // enough role — cross-tenant is cross-tenant regardless of seniority.
    it('should refuse a cross-tenant invite even from the highest role', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...INVITER, role: 'admin' })

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'admin', 'other-tenant')
      ).rejects.toThrow(AuthException)
      expect(mockRedis.set).not.toHaveBeenCalled()
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

    // Scenario: a successful invite; expected: expiresAt is roughly `now + tokenTtlSeconds*1000`.
    // Why: the prior test only checks expiresAt > now, which a `ttl * 1000 -> ttl / 1000` mutant
    // (~86 ms ahead) also satisfies. Pinning the delta to ~ttl*1000 (within tolerance) kills it.
    it('should set expiresAt to approximately now + tokenTtlSeconds (multiplication, not division)', async () => {
      const before = Date.now()
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      const after = Date.now()

      const [, inviteData] = mockEmailProvider.sendInvitation.mock.calls[0] as [
        string,
        { expiresAt: Date }
      ]
      const expectedMs = mockOptions.invitations.tokenTtlSeconds * 1_000
      const delta = inviteData.expiresAt.getTime() - before
      // Lower bound = expected minus the call duration; upper bound = expected plus small slack.
      expect(delta).toBeGreaterThanOrEqual(expectedMs - (after - before) - 1_000)
      expect(delta).toBeLessThanOrEqual(expectedMs + 1_000)
    })

    // Scenario: a successful invite; expected: an info log identifying the created invitation is
    // emitted. Why: pins the "invite: invitation created" template so emptying it is caught — the
    // invite() method returns void, so the log is the only observable success signal here.
    it('should log the invitation-created event on success', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      const logged = logSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('invite: invitation created')
      logSpy.mockRestore()
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
    it('should throw AuthException with INSUFFICIENT_ROLE for an unknown role', async () => {
      await expect(
        service.invite('inviter-1', 'invited@example.com', 'unknown-role', 'tenant-1')
      ).rejects.toThrow(AuthException)

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
    it('should throw AuthException with INSUFFICIENT_ROLE when inviter role is insufficient', async () => {
      // A member inviter cannot invite an admin (member has no inherited roles).
      const memberInviter = { ...INVITER, role: 'member' }
      mockUserRepo.findById.mockResolvedValue(memberInviter)

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'admin', 'tenant-1')
      ).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // acceptInvitation()
  // ---------------------------------------------------------------------------

  describe('acceptInvitation', () => {
    beforeEach(() => {
      mockRedis.getdel.mockResolvedValue(JSON.stringify(VALID_STORED_INVITATION))
      // The inviter is re-read at redemption: their authority is what the invitation rests on,
      // and authority is revocable. By default they are still in good standing.
      mockUserRepo.findById.mockResolvedValue({
        id: 'inviter-1',
        email: 'inviter@example.com',
        status: 'active',
        role: 'admin',
        tenantId: 'tenant-1'
      })
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

    // An invitation is a delegation of authority, and authority is revocable. Validating it
    // only at creation meant a 48-hour token carried whatever power its author had when they
    // clicked send: an admin could invite, then be banned and stripped of their role, and the
    // invitee would still arrive as an admin of that tenant with a live session. That is a
    // clean way to keep a foothold across the account kill switch, which makes the switch
    // advisory.
    it.each([
      ['banned', { status: 'banned', role: 'admin', tenantId: 'tenant-1' }],
      ['moved to another tenant', { status: 'active', role: 'admin', tenantId: 'tenant-2' }],
      ['deleted', null]
    ])('refuses an invitation whose inviter was %s', async (_label, inviter) => {
      mockUserRepo.findById.mockResolvedValue(
        inviter === null ? null : { id: 'inviter-1', email: 'i@e.com', ...inviter }
      )

      await expect(
        service.acceptInvitation(
          { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' },
          TEST_IP,
          TEST_AGENT,
          TEST_HEADERS
        )
      ).rejects.toMatchObject({
        // Answered as an invalid token, not a role error: the redeemer is not the one who lost
        // authority, and saying why would describe the inviter's account status to a stranger.
        response: { error: { code: AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN } }
      })
      expect(mockUserRepo.create).not.toHaveBeenCalled()
    })

    // Demotion is the same failure by another route: the invitation grants `admin`, and by the
    // time it is redeemed its author is only a `member`. The hierarchy check that ran at
    // creation has to run again, against who they are now.
    it('refuses an invitation whose inviter no longer out-ranks the granted role', async () => {
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ ...VALID_STORED_INVITATION, role: 'admin' })
      )
      mockUserRepo.findById.mockResolvedValue({
        id: 'inviter-1',
        email: 'i@e.com',
        status: 'active',
        role: 'member',
        tenantId: 'tenant-1'
      })

      await expect(
        service.acceptInvitation(
          { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' },
          TEST_IP,
          TEST_AGENT,
          TEST_HEADERS
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN } }
      })
      expect(mockUserRepo.create).not.toHaveBeenCalled()
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
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockRedis.getdel.mockResolvedValue('{not-valid-json}')
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
      // The invitee gets the same code as for an expired token, by design. The operator gets
      // the one line that says the record was corrupted rather than stale.
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('not parseable JSON'))
      warnSpy.mockRestore()
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

    // Scenario: stored payload where `role` is an ARRAY (not a string) but every other field is
    // valid and the array stringifies to a real hierarchy key (['admin'] -> 'admin'); expected:
    // rejected and no user created. Why: the isStoredInvitation `typeof role === 'string'` clause
    // is the only guard — bypassing it (clause -> true) would let the array slip past the later
    // Object.hasOwn(hierarchy, role) check (which coerces ['admin'] to 'admin') and create a user.
    it('should reject and not create a user when stored role is an array (role-type guard)', async () => {
      const tampered = { ...VALID_STORED_INVITATION, role: ['admin'] }
      mockRedis.getdel.mockResolvedValue(JSON.stringify(tampered))
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      let caught: unknown
      try {
        await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      } catch (err) {
        caught = err
      }
      expect(caught).toBeInstanceOf(AuthException)
      const resp = (caught as AuthException).getResponse() as { error?: { code?: string } }
      expect(resp.error?.code).toBe(AUTH_ERROR_CODES.INVALID_INVITATION_TOKEN)
      expect(mockUserRepo.create).not.toHaveBeenCalled()
    })

    // Scenario: stored payload where `tenantId` is a number (not a string), all else valid;
    // expected: rejected and no user created. Why: only the isStoredInvitation
    // `typeof tenantId === 'string'` clause rejects it — bypassing it (clause -> true) would
    // create the user with a numeric tenantId (tenantId is never re-checked downstream).
    it('should reject and not create a user when stored tenantId is not a string (tenantId-type guard)', async () => {
      const tampered = { ...VALID_STORED_INVITATION, tenantId: 123 }
      mockRedis.getdel.mockResolvedValue(JSON.stringify(tampered))
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
      expect(mockUserRepo.create).not.toHaveBeenCalled()
    })

    // Scenario: stored payload where `inviterUserId` is a number, all else valid; expected:
    // rejected and no user created. Why: only the `typeof inviterUserId === 'string'` clause
    // rejects it — bypassing it (clause -> true) would create the user (inviterUserId is unused
    // downstream so nothing else would fail).
    it('should reject and not create a user when stored inviterUserId is not a string (inviterUserId-type guard)', async () => {
      const tampered = { ...VALID_STORED_INVITATION, inviterUserId: 42 }
      mockRedis.getdel.mockResolvedValue(JSON.stringify(tampered))
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
      expect(mockUserRepo.create).not.toHaveBeenCalled()
    })

    // Scenario: stored payload where `createdAt` is a number, all else valid; expected: rejected
    // and no user created. Why: only the `typeof createdAt === 'string'` clause rejects it —
    // bypassing it (clause -> true) would create the user (createdAt is unused downstream).
    it('should reject and not create a user when stored createdAt is not a string (createdAt-type guard)', async () => {
      const tampered = { ...VALID_STORED_INVITATION, createdAt: 1_700_000_000 }
      mockRedis.getdel.mockResolvedValue(JSON.stringify(tampered))
      const dto = { token: VALID_TOKEN, name: 'Jane', password: 'Secure123!' }

      await expect(
        service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).rejects.toThrow(AuthException)
      expect(mockUserRepo.create).not.toHaveBeenCalled()
    })

    // Scenario: sessions are DISABLED (the default options); expected: createSession is never
    // called after a successful acceptance. Why: kills the `if (sessions.enabled)` -> `if (true)`
    // mutant, which would create a tracked session even when the feature is off.
    it('should NOT call sessionService.createSession when sessions.enabled is false', async () => {
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      expect(mockSessionService.createSession).not.toHaveBeenCalled()
    })

    // Scenario: hooks injected as null (no hooks object at all); expected: acceptInvitation still
    // resolves. Why: the `this.hooks?.afterInvitationAccepted` optional chain protects against a
    // null hooks container — removing the `?.` would dereference null and throw a TypeError.
    it('should resolve when the hooks container is null (optional-chaining guard)', async () => {
      const nullHooksModule = await Test.createTestingModule({
        providers: [
          InvitationService,
          { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
          { provide: BYMAX_AUTH_USER_REPOSITORY, useValue: mockUserRepo },
          { provide: BYMAX_AUTH_EMAIL_PROVIDER, useValue: mockEmailProvider },
          { provide: BYMAX_AUTH_HOOKS, useValue: null },
          { provide: PasswordService, useValue: mockPasswordService },
          { provide: SessionService, useValue: mockSessionService },
          { provide: TokenManagerService, useValue: mockTokenManager },
          { provide: AuthRedisService, useValue: mockRedis }
        ]
      }).compile()

      const svcNullHooks = nullHooksModule.get(InvitationService)
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }

      await expect(
        svcNullHooks.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)
      ).resolves.toBe(AUTH_RESULT)
    })

    // Scenario: a successful acceptance; expected: an info log identifying the acceptance event
    // is emitted. Why: pins the "acceptInvitation: invitation accepted" template so emptying it
    // is caught — the success path is otherwise observable only via the returned AuthResult.
    it('should log the invitation-accepted event on success', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      const logged = logSpy.mock.calls.map((c) => String(c[0])).join(' ')
      expect(logged).toContain('acceptInvitation: invitation accepted')
      logSpy.mockRestore()
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

    // Verifies that a throwing afterInvitationAccepted hook is logged and does not propagate.
    it('should log the error and still return AuthResult when afterInvitationAccepted hook throws', async () => {
      // Arrange
      mockHooks.afterInvitationAccepted.mockRejectedValue(new Error('hook failed'))
      const dto = { token: VALID_TOKEN, name: 'Invited User', password: 'Secure123!' }
      const loggerSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined)

      // Act — service must resolve even though the hook will reject
      const result = await service.acceptInvitation(dto, TEST_IP, TEST_AGENT, TEST_HEADERS)

      // Flush microtask queue so the fire-and-forget .catch handler runs
      await new Promise<void>((resolve) => setImmediate(resolve))

      // Assert
      expect(result).toBe(AUTH_RESULT)
      expect(loggerSpy).toHaveBeenCalledWith(
        'afterInvitationAccepted hook threw',
        expect.any(Error)
      )
      loggerSpy.mockRestore()
    })
  })

  // The stored record is trusted on accept, so its SHAPE is re-checked first: a value whose
  // `role` or `tenantId` is not a string would flow into the created account and the issued
  // session. The guard reads every field, and each field needs its own case — a record missing
  // one is otherwise refused by the neighbouring clause and the gap is invisible.
  // The consume is a single-use `GETDEL`, so anything that fails after it destroys the
  // invitation rather than merely refusing the request. A breached password is a RECOVERABLE
  // client error — the invitee picks another one and retries — so screening after the consume
  // told them their password was unacceptable and, in the same breath, that the only credential
  // they had to fix it was gone. `PasswordResetService.resetPassword` was refactored away from
  // exactly this shape; the reasoning had not reached here.
  describe('a recoverable client error must not spend the invitation', () => {
    it('screens the password before consuming the token', async () => {
      // `Once`, so the rejection cannot leak into a later case — these mocks are shared and
      // not reset between tests.
      mockPasswordService.assertAcceptable.mockRejectedValueOnce(
        new AuthException(AUTH_ERROR_CODES.PASSWORD_COMPROMISED)
      )
      mockRedis.getdel.mockClear()

      await expect(
        service.acceptInvitation(
          { token: 'a'.repeat(64), name: 'N', password: 'password' },
          '1.2.3.4',
          'agent',
          {}
        )
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.PASSWORD_COMPROMISED } }
      })

      // THE property: the token was never spent, so the invitee can simply retry.
      expect(mockRedis.getdel).not.toHaveBeenCalled()
    })
  })

  describe('acceptInvitation record shape', () => {
    it.each([
      ['role', { ...VALID_STORED_INVITATION, role: 42 }],
      ['tenantId', { ...VALID_STORED_INVITATION, tenantId: null }],
      ['email', { ...VALID_STORED_INVITATION, email: undefined }],
      ['inviterUserId', { ...VALID_STORED_INVITATION, inviterUserId: 7 }],
      ['createdAt', { ...VALID_STORED_INVITATION, createdAt: 1_700_000_000 }]
    ])('refuses a stored record whose %s is not a string', async (_field, record) => {
      mockRedis.getdel.mockResolvedValue(JSON.stringify(record))

      await expect(
        service.acceptInvitation(
          { token: VALID_TOKEN, name: 'New User', password: 'gliding-walnut-forecast' },
          TEST_IP,
          TEST_AGENT,
          TEST_HEADERS
        )
      ).rejects.toThrow(AuthException)
      // Refused before any account was created — the shape check is the first gate for a
      // reason.
      expect(mockUserRepo.create).not.toHaveBeenCalled()
    })

    // A role the hierarchy does not declare is what a tampered Redis value looks like. The
    // inviter re-validation catches most of these on its own — `hasRole` cannot grant a role
    // it has never heard of — but not when the tampered role happens to be the inviter's OWN,
    // because `hasRole` grants a role to itself. That corner is what this check is for, and
    // this is the only case that can tell the two apart.
    it('refuses a role the hierarchy does not declare, even when it is the inviter own role', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...INVITER, role: 'ghost-role' })
      mockRedis.getdel.mockResolvedValue(
        JSON.stringify({ ...VALID_STORED_INVITATION, role: 'ghost-role' })
      )

      await expect(
        service.acceptInvitation(
          { token: VALID_TOKEN, name: 'New User', password: 'gliding-walnut-forecast' },
          TEST_IP,
          TEST_AGENT,
          TEST_HEADERS
        )
      ).rejects.toThrow(AuthException)
      expect(mockUserRepo.create).not.toHaveBeenCalled()
    })

    // The refusal is logged with the inviter and the role, which is what an operator needs to
    // tell a revoked delegation from a corrupted record.
    it('logs which inviter lost the authority the invitation rests on', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)
      mockUserRepo.findById.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(JSON.stringify(VALID_STORED_INVITATION))

      await expect(
        service.acceptInvitation(
          { token: VALID_TOKEN, name: 'New User', password: 'gliding-walnut-forecast' },
          TEST_IP,
          TEST_AGENT,
          TEST_HEADERS
        )
      ).rejects.toThrow(AuthException)

      const warned = warnSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(warned).toContain('the inviter can no longer grant this invitation')
      expect(warned).toContain('inviterUserId=inviter-1')
      expect(warned).toContain('role=member')
      warnSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // revokeInvitation()
  // ---------------------------------------------------------------------------

  describe('revokeInvitation', () => {
    /** The index key the service derives for the fixture invitee. */
    const INDEX_KEY = `invidx:tenant-1:${hmacSha256('invited@example.com', HMAC_KEY)}`
    const TOKEN_HASH = 'b'.repeat(64)

    beforeEach(() => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      mockRedis.get.mockImplementation((key: string) =>
        Promise.resolve(key === INDEX_KEY ? TOKEN_HASH : JSON.stringify(VALID_STORED_INVITATION))
      )
      mockRedis.del.mockResolvedValue(true)
    })

    // The capability the module has always documented and never had: an invitation is a
    // credential that provisions an account at a role, and it was unwithdrawable for its
    // whole TTL.
    it('deletes the invitation and its index', async () => {
      await expect(
        service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')
      ).resolves.toBe(true)

      expect(mockRedis.del).toHaveBeenCalledWith(INDEX_KEY)
      expect(mockRedis.del).toHaveBeenCalledWith(`inv:${TOKEN_HASH}`)
      // The record is READ under the same key it is deleted under, or the role check below
      // would be reading someone else's invitation — or nothing at all, which reads as
      // "unparseable" and withdraws without a role check.
      expect(mockRedis.get).toHaveBeenCalledWith(`inv:${TOKEN_HASH}`)
    })

    // The withdrawal is logged with the address masked and the tenant and revoker named: the
    // three things an operator reconstructing "who cancelled this invitation" needs, and the
    // one thing — the address in the clear — they must not get from a log line.
    it('logs the withdrawal with the address masked', async () => {
      const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined)

      await service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')

      const logged = logSpy.mock.calls.map((call) => String(call[0])).join(' ')
      expect(logged).toContain('revokeInvitation: invitation withdrawn')
      expect(logged).toContain('tenantId=tenant-1')
      expect(logged).toContain('revokerUserId=inviter-1')
      expect(logged).not.toContain('invited@example.com')
      logSpy.mockRestore()
    })

    // The address is normalized the same way it was on the way in, or the lookup misses the
    // index it wrote and every revoke silently reports "nothing pending".
    it('normalizes the address before looking it up', async () => {
      await service.revokeInvitation('inviter-1', '  INVITED@Example.com  ', 'tenant-1')

      expect(mockRedis.get).toHaveBeenCalledWith(INDEX_KEY)
    })

    // Idempotent, and deliberately silent about which case it was: answering differently
    // would turn the endpoint into an oracle for "does this address have an invitation".
    it('answers false when there is nothing pending', async () => {
      mockRedis.get.mockResolvedValue(null)

      await expect(
        service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')
      ).resolves.toBe(false)
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // A member must not be able to cancel an admin's invitations — the revoker is held to
    // the same bar as the issuer.
    // The refusal is silent, and that is the point. The caller names an address and nothing
    // else, so a 403 would say "there is a pending invitation here, at a role above yours"
    // while a 204 says "there is none" — an oracle any member could walk an address list
    // through, which is exactly what hashing the address into the index exists to prevent.
    it('answers a revoker who does not out-rank the invited role exactly as it answers an address with no invitation', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...INVITER, role: 'member' })
      mockRedis.get.mockImplementation((key: string) =>
        Promise.resolve(
          key === INDEX_KEY
            ? TOKEN_HASH
            : JSON.stringify({ ...VALID_STORED_INVITATION, role: 'admin' })
        )
      )

      const outranked = await service.revokeInvitation(
        'inviter-1',
        'invited@example.com',
        'tenant-1'
      )
      expect(mockRedis.del).not.toHaveBeenCalled()

      // The same caller, against an address with nothing pending.
      mockRedis.get.mockResolvedValue(null)
      const absent = await service.revokeInvitation('inviter-1', 'nobody@example.com', 'tenant-1')

      expect(outranked).toBe(false)
      expect(outranked).toBe(absent)
    })

    // A suspended admin holding a live access token is not making authority decisions.
    it('refuses a blocked revoker', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...INVITER, status: 'SUSPENDED' })

      await expect(
        service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')
      ).rejects.toThrow(AuthException)
    })

    // Cross-tenant: the caller's own claims decide the tenant, and a caller from another one
    // is refused before any lookup happens.
    it('refuses a revoker from a different tenant', async () => {
      await expect(
        service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-2')
      ).rejects.toThrow(AuthException)
      expect(mockRedis.get).not.toHaveBeenCalled()
    })

    // The JWT names a user that no longer exists.
    it('refuses when the revoker is gone', async () => {
      mockUserRepo.findById.mockResolvedValue(null)

      await expect(
        service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')
      ).rejects.toThrow(AuthException)
    })

    // A record that no longer parses is withdrawn without a role check: it can no longer be
    // accepted either, and leaving it indexed would be worse than removing it.
    it('withdraws an unparseable record without a role check', async () => {
      mockRedis.get.mockImplementation((key: string) =>
        Promise.resolve(key === INDEX_KEY ? TOKEN_HASH : 'not-json')
      )

      await expect(
        service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')
      ).resolves.toBe(true)
    })

    // …and one whose shape is wrong, and one whose record has already expired out from under
    // the index. Both reach the same place by a different route.
    it.each([
      ['a record of the wrong shape', '{"nope":true}'],
      ['a record that has already expired', null]
    ])('withdraws over %s', async (_label, record) => {
      mockRedis.get.mockImplementation((key: string) =>
        Promise.resolve(key === INDEX_KEY ? TOKEN_HASH : record)
      )

      await expect(
        service.revokeInvitation('inviter-1', 'invited@example.com', 'tenant-1')
      ).resolves.toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // supersede-on-reinvite
  // ---------------------------------------------------------------------------

  describe('invite supersedes a pending invitation', () => {
    // Two live tokens for one invitee is two chances for an intercepted link to be redeemed,
    // and a revoke would only ever reach the newest — the older would sit valid and
    // unreferenced for the rest of its TTL.
    it('drops the previous invitation for the same address', async () => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      // The pending invitation the supersede will displace: readable for the rank check, and
      // returned by the atomic index claim as the hash that was displaced.
      mockRedis.get.mockResolvedValue('c'.repeat(64))
      mockRedis.eval.mockResolvedValue(1)
      mockRedis.set.mockResolvedValue('OK')
      mockRedis.del.mockResolvedValue(true)
      mockEmailProvider.sendInvitation.mockResolvedValue(undefined)

      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      // The claim is a compare-and-swap against the hash the rank check approved, so the two
      // steps cannot disagree about WHICH invitation is being superseded.
      expect(mockRedis.eval).toHaveBeenCalledWith(
        expect.stringContaining('~= ARGV[3]'),
        [`invidx:tenant-1:${hmacSha256('invited@example.com', HMAC_KEY)}`],
        expect.arrayContaining([expect.any(String), expect.any(String), 'c'.repeat(64)])
      )
      expect(mockRedis.del).toHaveBeenCalledWith(`inv:${'c'.repeat(64)}`)
    })

    // …and does not delete anything when the invitee had no pending invitation.
    it('deletes nothing when there was none', async () => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      mockRedis.get.mockResolvedValue(null)
      mockRedis.eval.mockResolvedValue(1)
      mockRedis.set.mockResolvedValue('OK')
      mockEmailProvider.sendInvitation.mockResolvedValue(undefined)

      await service.invite('inviter-1', 'fresh@example.com', 'member', 'tenant-1')

      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // The index can outlive the record it names: the `inv:` key has the same TTL but a revoke
    // deletes them in sequence, and a crash between the two leaves the index pointing at
    // nothing. There is no role to compare against, so the supersede proceeds — the dangling
    // index is replaced, which is the cleanup this path would want anyway.
    it('supersedes freely when the index names a record that is gone', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...INVITER, role: 'member' })
      mockRedis.get.mockImplementation((key: string) =>
        Promise.resolve(key.startsWith('invidx:') ? 'c'.repeat(64) : null)
      )
      mockRedis.eval.mockResolvedValue(1)
      mockRedis.set.mockResolvedValue('OK')
      mockRedis.del.mockResolvedValue(true)
      mockEmailProvider.sendInvitation.mockResolvedValue(undefined)

      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      expect(mockEmailProvider.sendInvitation).toHaveBeenCalledTimes(1)
      expect(mockRedis.del).toHaveBeenCalledWith(`inv:${'c'.repeat(64)}`)
    })

    // The rank check and the index claim are separate round trips, so on their own they can
    // disagree about WHICH invitation is being superseded: an outranked caller passes the check
    // while the index is momentarily empty, then displaces a higher-ranked invitation created
    // in between. The claim is a compare-and-swap against the hash the check approved, so a
    // record that moved makes the claim fail and the approval is re-derived against what is
    // actually there — where the rank check now sees the ADMIN invitation and refuses.
    it('refuses when the pending invitation changes under the rank check', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...INVITER, role: 'member' })
      // First pass: the index is empty, so there is nothing to out-rank. Every pass after it
      // sees an ADMIN invitation — the one that landed in between.
      let pass = 0
      mockRedis.get.mockImplementation((key: string) => {
        if (key.startsWith('invidx:')) {
          pass += 1
          return Promise.resolve(pass === 1 ? null : 'c'.repeat(64))
        }
        return Promise.resolve(
          JSON.stringify({
            email: 'invited@example.com',
            role: 'admin',
            tenantId: 'tenant-1',
            inviterUserId: 'someone-senior',
            createdAt: new Date().toISOString()
          })
        )
      })
      // The compare-and-swap fails: the index no longer holds what the first pass approved.
      mockRedis.eval.mockResolvedValue(0)

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE } }
      })

      // Nothing was displaced and no replacement was minted.
      expect(mockRedis.del).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
    })

    // Contention between two callers who are BOTH allowed to supersede is not an authorisation
    // failure, so the approval is re-derived and the retry proceeds rather than refusing.
    it('re-derives its approval and proceeds when it loses one claim', async () => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      mockRedis.get.mockResolvedValue('c'.repeat(64))
      // Lose the first claim, win the second.
      mockRedis.eval.mockResolvedValueOnce(0).mockResolvedValue(1)
      mockRedis.set.mockResolvedValue('OK')
      mockRedis.del.mockResolvedValue(true)
      mockEmailProvider.sendInvitation.mockResolvedValue(undefined)

      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      expect(mockRedis.eval).toHaveBeenCalledTimes(2)
      expect(mockEmailProvider.sendInvitation).toHaveBeenCalledTimes(1)
    })

    // `eval` is typed `unknown`, and a client that surfaces the Lua integer reply as a string
    // is within its rights. Comparing straight to `1` would read every successful claim as
    // contention on such a client — three lost passes, then a refusal, for an invitation that
    // was in fact claimed each time. Both spellings must mean the same thing here.
    it.each([
      ['a numeric reply', 1],
      ['a string reply', '1']
    ])('accepts %s from the claim script', async (_case, reply) => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      mockRedis.get.mockResolvedValue('c'.repeat(64))
      mockRedis.eval.mockResolvedValue(reply)
      mockRedis.set.mockResolvedValue('OK')
      mockRedis.del.mockResolvedValue(true)
      mockEmailProvider.sendInvitation.mockResolvedValue(undefined)

      await service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')

      expect(mockRedis.eval).toHaveBeenCalledTimes(1)
      expect(mockEmailProvider.sendInvitation).toHaveBeenCalledTimes(1)
    })

    // The retry has to be bounded, and the bound has to fail closed. An address under sustained
    // contention — the shape a script hammering one invitee produces — would otherwise spin
    // here indefinitely, and giving up by *proceeding* would mint the invitation on an approval
    // that no longer describes what the index holds. Neither is acceptable, so an exhausted
    // budget refuses: the caller has not been shown to be allowed to destroy whatever is there.
    it('refuses once the retry budget is exhausted, without minting anything', async () => {
      mockUserRepo.findById.mockResolvedValue(INVITER)
      mockRedis.get.mockResolvedValue('c'.repeat(64))
      // Every claim loses — the index keeps moving between the rank check and the swap.
      mockRedis.eval.mockResolvedValue(0)
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined)

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE } }
      })

      // Bounded, and the bound is the constant — not "eventually gives up".
      expect(mockRedis.eval).toHaveBeenCalledTimes(3)
      expect(mockRedis.set).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('the pending invitation kept changing under the rank check')
      )
      warnSpy.mockRestore()
    })

    // Superseding DESTROYS a pending invitation — the same end state `revokeInvitation`
    // produces, and that route is deliberately strict: the caller must out-rank the role the
    // invitation grants, and an outranked one is answered as if no invitation existed so the
    // endpoint is not an oracle. `create`'s own check is about the role being REQUESTED, which
    // says nothing about the role being destroyed, so any tenant member could delete a pending
    // ADMIN invitation by inviting the same address at MEMBER — a capability the revoke route
    // refuses them and refuses even to confirm exists.
    it('refuses to supersede an invitation the caller is outranked by', async () => {
      mockUserRepo.findById.mockResolvedValue({ ...INVITER, role: 'member' })
      mockRedis.get.mockImplementation((key: string) =>
        Promise.resolve(
          key.startsWith('invidx:')
            ? 'c'.repeat(64)
            : JSON.stringify({
                email: 'invited@example.com',
                role: 'admin',
                tenantId: 'tenant-1',
                inviterUserId: 'someone-senior',
                createdAt: new Date().toISOString()
              })
        )
      )

      await expect(
        service.invite('inviter-1', 'invited@example.com', 'member', 'tenant-1')
      ).rejects.toMatchObject({
        response: { error: { code: AUTH_ERROR_CODES.INSUFFICIENT_ROLE } }
      })

      // Nothing was displaced, and no replacement was minted.
      expect(mockRedis.eval).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
      expect(mockEmailProvider.sendInvitation).not.toHaveBeenCalled()
    })
  })
})
