import { createHash, createHmac } from 'node:crypto'

import { JwtService } from '@nestjs/jwt'
import { Test } from '@nestjs/testing'

import { BYMAX_AUTH_OPTIONS } from '../bymax-auth.constants'
import { AUTH_ERROR_CODES } from '../errors/auth-error-codes'
import { AuthException } from '../errors/auth-exception'
import { AuthRedisService } from '../redis/auth-redis.service'
import { TokenManagerService } from './token-manager.service'

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

const FIXED_JWT = 'signed.jwt.token'
const FIXED_UUID = '00000000-0000-0000-0000-000000000001'

/** Local sha256 helper mirroring the production crypto util — node:crypto.createHash is the real impl. */
function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/**
 * The refresh token every mint produces under the mocked `randomBytes`: 32 bytes of 0x11
 * rendered as 64 hex characters. Pinning the length here is what keeps the 256-bit format
 * from silently regressing to a shorter token.
 */
const FIXED_REFRESH_TOKEN = '11'.repeat(32)

/** SHA-256 of the minted refresh token — the hash keying every new refresh session. */
const NEW_HASH = sha256(FIXED_REFRESH_TOKEN)

const mockJwtService = {
  sign: jest.fn().mockReturnValue(FIXED_JWT),
  decode: jest.fn(),
  verify: jest.fn()
}

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  eval: jest.fn(),
  getdel: jest.fn(),
  sadd: jest.fn().mockResolvedValue(1),
  srem: jest.fn().mockResolvedValue(1),
  expire: jest.fn().mockResolvedValue(undefined),
  revokeAllUserTokens: jest.fn().mockResolvedValue(undefined)
}

const JWT_SECRET = 'test-jwt-secret-for-hmac-that-is-at-least-32-chars-long'

/**
 * HMAC key — mirrors the derivation in `resolveOptions.deriveHmacKey`.
 * Required because `TokenManagerService` reads `options.hmacKey` (not
 * `options.jwt.secret`) for Redis identifier HMACs.
 */
const HMAC_KEY = createHash('sha256')
  .update(`bymax-auth:hmac-key:v1:${JWT_SECRET}`, 'utf8')
  .digest('hex')

const mockOptions = {
  jwt: {
    accessExpiresIn: '15m',
    accessCookieMaxAgeMs: 900_000,
    refreshExpiresInDays: 7,
    refreshGraceWindowSeconds: 30,
    algorithm: 'HS256',
    secret: JWT_SECRET
  },
  hmacKey: HMAC_KEY
}

const SAFE_USER = {
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

const SAFE_ADMIN = {
  id: 'admin-1',
  email: 'admin@platform.com',
  name: 'Platform Admin',
  role: 'super-admin',
  status: 'active',
  mfaEnabled: false,
  lastLoginAt: null,
  createdAt: new Date('2026-01-01'),
  updatedAt: new Date('2026-01-01')
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

// Use inline values to avoid TDZ — jest.mock factories run before const declarations.
// `randomUUID` still backs the access token's jti; `randomBytes` backs the refresh token,
// which is now 32 CSPRNG bytes rendered as 64 hex characters rather than a UUID.
jest.mock('node:crypto', () => ({
  ...jest.requireActual('node:crypto'),
  randomUUID: jest.fn().mockReturnValue('00000000-0000-0000-0000-000000000001'),
  randomBytes: jest.fn((size: number) => Buffer.alloc(size, 0x11))
}))

describe('TokenManagerService', () => {
  let service: TokenManagerService

  beforeEach(async () => {
    jest.clearAllMocks()
    mockJwtService.sign.mockReturnValue(FIXED_JWT)
    // Default: no reuse sentinel exists, so the terminal reissue path treats an
    // unknown token as a plain invalid string. Reuse-detection tests override this.
    mockRedis.get.mockResolvedValue(null)
    // Reset getdel between tests: some reuse tests install a keyed mockImplementation
    // (grace vs rused: key) that clearAllMocks does not clear, so wipe it here to stop
    // it leaking into later tests. Re-seed the default to `null` (not the reset default
    // of `undefined`) so the double matches the real getdel contract of
    // `Promise<string | null>` — an `undefined` would fail the `=== null` guard in
    // handleReusedToken and spuriously enter the reuse branch. Tests override as needed.
    mockRedis.getdel.mockReset()
    mockRedis.getdel.mockResolvedValue(null)

    const module = await Test.createTestingModule({
      providers: [
        TokenManagerService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: BYMAX_AUTH_OPTIONS, useValue: mockOptions },
        { provide: AuthRedisService, useValue: mockRedis }
      ]
    }).compile()

    service = module.get(TokenManagerService)
  })

  // ---------------------------------------------------------------------------
  // issueAccess
  // ---------------------------------------------------------------------------

  describe('issueAccess', () => {
    // Verifies that issueAccess calls JwtService.sign with a generated jti and returns the signed token.
    it('should sign a JWT with a generated jti', () => {
      const token = service.issueAccess({
        sub: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        type: 'dashboard',
        status: 'active',
        mfaEnabled: false,
        mfaVerified: false
      })

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ sub: 'user-1', jti: FIXED_UUID }),
        expect.objectContaining({ expiresIn: '15m', algorithm: 'HS256' })
      )
      expect(token).toBe(FIXED_JWT)
    })
  })

  // ---------------------------------------------------------------------------
  // issueTokens
  // ---------------------------------------------------------------------------

  describe('issueTokens', () => {
    // Verifies that issueTokens stores the refresh session in Redis with the correct TTL in seconds.
    it('should store refresh session in Redis with correct TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issueTokens(SAFE_USER, '1.2.3.4', 'TestBrowser')

      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^rt:/),
        expect.any(String),
        7 * 86_400
      )
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.user).toEqual(SAFE_USER)
    })

    // Scenario: the minted refresh token's shape. Expected: 64 lowercase hex characters, i.e.
    // 32 CSPRNG bytes. Why: this token is a bearer credential that survives for days, and the
    // UUID v4 it replaced carried ~122 bits — six of its 128 bits are fixed version/variant
    // markers. Pinning the length here stops a future change quietly shortening it, and it is
    // the format the sibling Rust backend validates before it will even hash a presented token.
    it('mints a 256-bit refresh token rendered as 64 hex characters', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issueTokens(SAFE_USER, '1.2.3.4', 'Chrome')

      expect(result.rawRefreshToken).toMatch(/^[0-9a-f]{64}$/)
    })

    // Verifies that the stored session JSON contains the expected fields (userId, tenantId, role, ip, device).
    it('should store a JSON session with correct fields', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '127.0.0.1', 'Chrome')

      const storedJson = mockRedis.set.mock.calls[0]?.[1] as string
      const session = JSON.parse(storedJson) as Record<string, unknown>
      expect(session['userId']).toBe('user-1')
      expect(session['tenantId']).toBe('tenant-1')
      expect(session['role']).toBe('member')
      expect(session['ip']).toBe('127.0.0.1')
      expect(session['device']).toBe('Chrome')
    })

    // Scenario: issueTokens registers the new refresh token in the per-user SET and sets its TTL.
    // Expected: sadd('sess:user-1', 'rt:<newHash>') and expire('sess:user-1', 7*86400). Why: kills
    // the StringLiteral mutants on lines 190 (key → '', member → '') and 191 (expire key → '') by
    // pinning the exact `sess:` key shape, the `rt:` member value, and the TTL.
    it('adds the rt: member to sess:{userId} and expires the SET with the refresh TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '1.2.3.4', 'Chrome')

      expect(mockRedis.sadd).toHaveBeenCalledWith('sess:user-1', `rt:${NEW_HASH}`)
      expect(mockRedis.expire).toHaveBeenCalledWith('sess:user-1', 7 * 86_400)
    })

    // Scenario: a normal login (no MFA-complete override) must NOT mark the access token mfaVerified.
    // Expected: sign payload has mfaVerified:false. Why: kills the BooleanLiteral mutant on line 172
    // (`overrides?.mfaVerified ?? false` → `?? true`), a security regression that would skip the
    // MFA challenge after a plain password login.
    it('issues a dashboard access token with mfaVerified:false when no override is given', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issueTokens(SAFE_USER, '1.2.3.4', 'Chrome')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]).toMatchObject({ mfaVerified: false })
    })
  })

  // ---------------------------------------------------------------------------
  // issuePlatformTokens
  // ---------------------------------------------------------------------------

  describe('issuePlatformTokens', () => {
    // Verifies that the access token payload uses type 'platform' for platform admin sessions.
    it('should use type:platform in the access token payload', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'platform', sub: 'admin-1' }),
        expect.any(Object)
      )
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.admin).toEqual(SAFE_ADMIN)
    })

    // Verifies that platform refresh sessions are stored under the 'prt:' prefix to separate them from user sessions.
    it('should store the session under prt: prefix', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^prt:/),
        expect.any(String),
        7 * 86_400
      )
    })

    // Scenario: platform issuance registers the prt: member in sess:{adminId} and sets the TTL.
    // Expected: sadd('sess:admin-1', 'prt:<newHash>') and expire('sess:admin-1', 7*86400). Why:
    // kills the StringLiteral mutants on lines 234 (key → '', member → '') and 235 (expire key → '').
    it('adds the prt: member to psess:{adminId} and expires the SET with the refresh TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      expect(mockRedis.sadd).toHaveBeenCalledWith('psess:admin-1', `prt:${NEW_HASH}`)
      expect(mockRedis.expire).toHaveBeenCalledWith('psess:admin-1', 7 * 86_400)
    })

    // Scenario: the platform plane must not write into the dashboard session index. Expected: no
    // sadd targets sess:{adminId}. Why: a platform admin id and a dashboard user id come from
    // different repositories and may collide, so sharing the index let a dashboard revoke-all
    // log the same-id admin out. This pins the separation that fixes it.
    it('never indexes a platform session in the dashboard sess: SET', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const indexedKeys = mockRedis.sadd.mock.calls.map((call) => call[0] as string)
      expect(indexedKeys).not.toContain('sess:admin-1')
    })

    // Scenario: a platform session needs a detail record so a listing can describe it.
    // Expected: psd:{hash} holds the same field set the dashboard sd: record uses, with
    // Unix-millisecond timestamps. Why: the sibling Rust backend reads psd: when listing
    // platform sessions; without this write it would find nothing for a nest-created session.
    it('writes the psd: detail record with epoch-millisecond timestamps', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const detailCall = mockRedis.set.mock.calls.find(
        (call) => (call[0] as string) === `psd:${NEW_HASH}`
      )
      expect(detailCall).toBeDefined()
      const detail = JSON.parse(detailCall![1] as string) as Record<string, unknown>
      expect(detail).toMatchObject({ device: 'Firefox', ip: '1.2.3.4' })
      expect(typeof detail['createdAt']).toBe('number')
      expect(typeof detail['lastActivityAt']).toBe('number')
    })

    // Scenario: a platform admin has no tenant — the stored session tenantId must be an empty string.
    // Expected: stored session JSON has tenantId === ''. Why: kills the StringLiteral mutant on line
    // 229 that passes "Stryker was here!" as the tenantId to buildSession.
    it('stores an empty tenantId in the platform session record', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const storedJson = mockRedis.set.mock.calls[0]?.[1] as string
      const session = JSON.parse(storedJson) as Record<string, unknown>
      expect(session['tenantId']).toBe('')
    })

    // Scenario: a plain platform login (no override) must NOT mark the access token mfaVerified.
    // Expected: sign payload has mfaVerified:false. Why: kills the BooleanLiteral mutant on line 223
    // (`overrides?.mfaVerified ?? false` → `?? true`).
    it('issues a platform access token with mfaVerified:false when no override is given', async () => {
      mockRedis.set.mockResolvedValue(undefined)

      await service.issuePlatformTokens(SAFE_ADMIN, '1.2.3.4', 'Firefox')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]).toMatchObject({ mfaVerified: false })
    })
  })

  // ---------------------------------------------------------------------------
  // reissueTokens
  // ---------------------------------------------------------------------------

  describe('reissueTokens', () => {
    const OLD_SESSION = JSON.stringify({
      userId: 'user-1',
      tenantId: 'tenant-1',
      role: 'member',
      device: 'Browser',
      ip: '1.2.3.4',
      createdAt: '2026-01-01T00:00:00.000Z'
    })

    // Verifies that mfaEnabled:true in the stored session is propagated into the rotated access token.
    // This is a critical security property: MfaRequiredGuard must continue to enforce MFA after rotation.
    it('should propagate mfaEnabled:true from the stored session into the rotated access token', async () => {
      const sessionWithMfa = JSON.stringify({
        userId: 'user-1',
        tenantId: 'tenant-1',
        role: 'member',
        device: 'Browser',
        ip: '1.2.3.4',
        createdAt: '2026-01-01T00:00:00.000Z',
        mfaEnabled: true
      })
      mockRedis.eval.mockResolvedValue(sessionWithMfa)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]).toMatchObject({ mfaEnabled: true })
    })

    // Verifies that a primary rotation (existing session found via Lua eval) returns new tokens.
    it('should create a new session and return new tokens when old session exists', async () => {
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.eval).toHaveBeenCalled()
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      // RotatedTokenResult: identity in session field, not a full SafeAuthUser
      expect(result.session.userId).toBe('user-1')
      expect(result.session.tenantId).toBe('tenant-1')
      expect(result.session.role).toBe('member')
    })

    // Verifies that primary rotation writes a new session (rt:), a grace pointer
    // (rp:), and a reuse-detection sentinel (rused:) for the rotated-away token.
    it('should write new session, grace pointer, and reuse sentinel on primary rotation', async () => {
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      // Three redis.set calls: new session (rt:), grace pointer (rp:), reuse sentinel (rused:)
      expect(mockRedis.set).toHaveBeenCalledTimes(3)
      const keys = mockRedis.set.mock.calls.map((c: unknown[]) => String(c[0]))
      expect(keys.some((k) => k.startsWith('rt:'))).toBe(true)
      expect(keys.some((k) => k.startsWith('rp:'))).toBe(true)
      expect(keys.some((k) => k.startsWith('rused:'))).toBe(true)
    })

    // Verifies that primary rotation tracks the grace pointer in sess:{userId} so invalidateUserSessions can delete it.
    it('should add the grace pointer key to sess:{userId} SET on primary rotation', async () => {
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const saddCalls = mockRedis.sadd.mock.calls as unknown[][]
      const addedKeys = saddCalls.map((c) => String(c[1]))
      expect(addedKeys.some((k) => k.startsWith('rp:'))).toBe(true)
    })

    // Verifies that when the primary session key is null, the grace window pointer is checked via getdel.
    it('should use grace window session when Lua returns null', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_SESSION) // grace pointer found (atomic GETDEL)
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.getdel).toHaveBeenCalledWith(expect.stringMatching(/^rp:/))
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
    })

    // Verifies that grace-window rotation writes ONLY the new session key (rt:), never another
    // grace pointer (rp:). Chaining grace pointers would allow an attacker with a single captured
    // refresh token to indefinitely extend the session by consuming consecutive grace windows.
    it('should write only a new session (no new grace pointer) on grace-window rotation', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.set).toHaveBeenCalledTimes(1)
      const keys = mockRedis.set.mock.calls.map((c: unknown[]) => String(c[0]))
      expect(keys.some((k) => k.startsWith('rt:'))).toBe(true)
      expect(keys.some((k) => k.startsWith('rp:'))).toBe(false)
    })

    // Verifies that grace-window rotation registers only the new `rt:` session under sess:{userId}.
    // No `rp:` pointer is added because none is created — the grace window is intentionally
    // single-shot to prevent an indefinite-refresh attack from a captured token.
    it('should add only the new rt: key to sess:{userId} SET on grace-window rotation', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const saddCalls = mockRedis.sadd.mock.calls as unknown[][]
      const addedKeys = saddCalls.map((c) => String(c[1]))
      expect(addedKeys.some((k) => k.startsWith('rt:'))).toBe(true)
      expect(addedKeys.some((k) => k.startsWith('rp:'))).toBe(false)
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when the session contains invalid JSON.
    it('should throw REFRESH_TOKEN_INVALID when the session contains invalid JSON', async () => {
      mockRedis.eval.mockResolvedValue('not-valid-json')

      await expect(service.reissueTokens('old-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when the session JSON is missing required fields.
    it('should throw REFRESH_TOKEN_INVALID when session JSON is missing userId or role', async () => {
      mockRedis.eval.mockResolvedValue(JSON.stringify({ ip: '1.2.3.4', device: 'Browser' }))

      await expect(service.reissueTokens('old-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when neither the session nor the grace pointer exists.
    it('should throw REFRESH_TOKEN_INVALID when neither old session nor grace window found', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(null)

      await expect(service.reissueTokens('invalid-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )

      try {
        await service.reissueTokens('invalid-token-2', '1.2.3.4', 'Browser')
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID })
        })
      }
    })

    // Reuse detection (RFC 6819): when the live session and grace pointer are gone
    // but the reuse sentinel (rused:{hash}) still names a user, the presented token
    // is a replay of a rotated-away token past its grace window — a theft signal.
    // The whole token family must be revoked and the user's access tokens cut off,
    // then the request still fails as REFRESH_TOKEN_INVALID.
    it('should revoke the whole family when a superseded token is reused', async () => {
      mockRedis.eval.mockResolvedValue(null) // no live session
      // grace pointer getdel → null; reuse-sentinel getdel → the victim's id (consumed).
      mockRedis.getdel.mockImplementation((key: string) =>
        Promise.resolve(key.startsWith('rused:') ? 'victim-user-id' : null)
      )

      await expect(service.reissueTokens('stolen-token', '9.9.9.9', 'Attacker')).rejects.toThrow(
        AuthException
      )

      // Sentinel is read-and-cleared with GETDEL so a replay cannot re-trigger revocation.
      expect(mockRedis.getdel).toHaveBeenCalledWith(expect.stringMatching(/^rused:/))
      // Full-family revocation: sessions deleted AND access-token cutoff recorded in one call.
      expect(mockRedis.revokeAllUserTokens).toHaveBeenCalledWith(
        'victim-user-id',
        expect.any(Number)
      )
    })

    // The theft reaction fires exactly once: because the sentinel is consumed (GETDEL),
    // replaying the same stolen token a second time finds no sentinel and fails as a
    // plain invalid token — an attacker cannot loop it to repeatedly log the victim out.
    it('should react only once — a second replay does not re-revoke', async () => {
      mockRedis.eval.mockResolvedValue(null)
      let sentinelConsumed = false
      mockRedis.getdel.mockImplementation((key: string) => {
        if (!key.startsWith('rused:')) return Promise.resolve(null)
        if (sentinelConsumed) return Promise.resolve(null)
        sentinelConsumed = true
        return Promise.resolve('victim-user-id')
      })

      await expect(service.reissueTokens('stolen', '9.9.9.9', 'Attacker')).rejects.toThrow(
        AuthException
      )
      await expect(service.reissueTokens('stolen', '9.9.9.9', 'Attacker')).rejects.toThrow(
        AuthException
      )

      expect(mockRedis.revokeAllUserTokens).toHaveBeenCalledTimes(1)
    })

    // Without a sentinel the token is just an unknown/expired string — no family is
    // touched; only the invalid error is raised.
    it('should NOT revoke anything when no reuse sentinel exists', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(null) // grace + sentinel both absent

      await expect(service.reissueTokens('garbage-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )

      expect(mockRedis.revokeAllUserTokens).not.toHaveBeenCalled()
    })

    // Scenario: the rotation Lua is invoked with the exact old `rt:` key and an empty ARGV array.
    // Expected: eval called with the ROTATE_LUA script (containing GET + DEL) and [`rt:<oldHash>`].
    // Why: kills the StringLiteral mutants on line 42 (script → '') and line 277 (oldSessionKey → '').
    it('evaluates ROTATE_LUA with the rt:{oldHash} key on rotation', async () => {
      const oldHash = sha256('old-refresh-token')
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const evalCall = mockRedis.eval.mock.calls[0] as [string, string[], string[]]
      expect(evalCall[0]).toContain("redis.call('GET'")
      expect(evalCall[0]).toContain("redis.call('DEL'")
      expect(evalCall[1]).toEqual([`rt:${oldHash}`])
    })

    // Scenario: primary rotation rewrites the per-user SET — remove old rt:, add new rt: and the
    // grace pointer, then expire the SET with the refresh TTL (days*86400).
    // Expected: exact srem/sadd/expire calls on 'sess:user-1'. Why: kills the StringLiteral mutants
    // on lines 343-346 (each `sess:${old.userId}` key → '' and each member value → '') and the
    // arithmetic mutant on line 274 (`* 86_400` → `/ 86_400`) via the pinned TTL.
    it('updates the sess:{userId} SET with exact keys and TTL on primary rotation', async () => {
      const oldHash = sha256('old-refresh-token')
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.srem).toHaveBeenCalledWith('sess:user-1', `rt:${oldHash}`)
      expect(mockRedis.sadd).toHaveBeenCalledWith('sess:user-1', `rt:${NEW_HASH}`)
      expect(mockRedis.sadd).toHaveBeenCalledWith('sess:user-1', `rp:${oldHash}`)
      expect(mockRedis.expire).toHaveBeenCalledWith('sess:user-1', 7 * 86_400)
    })

    // Scenario: grace-window rotation registers the new rt: under the per-user SET and expires it.
    // Expected: sadd('sess:user-1', 'rt:<newHash>') and expire('sess:user-1', 7*86400). Why: kills
    // the StringLiteral mutants on lines 383 (key/member) and 384 (expire key), plus the line 274
    // TTL arithmetic mutant on the grace path.
    it('updates the sess:{userId} SET with exact key and TTL on grace-window rotation', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      expect(mockRedis.sadd).toHaveBeenCalledWith('sess:user-1', `rt:${NEW_HASH}`)
      expect(mockRedis.expire).toHaveBeenCalledWith('sess:user-1', 7 * 86_400)
    })

    // Scenario: a rotated access token must carry status:'' and mfaVerified:false (state is not
    // persisted in the Redis session, forcing re-auth of MFA after rotation).
    // Expected: sign payload has status === '' and mfaVerified === false. Why: kills the StringLiteral
    // mutant on line 456 (status → "Stryker was here!") and the BooleanLiteral on line 458 (false → true).
    it('issues the rotated access token with an empty status and mfaVerified:false', async () => {
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]['status']).toBe('')
      expect(signCall[0]['mfaVerified']).toBe(false)
    })

    // Scenario: a stored session WITHOUT an mfaEnabled field must default mfaEnabled to false.
    // Expected: rotated access token payload has mfaEnabled:false. Why: kills the BooleanLiteral
    // mutant on line 417 (`... ? rec['mfaEnabled'] : false` → `: true`) which would silently grant
    // mfaEnabled to legacy sessions on rotation.
    it('defaults mfaEnabled to false when the stored session omits it', async () => {
      // OLD_SESSION intentionally has no mfaEnabled field.
      mockRedis.eval.mockResolvedValue(OLD_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]['mfaEnabled']).toBe(false)
    })

    // Scenario: malformed JSON in the session record must be logged AND rejected as REFRESH_TOKEN_INVALID.
    // Expected: logger.warn called with the exact parse-failure message; throws REFRESH_TOKEN_INVALID.
    // Why: kills the BlockStatement mutant on line 401 (`catch {}` — would skip the warn+throw) and the
    // StringLiteral mutant on line 402 (warn message → '').
    it('warns and throws REFRESH_TOKEN_INVALID on malformed session JSON', async () => {
      const warnSpy = jest.spyOn(service['logger'], 'warn').mockImplementation(() => undefined)
      mockRedis.eval.mockResolvedValue('not-valid-json{{{')

      let thrown: unknown
      try {
        await service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      } catch (e) {
        thrown = e
      }

      expect(thrown).toBeInstanceOf(AuthException)
      expect((thrown as AuthException).getResponse()).toMatchObject({
        error: expect.objectContaining({ code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID })
      })
      expect(warnSpy).toHaveBeenCalledWith('parseSession: malformed session JSON in Redis')
      warnSpy.mockRestore()
    })

    // Scenario: a session JSON missing only userId (role present) must be rejected as AuthException.
    // Expected: rejects with AuthException. Why: kills the `typeof rec['userId'] !== 'string'` → false
    // mutant on line 409 (and the OR-chain collapses) — without the userId guard a role-only object
    // would be accepted and rotation would succeed.
    it('throws AuthException when the session JSON has role but no userId', async () => {
      mockRedis.eval.mockResolvedValue(JSON.stringify({ role: 'member' }))

      await expect(
        service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Scenario: a session JSON missing only role (userId present) must be rejected as AuthException.
    // Expected: rejects with AuthException. Why: kills the `typeof rec['role'] !== 'string'` → false
    // mutant on line 410 — without the role guard a userId-only object would be accepted.
    it('throws AuthException when the session JSON has userId but no role', async () => {
      mockRedis.eval.mockResolvedValue(JSON.stringify({ userId: 'user-1' }))

      await expect(
        service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Scenario: a session record that parses to JSON null must be rejected as AuthException — not a
    // TypeError. Expected: rejects with AuthException specifically. Why: kills the `parsed === null`
    // → false mutant on line 408; without the null guard the code dereferences null['userId'] and
    // throws a TypeError (not an AuthException), changing observable behavior.
    it('throws AuthException (not TypeError) when the session JSON is null', async () => {
      mockRedis.eval.mockResolvedValue('null')

      await expect(
        service.reissueTokens('old-refresh-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
    })

    // Scenario: when neither the primary session nor the grace pointer exists, a warning is logged
    // before throwing. Expected: logger.warn called with the exact "no valid session" message.
    // Why: kills the StringLiteral mutant on line 306 (warn message → '').
    it('warns with the no-valid-session message before throwing REFRESH_TOKEN_INVALID', async () => {
      const warnSpy = jest.spyOn(service['logger'], 'warn').mockImplementation(() => undefined)
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(null)

      await expect(service.reissueTokens('gone-token', '1.2.3.4', 'Browser')).rejects.toThrow(
        AuthException
      )
      expect(warnSpy).toHaveBeenCalledWith(
        'reissueTokens: no valid session or grace window found — REFRESH_TOKEN_INVALID'
      )
      warnSpy.mockRestore()
    })
  })

  // ---------------------------------------------------------------------------
  // decodeToken
  // ---------------------------------------------------------------------------

  describe('decodeToken', () => {
    // Verifies that decodeToken returns the full decoded payload when the jti claim is present.
    it('should return the decoded payload when jti is present', () => {
      const payload = { jti: 'some-uuid', sub: 'user-1', type: 'dashboard' }
      mockJwtService.decode.mockReturnValue(payload)

      const result = service.decodeToken('some.jwt.token')

      expect(result).toEqual(payload)
      expect(mockJwtService.decode).toHaveBeenCalledWith('some.jwt.token')
    })

    // Verifies that TOKEN_INVALID is thrown when the decoded payload lacks a jti claim.
    it('should throw TOKEN_INVALID when jti is missing', () => {
      mockJwtService.decode.mockReturnValue({ sub: 'user-1' }) // no jti

      expect(() => service.decodeToken('some.jwt.token')).toThrow(AuthException)
    })

    // Verifies that TOKEN_INVALID is thrown when JwtService.decode returns null (malformed token).
    it('should throw TOKEN_INVALID when decode returns null', () => {
      mockJwtService.decode.mockReturnValue(null)

      expect(() => service.decodeToken('malformed-token')).toThrow(AuthException)
    })

    // Scenario: a decoded payload with jti present but sub missing must be rejected.
    // Expected: throws AuthException. Why: kills the `typeof raw['sub'] !== 'string'` → false mutant
    // on line 657 — without the sub guard a jti-only payload would be wrongly accepted.
    it('should throw TOKEN_INVALID when sub is missing', () => {
      mockJwtService.decode.mockReturnValue({ jti: 'some-uuid' }) // no sub

      expect(() => service.decodeToken('some.jwt.token')).toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // issueMfaTempToken
  // ---------------------------------------------------------------------------

  describe('issueMfaTempToken', () => {
    // Verifies that an MFA challenge token is signed with type 'mfa_challenge' and stored in Redis with a 300s TTL.
    it('should sign an MFA JWT and store it in Redis with 300s TTL', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      const token = await service.issueMfaTempToken('user-1', 'dashboard')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ sub: 'user-1', type: 'mfa_challenge', context: 'dashboard' }),
        expect.objectContaining({ expiresIn: '300s' })
      )
      expect(mockRedis.set).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/), 'user-1', 300)
      expect(token).toBe(FIXED_JWT)
    })

    // Verifies that platform MFA challenges use context 'platform' in the token payload.
    it('should use context:platform for platform MFA challenges', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await service.issueMfaTempToken('admin-1', 'platform')

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ context: 'platform', sub: 'admin-1' }),
        expect.any(Object)
      )
    })

    // Verifies that issuing a fresh MFA temp token resets the per-user MFA challenge
    // brute-force counter (`lf:{hmacSha256('challenge:{userId}')}`), so that failed
    // attempts from an abandoned prior login session do not compound against the user.
    it('should reset the MFA challenge brute-force counter on new token issuance', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await service.issueMfaTempToken('user-1', 'dashboard')

      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^lf:/))
    })

    // Scenario: the brute-force identifier must be HMAC of the namespaced 'challenge:{userId}' value,
    // matching the identifier MfaService uses in `challenge`.
    // Expected: del('lf:<hmac(challenge:user-1)>'). Why: kills the StringLiteral mutant on line 707
    // (`challenge:${userId}` → '') which would HMAC the empty string, breaking key alignment so the
    // reset would target the wrong Redis key.
    it('resets the brute-force counter using the exact challenge:{userId} HMAC identifier', async () => {
      mockRedis.set.mockResolvedValue(undefined)
      mockRedis.del.mockResolvedValue(undefined)

      await service.issueMfaTempToken('user-1', 'dashboard')

      const expectedIdentifier = createHmac('sha256', HMAC_KEY)
        .update('challenge:user-1', 'utf8')
        .digest('hex')
      expect(mockRedis.del).toHaveBeenCalledWith(`lf:${expectedIdentifier}`)
    })
  })

  // ---------------------------------------------------------------------------
  // verifyMfaTempToken
  // ---------------------------------------------------------------------------

  describe('verifyMfaTempToken', () => {
    // Verifies that verifyMfaTempToken returns userId, context, and jti when
    // the token is valid and the Redis entry still exists. The Redis entry
    // is NOT removed by verify (split from consume in v1.0.8+) so the caller
    // can retry on wrong TOTP under the same JWT.
    it('should return userId, context, and jti when token is valid and in Redis', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('user-1') // entry exists; not deleted by verify

      const result = await service.verifyMfaTempToken(FIXED_JWT)

      expect(result).toEqual({ userId: 'user-1', context: 'dashboard', jti: FIXED_UUID })
    })

    // Verifies that verifyMfaTempToken uses GET (not GETDEL) so wrong-TOTP
    // attempts can retry under the same JWT. The matching consume step lives
    // in `consumeMfaTempToken` and is invoked only after the code is valid.
    it('uses GET (not GETDEL) so the token survives wrong-code retries', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('user-1')

      await service.verifyMfaTempToken(FIXED_JWT)

      expect(mockRedis.get).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/))
      // The verify step must NOT delete the Redis entry — that is the job
      // of `consumeMfaTempToken` invoked only when the TOTP is valid.
      expect(mockRedis.getdel).not.toHaveBeenCalled()
      expect(mockRedis.del).not.toHaveBeenCalled()
    })

    // Verifies that MFA_TEMP_TOKEN_INVALID is thrown when the token is not found in Redis (already consumed or expired).
    it('should throw MFA_TEMP_TOKEN_INVALID when token is not in Redis', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue(null) // not found / already consumed

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
    })

    // Verifies that MFA_TEMP_TOKEN_INVALID is thrown when storedUserId differs from the JWT sub claim.
    // This is a defence-in-depth check: requires a forged JWT but makes the binding between
    // the Redis record and the token claims explicit and auditable.
    it('should throw MFA_TEMP_TOKEN_INVALID when storedUserId does not match payload.sub', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('different-user') // userId mismatch

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
    })

    // Scenario: the JWT must be verified with the configured algorithm allowlist.
    // Expected: jwtService.verify called with { algorithms: ['HS256'] }. Why: kills the ObjectLiteral
    // mutant on line 730 (options → {}) and the ArrayDeclaration mutant on line 731 (algorithms → [])
    // which would disable algorithm pinning and allow algorithm-confusion attacks.
    it('verifies the MFA temp token with the configured algorithm allowlist', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: 'user-1',
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      })
      mockRedis.get.mockResolvedValue('user-1')

      await service.verifyMfaTempToken(FIXED_JWT)

      expect(mockJwtService.verify).toHaveBeenCalledWith(FIXED_JWT, { algorithms: ['HS256'] })
    })

    // Scenario: Redis returns null (token consumed/expired) AND the JWT sub is also null.
    // Expected: throws AuthException (the storedUserId === null guard fires first). Why: kills the
    // ConditionalExpression `if (false)` and the empty-block mutants on line 737 — without the null
    // guard, `null !== null` is false so the sub-mismatch check is skipped and the method would
    // wrongly return `{ userId: null }` instead of throwing.
    it('throws when storedUserId is null even if it equals a null sub claim', async () => {
      mockJwtService.verify.mockReturnValue({
        jti: FIXED_UUID,
        sub: null,
        type: 'mfa_challenge',
        context: 'dashboard',
        iat: 0,
        exp: 9999999999
      } as unknown as { jti: string; sub: string; type: string; context: string })
      mockRedis.get.mockResolvedValue(null)

      await expect(service.verifyMfaTempToken(FIXED_JWT)).rejects.toThrow(AuthException)
    })
  })

  // ---------------------------------------------------------------------------
  // consumeMfaTempToken
  // ---------------------------------------------------------------------------

  describe('consumeMfaTempToken', () => {
    // Verifies that consumeMfaTempToken removes the Redis entry keyed by
    // mfa:{sha256(jti)} so the JWT cannot be reused after a successful
    // MFA challenge. Must be a `DEL` (not `GETDEL`) because the value
    // is already known by the caller and a GETDEL would be wasteful.
    it('deletes the mfa:{sha256(jti)} Redis entry', async () => {
      mockRedis.del.mockResolvedValue(undefined)

      await service.consumeMfaTempToken(FIXED_UUID)

      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringMatching(/^mfa:/))
      expect(mockRedis.del).toHaveBeenCalledTimes(1)
    })

    // Verifies that consumeMfaTempToken hashes the jti before keying so
    // the raw jti is never persisted to Redis. Mirrors the `issueMfaTempToken`
    // and `verifyMfaTempToken` key derivation.
    it('hashes the jti via sha256 before keying the Redis entry', async () => {
      mockRedis.del.mockResolvedValue(undefined)

      await service.consumeMfaTempToken(FIXED_UUID)

      const calls = mockRedis.del.mock.calls
      const calledKey = (calls[0] as [string])[0]
      // The deleted key starts with `mfa:` and the suffix is a hex SHA-256
      // (64 lowercase hex chars). Confirms the jti is not present in the raw.
      expect(calledKey).toMatch(/^mfa:[0-9a-f]{64}$/)
      expect(calledKey).not.toContain(FIXED_UUID)
    })

    // Verifies idempotency: a second call (e.g. from a concurrent successful
    // submission that lost a race) is a benign no-op rather than an error.
    it('is idempotent — calling twice does not throw', async () => {
      mockRedis.del.mockResolvedValue(undefined)

      await service.consumeMfaTempToken(FIXED_UUID)
      await expect(service.consumeMfaTempToken(FIXED_UUID)).resolves.toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // reissuePlatformTokens
  // ---------------------------------------------------------------------------

  describe('reissuePlatformTokens', () => {
    /** Minimal valid platform session JSON — matches the RefreshSession shape used for platform admins. */
    const OLD_PLATFORM_SESSION = JSON.stringify({
      userId: 'admin-1',
      tenantId: '',
      role: 'super-admin',
      device: 'Browser',
      ip: '1.2.3.4',
      createdAt: '2026-01-01T00:00:00.000Z',
      mfaEnabled: false
    })

    // Verifies the primary rotation path: the old prt: session is found via Lua eval,
    // a new session is issued, and a RotatedTokenResult is returned with the expected fields.
    it('should return new tokens when the primary prt: session is found via Lua eval', async () => {
      mockRedis.eval.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.reissuePlatformTokens(
        'old-platform-refresh',
        '1.2.3.4',
        'Browser'
      )

      expect(mockRedis.eval).toHaveBeenCalled()
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.session.userId).toBe('admin-1')
      expect(result.session.tenantId).toBe('')
      expect(result.session.role).toBe('super-admin')
    })

    // Verifies that primary rotation writes two Redis entries: a new session under prt:
    // and a grace-window pointer under prp: — both are required to handle concurrent requests.
    it('should write a new prt: session and a prp: grace pointer on primary rotation', async () => {
      mockRedis.eval.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const keys = (mockRedis.set.mock.calls as unknown[][]).map((c) => String(c[0]))
      expect(keys.filter((k) => k.startsWith('prt:'))).toHaveLength(1)
      expect(keys.filter((k) => k.startsWith('prp:'))).toHaveLength(1)
      // The rotated session carries its detail record along, so a listing describes the live
      // token rather than a hash that no longer exists.
      expect(keys.filter((k) => k.startsWith('psd:'))).toHaveLength(1)
    })

    // Verifies that primary rotation uses the grace-window path: Lua eval returns null (primary
    // session gone) but getdel finds and consumes the prp: grace pointer, issuing a new token pair.
    it('should return new tokens from the prp: grace pointer when the primary session is gone', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      const result = await service.reissuePlatformTokens(
        'old-platform-refresh',
        '1.2.3.4',
        'Browser'
      )

      expect(mockRedis.getdel).toHaveBeenCalledWith(expect.stringMatching(/^prp:/))
      expect(result.accessToken).toBe(FIXED_JWT)
      expect(result.rawRefreshToken).toBe(FIXED_REFRESH_TOKEN)
      expect(result.session.userId).toBe('admin-1')
    })

    // Verifies that platform grace-window rotation writes ONLY a new prt: session — never a
    // new prp: grace pointer. Single-shot grace semantics prevent indefinite session extension
    // from a captured refresh token (matches dashboard-side `rt:` / `rp:` behavior).
    it('should write only a new prt: session (no new prp: pointer) on grace-window rotation', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const keys = (mockRedis.set.mock.calls as unknown[][]).map((c) => String(c[0]))
      expect(keys.filter((k) => k.startsWith('prt:'))).toHaveLength(1)
      expect(keys.filter((k) => k.startsWith('prp:'))).toHaveLength(0)
      expect(keys.filter((k) => k.startsWith('psd:'))).toHaveLength(1)
    })

    // Verifies that REFRESH_TOKEN_INVALID is thrown when neither the primary session nor
    // the grace pointer exists — the refresh token has expired or was already consumed.
    it('should throw REFRESH_TOKEN_INVALID when neither prt: session nor prp: grace pointer exists', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(null)

      await expect(
        service.reissuePlatformTokens('expired-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)

      try {
        await service.reissuePlatformTokens('expired-token-2', '1.2.3.4', 'Browser')
      } catch (e) {
        expect(e).toBeInstanceOf(AuthException)
        expect((e as AuthException).getResponse()).toMatchObject({
          error: expect.objectContaining({ code: AUTH_ERROR_CODES.REFRESH_TOKEN_INVALID })
        })
      }
    })

    // Scenario: platform rotation evaluates ROTATE_LUA with the exact old prt: key.
    // Expected: eval called with the script and [`prt:<oldHash>`]. Why: kills the StringLiteral
    // mutant on line 495 (oldSessionKey → '').
    it('evaluates ROTATE_LUA with the prt:{oldHash} key on platform rotation', async () => {
      const oldHash = sha256('old-platform-refresh')
      mockRedis.eval.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const evalCall = mockRedis.eval.mock.calls[0] as [string, string[], string[]]
      expect(evalCall[1]).toEqual([`prt:${oldHash}`])
    })

    // Scenario: platform primary rotation rewrites the per-user SET — remove old prt:, add new prt:
    // and the prp: grace pointer, then expire the SET with the refresh TTL (days*86400).
    // Expected: exact srem/sadd/expire calls on 'sess:admin-1'. Why: kills the StringLiteral mutants
    // on lines 557-560 (each `sess:${old.userId}` key → '' and each member value → '') and the
    // arithmetic mutant on line 492 (`* 86_400` → `/ 86_400`) via the pinned TTL.
    it('updates the psess:{adminId} SET with exact keys and TTL on platform primary rotation', async () => {
      const oldHash = sha256('old-platform-refresh')
      mockRedis.eval.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      expect(mockRedis.srem).toHaveBeenCalledWith('psess:admin-1', `prt:${oldHash}`)
      expect(mockRedis.sadd).toHaveBeenCalledWith('psess:admin-1', `prt:${NEW_HASH}`)
      expect(mockRedis.sadd).toHaveBeenCalledWith('psess:admin-1', `prp:${oldHash}`)
      expect(mockRedis.expire).toHaveBeenCalledWith('psess:admin-1', 7 * 86_400)
      // The legacy index is pruned but never written to, so it drains as sessions rotate
      // instead of holding stale members for a full refresh lifetime.
      expect(mockRedis.srem).toHaveBeenCalledWith('sess:admin-1', `prt:${oldHash}`)
      const indexed = mockRedis.sadd.mock.calls.map((call) => call[0] as string)
      expect(indexed).not.toContain('sess:admin-1')
    })

    // Scenario: the new platform session record must store an empty tenantId on primary rotation.
    // Expected: a stored session JSON has tenantId === ''. Why: kills the StringLiteral mutant on
    // line 553 that passes "Stryker was here!" as the tenantId to buildSession.
    it('stores an empty tenantId in the rotated platform session on primary rotation', async () => {
      mockRedis.eval.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const storedJson = mockRedis.set.mock.calls[0]?.[1] as string
      const session = JSON.parse(storedJson) as Record<string, unknown>
      expect(session['tenantId']).toBe('')
    })

    // Scenario: platform grace-window rotation removes the consumed prp: pointer, adds the new prt:,
    // and expires the SET with the refresh TTL.
    // Expected: exact srem/sadd/expire calls on 'sess:admin-1'. Why: kills the StringLiteral mutants
    // on lines 598 (srem key/member), 599 (sadd key/member), and 600 (expire key) and the line 492
    // TTL arithmetic mutant on the grace path.
    it('updates the psess:{adminId} SET with exact keys and TTL on platform grace-window rotation', async () => {
      const oldHash = sha256('old-platform-refresh')
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      expect(mockRedis.srem).toHaveBeenCalledWith('psess:admin-1', `prp:${oldHash}`)
      expect(mockRedis.sadd).toHaveBeenCalledWith('psess:admin-1', `prt:${NEW_HASH}`)
      expect(mockRedis.expire).toHaveBeenCalledWith('psess:admin-1', 7 * 86_400)
      expect(mockRedis.srem).toHaveBeenCalledWith('sess:admin-1', `prp:${oldHash}`)
    })

    // Scenario: the new platform session record must store an empty tenantId on grace-window rotation.
    // Expected: the stored session JSON has tenantId === ''. Why: kills the StringLiteral mutant on
    // line 587 that passes "Stryker was here!" as the tenantId to buildSession.
    it('stores an empty tenantId in the rotated platform session on grace-window rotation', async () => {
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const storedJson = mockRedis.set.mock.calls[0]?.[1] as string
      const session = JSON.parse(storedJson) as Record<string, unknown>
      expect(session['tenantId']).toBe('')
    })

    // Scenario: a rotated platform access token must always carry mfaVerified:false.
    // Expected: sign payload has mfaVerified === false. Why: kills the BooleanLiteral mutant on line
    // 622 (`mfaVerified: false` → `true`).
    it('issues the rotated platform access token with mfaVerified:false', async () => {
      mockRedis.eval.mockResolvedValue(OLD_PLATFORM_SESSION)
      mockRedis.set.mockResolvedValue(undefined)

      await service.reissuePlatformTokens('old-platform-refresh', '1.2.3.4', 'Browser')

      const signCall = mockJwtService.sign.mock.calls[0] as [Record<string, unknown>]
      expect(signCall[0]['mfaVerified']).toBe(false)
    })

    // Scenario: when neither the primary nor grace pointer exists, a warning is logged before throwing.
    // Expected: logger.warn called with the exact platform "no valid session" message. Why: kills the
    // StringLiteral mutant on line 528 (warn message → '').
    it('warns with the no-valid-session message before throwing on platform rotation', async () => {
      const warnSpy = jest.spyOn(service['logger'], 'warn').mockImplementation(() => undefined)
      mockRedis.eval.mockResolvedValue(null)
      mockRedis.getdel.mockResolvedValue(null)

      await expect(
        service.reissuePlatformTokens('gone-platform-token', '1.2.3.4', 'Browser')
      ).rejects.toThrow(AuthException)
      expect(warnSpy).toHaveBeenCalledWith(
        'reissuePlatformTokens: no valid session or grace window found — REFRESH_TOKEN_INVALID'
      )
      warnSpy.mockRestore()
    })
  })
})
